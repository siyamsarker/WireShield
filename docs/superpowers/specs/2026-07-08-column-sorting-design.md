# Column Sorting for Console Tables

## Context

The WireShield admin console (`/console`) was recently restyled to align with Cloudflare's dashboard aesthetic (see `docs/superpowers/specs` history / commit `5ed658a`). That pass was presentational-only. The one real interaction gap left over from the Cloudflare reference screenshots was sortable column headers, deliberately deferred because it requires new JS/backend behavior. This spec covers adding it.

## Scope

Five tables get click-to-sort headers: Users, Audit Trail, Activity Log, Agents, and the dashboard's Recent Activity table. No row-selection checkboxes or bulk-action toolbar — those remain out of scope (per prior decision).

## Why two mechanisms, not one

Inspecting `console-server/app/routers/console.py` shows Users, Audit Trail, and Activity Log are all server-paginated (`GET /api/console/{users,audit-logs,activity-logs}`, 20-30 rows per page, raw SQL with hardcoded `ORDER BY ... LIMIT ? OFFSET ?`). Agents and the dashboard's Recent Activity table already load their full result set into a JS array and render/filter client-side.

Sorting only the currently-loaded page of a paginated table is a real UX trap (sort by Name, click Next, the new page arrives in server order again) — confirmed with the user, who chose real server-side sorting for the three paginated tables over that shortcut. Agents/Dashboard already hold everything, so client-side sort is both correct and free of any backend change there.

## Backend: server-side sort (Users, Audit Trail, Activity Log)

Each of the three endpoints gains two optional query params:

- `sort: Optional[str] = None`
- `dir: Optional[str] = "desc"`

**Security constraint:** all three endpoints build their SQL by string concatenation (`query += " ORDER BY ..."`). A sort *column name* cannot be parameterized with `?` placeholders in SQLite (placeholders only bind values, not identifiers), so the sort key must never reach the query string directly. Each endpoint defines a small whitelist dict mapping an allowed key to a hardcoded, safe column expression:

```python
# Example — users endpoint
USERS_SORT_COLUMNS = {
    "client_id": "u.client_id",
    "ipv4": "u.wg_ipv4",
    "console_access": "u.console_access",
    "created": "u.created_at",
}
```

Resolution rule: if `sort` is present and found in the whitelist, and `dir.lower()` is exactly `"asc"` or `"desc"`, build `ORDER BY {whitelisted_column} {ASC|DESC}, {id_column} DESC` (the trailing id is a stable tiebreaker so equal-value rows don't reorder between pages — `u.id` for the users query since it aliases the table `u`, bare `id` for audit-logs since that query is unaliased, `a.id` for activity-logs since it aliases the table `a`). Otherwise, fall back to today's existing hardcoded order — never error on a bad/missing sort param, just ignore it.

Per-endpoint whitelist (only real, single-valued DB columns — nothing computed or composite):

| Endpoint | Sort key → column |
|---|---|
| `/api/console/users` | `client_id`→`u.client_id`, `ipv4`→`u.wg_ipv4`, `console_access`→`u.console_access`, `created`→`u.created_at` |
| `/api/console/audit-logs` | `timestamp`→`timestamp`, `client`→`client_id`, `action`→`action`, `status`→`status`, `ip`→`ip_address` |
| `/api/console/activity-logs` | `timestamp`→`a.timestamp`, `client`→`a.client_id`, `direction`→`a.direction` |

Columns left out deliberately: Users' Session Status / Active Duration / 2FA Status (derived from a subquery or a nullable secret, not a clean single-column sort — can be added later if wanted); Activity Log's "Connection Details" (a JS-composed string over protocol/src/dst, not one column).

## Frontend: shared interaction, two render paths

**Shared click/state logic** — one small helper added to `console-app.js` (alongside existing shared helpers like `renderPagination`/`getStatusClass`):

```js
// attachSort(theadEl, onSortChange) — wires click handlers on every
// th[data-sort-key] in theadEl. Tracks {key, dir} per thead via a
// WeakMap. First click on a header = ascending; second click on the
// same header flips direction; clicking a different header resets to
// ascending on the new key. Paints `.sort-asc`/`.sort-desc` + toggles
// aria-sort on the active header, clears it from the previous one.
// Calls onSortChange(key, dir) — callers decide what "change" means.
```

- **Users / Audit / Activity** (`onSortChange` re-fetches): changing sort resets to page 1 and re-issues the existing load call (`loadUsers()`, `loadAuditLogs()`, `loadActivityLogs()`) with `sort`/`dir` added to the query string alongside the params those functions already send. The current sort state is tracked the same way current filter state already is (a module-level variable read by the load function), so paging forward/back preserves the active sort.
- **Agents / Recent Activity** (`onSortChange` re-sorts in place): the callback sorts the existing in-memory array with a small comparator keyed by column type (string vs. number vs. timestamp) and calls the table's existing render function — no fetch.

**Markup:** sortable `<th>` elements in `console.html` get `data-sort-key="..."` and the `.th-sortable` class. Non-sortable columns (Actions, Advertised CIDRs, Connection Details, etc.) are untouched.

**CSS** (`ws-design-system.css` §17): `.th-sortable` gets `cursor: pointer`, a muted chevron placeholder on hover, and `.sort-asc`/`.sort-desc` modifiers that show a filled chevron in the active direction — matching the up/down chevron convention from the Cloudflare reference screenshots.

## Comparator details (client-side tables)

- **Agents**: Name/Status/Hostname/Version/WG IPv4 → case-insensitive string compare. Last seen → compare by the raw timestamp already present in the agent object, not the rendered "5 minutes ago" string. RX/TX → numeric compare on the raw byte count.
- **Recent Activity**: Time → raw timestamp. Client/Action/Status/IP → string compare.

## Testing

Per the project's existing pattern there's no JS test harness, so:
- **Backend**: one small `test_*.py` (or extend an existing test file if one exists for `console.py`) asserting: (a) a whitelisted `sort`/`dir` produces the expected `ORDER BY` column+direction, (b) a non-whitelisted `sort` value falls back to the default order rather than raising or being interpolated raw, (c) an invalid `dir` value falls back to `desc`.
- **Frontend**: manual verification (per `verify`/`run` skill pattern already used in this project) — click every sortable header on all five tables, confirm direction toggles, confirm Users/Audit/Activity re-fetch page 1 with the new order and that paging forward keeps the sort, confirm Agents/Recent Activity resort in place with no network call.

## Out of scope (unchanged from prior decision)

Row-selection checkboxes, bulk-action toolbar, sorting on computed/composite columns, persisting sort choice across page reloads (resets like the existing filters do).
