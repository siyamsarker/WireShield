# WireShield Brand Identity — Logo & Light Polish Design

**Date:** 2026-06-12
**Status:** Approved (design), pending implementation plan
**Scope:** UI/UX only. No endpoint, route, request/response, auth, or data-flow changes.

## Problem

The current logo (`assets/logo.svg`, `console-server/static/logo.svg`, `console-server/static/favicon.svg`) is a green padlock-and-network shield that:

- Uses green (`#4ade80`/`#22c55e`/`#16a34a`) while the entire product UI is blue→indigo — the mark fights its own brand.
- Stacks three competing metaphors (shield + node graph + tiny padlock).
- Uses an `feGaussianBlur` glow that smears at favicon/sidebar sizes.
- Is a 200×220 **portrait** canvas while every UI placement renders it square (28/48/140px), so the README hero is squished.

This is the one remaining gap from the prior UI redesign: a clean, cohesive UI anchored by an off-brand, generic mark.

## Decision

Adopt a single unified **app-icon** mark (chosen from concept "A — monogram W-wire", in the app-icon container the user confirmed against a reference image):

- **Container:** solid indigo `#4f46e5` squircle tile (rounded rect, `rx=16` on a 64-grid).
- **Glyph:** white **outline** shield containing a white "W" drawn as one continuous wire with three filled nodes (two upper terminals + center peak). The W doubles as a network/tunnel path — letterform and "wire" fused.
- The glow seen in the reference image is a presentation backdrop only and is **not** baked into the asset (keeps it crisp in a browser tab and on white).

One icon is used everywhere a logo appears (sidebar, captive-portal panels, README hero, favicon), fully retiring the green mark.

## Locked geometry — production SVG source of truth

### `assets/logo.svg` and `console-server/static/logo.svg` (byte-identical)

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" role="img" aria-label="WireShield">
  <rect x="2" y="2" width="60" height="60" rx="16" fill="#4f46e5"/>
  <path d="M32 13 L46 18 V31 C46 40.5 39.5 46.8 32 50 C24.5 46.8 18 40.5 18 31 V18 Z"
        fill="none" stroke="#ffffff" stroke-width="2.6" stroke-linejoin="round"/>
  <path d="M25 25.5 L28.8 37 L32 30 L35.2 37 L39 25.5" fill="none" stroke="#ffffff"
        stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="25" cy="25.5" r="2" fill="#ffffff"/>
  <circle cx="39" cy="25.5" r="2" fill="#ffffff"/>
  <circle cx="32" cy="30" r="2" fill="#ffffff"/>
</svg>
```

### `console-server/static/favicon.svg`

Same geometry and 64-grid viewBox (SVG scales cleanly to 16px); width/height `32`. If the three nodes muddy at 16px during verification, drop the two **terminal** nodes (`cx=25` and `cx=39`) and keep only the center peak node; keep the shield + W strokes. Decide this by eye against the 16px cell in the preview.

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="32" height="32" role="img" aria-label="WireShield">
  <rect x="2" y="2" width="60" height="60" rx="16" fill="#4f46e5"/>
  <path d="M32 13 L46 18 V31 C46 40.5 39.5 46.8 32 50 C24.5 46.8 18 40.5 18 31 V18 Z"
        fill="none" stroke="#ffffff" stroke-width="2.6" stroke-linejoin="round"/>
  <path d="M25 25.5 L28.8 37 L32 30 L35.2 37 L39 25.5" fill="none" stroke="#ffffff"
        stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="25" cy="25.5" r="2" fill="#ffffff"/>
  <circle cx="39" cy="25.5" r="2" fill="#ffffff"/>
  <circle cx="32" cy="30" r="2" fill="#ffffff"/>
</svg>
```

## Light brand polish (UI-only)

All of these are presentation-only; no JS behavior, request, or route changes.

1. **Sidebar lockup** (`console.html` + `console.css`): the icon now carries its own indigo tile, so flatten `.brand-logo` to a transparent, border-less, padding-less wrapper to avoid a tile-on-tile double corner. Keep the `.brand-text` / `.brand-sub` ("WireShield" / "Admin Console") lockup; tighten gap/alignment only as needed. The sidebar `<img>` already points at `/static/logo.svg`, so it picks up the new mark automatically.
2. **Captive-portal panels** (`2fa_setup.html`, `2fa_verify.html`, `access_denied.html`): these reference the shared `/static/logo.svg` and update automatically. Verify the brand row spacing at the existing 48px (`.auth-brand-logo`) / 34px (`.brand-logo`) sizes on the navy panels; the icon's own tile should sit cleanly without an extra wrapper background. No copy or layout changes beyond spacing nudges.
3. **README hero** (`README.md`): the `<img ... width="140" height="140">` points at `assets/logo.svg`; with a square viewBox it now renders correctly. No markup change required unless the existing dimensions need to stay square (they already are 140×140) — verify only.

### Explicitly out of scope (YAGNI / semantics)

- The **access-denied** alert icon (the red hand-drawn shield in the card body) stays red — it conveys an alert state and must not be rebranded to indigo.
- Console empty-state icons stay as-is.
- No dark-mode theme, no data-viz palette change (the prior redesign already unified chart colors), no functional changes.

## Verification approach

- Each SVG validates as well-formed XML.
- Visual check at 16 / 28 / 48 / 96 / 160px on light (`#ffffff`) and dark (`#0f172a`) backgrounds via a throwaway preview (not committed).
- All five Jinja templates render (`2fa_setup`, `2fa_verify`, `success`, `access_denied`, `console`).
- The existing Python suite stays green (101 tests) — changes are static assets + CSS + template attributes only.
- One commit per logical step; detailed messages describing the change itself; no "Co-Authored-By" trailer; no references to the plan or this spec in commit messages.
- The `assets/logo-concepts/` scratch folder is deleted before implementation (it is untracked).

## Files touched

| File | Change |
| :--- | :--- |
| `assets/logo.svg` | Replace with app-icon mark |
| `console-server/static/logo.svg` | Replace (byte-identical to above) |
| `console-server/static/favicon.svg` | Replace with favicon variant |
| `console-server/static/css/console.css` | Flatten `.brand-logo` wrapper |
| `console-server/templates/console.html` | Sidebar lockup spacing only (if needed) |
| `README.md` | Verify hero renders square (likely no change) |
