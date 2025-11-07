# WireShield v2.1.0 Enhancement Plan

## Overview
This document outlines the comprehensive enhancements being made to WireShield to transform it into an enterprise-grade VPN management solution with SQLite database integration, enhanced security features, and a polished modern UI.

## Current Status: Phase 1 Complete ✅

### Completed Work
1. **Database Layer Foundation**
   - ✅ SQLite3 integration with go-sqlite3 driver
   - ✅ Comprehensive schema design (7 tables)
   - ✅ Repository pattern implementation
   - ✅ Connection pooling and transaction support
   - ✅ WAL mode for improved concurrency

2. **Database Schema** (`internal/database/schema.go`)
   - `clients`: Client metadata, bandwidth stats, expiration tracking
   - `audit_logs`: Complete audit trail of all admin actions
   - `bandwidth_stats`: Historical bandwidth data for analytics
   - `system_metrics`: Server resource usage over time
   - `settings`: Key-value configuration store
   - `sessions`: Enhanced session management
   - `migrations`: Database version tracking

3. **Repository Layer** (`internal/database/models.go`, `repositories.go`)
   - **ClientRepository**: Full CRUD + search, filtering, stats tracking
   - **AuditLogRepository**: Comprehensive logging with cleanup
   - **MetricsRepository**: System & bandwidth metrics with time-series queries
   - **SettingsRepository**: Flexible configuration management

4. **Configuration Updates**
   - Added `DBPath` field to config (default: `/var/lib/wireshield/database.db`)
   - Backward compatible with existing deployments

## Planned Enhancements

### Phase 2: Server Integration & API Enhancement
**Goal**: Integrate database into existing server, add rich API endpoints

#### Tasks:
1. Update `server.New()` to initialize database connection
2. Add audit logging middleware for all admin actions
3. Implement new API endpoints:
   - `GET /api/clients/search?q=term` - Search clients
   - `GET /api/audit-logs` - View audit trail
   - `GET /api/analytics/bandwidth` - Bandwidth analytics
   - `GET /api/analytics/top-clients` - Top bandwidth consumers
   - `POST /api/clients/bulk-revoke` - Revoke multiple clients
   - `GET /api/clients/{id}/history` - Client activity history

4. Enhance existing endpoints with database:
   - Store client configs in DB alongside file system
   - Track all create/update/delete operations in audit log
   - Record bandwidth snapshots periodically

5. Migration utility:
   - Scan `/etc/wireguard/*.conf` for existing clients
   - Parse and import into SQLite
   - Non-destructive (keeps file-based configs)

#### Code Changes Required:
```go
// server.go modifications
type Server struct {
    cfg      *config.Config
    cfgPath  string
    mux      *http.ServeMux
    sess     *auth.Manager
    wg       *wireguard.Service
    db       *database.DB          // NEW
    clients  *database.ClientRepository      // NEW
    audit    *database.AuditLogRepository    // NEW
    metrics  *database.MetricsRepository     // NEW
    settings *database.SettingsRepository    // NEW
    tmpls    *template.Template
    // ... existing fields
}
```

### Phase 3: Modern UI/UX Redesign
**Goal**: Create enterprise-grade dashboard inspired by Tailscale, Cloudflare Zero Trust, WireGuard-UI

#### Design Principles:
- Clean, minimal interface with dark/light theme toggle
- Data-dense tables with inline actions
- Real-time updates with smooth animations
- Mobile-responsive design
- Accessibility (ARIA labels, keyboard nav)

#### UI Components to Build:

1. **Enhanced Dashboard** (`dashboard.tmpl`)
   - Server health status card with live CPU/memory/network
   - Quick stats: Active clients, Total bandwidth, Uptime
   - Recent activity feed from audit logs
   - Bandwidth chart (last 24h/7d/30d)
   - Quick actions: Add client, View logs, Download backup

2. **Advanced Client Management** (`clients.tmpl`)
   - Sortable, filterable data table
   - Search bar with instant results
   - Bulk actions: Select multiple → Revoke/Enable/Disable
   - Inline actions: QR code, Config download, Edit, Revoke
   - Status indicators: 🟢 Active, 🟡 Idle, 🔴 Expired, ⚫ Revoked
   - Bandwidth sparklines per client
   - Last seen timestamp
   - Modal dialogs for add/edit (not separate pages)

3. **Analytics Dashboard** (NEW)
   - Bandwidth over time chart (Chart.js or similar)
   - Top 10 clients by bandwidth
   - Geographic distribution (if endpoint IPs parsed)
   - Connection duration heatmap
   - Export data as CSV/JSON

4. **Audit Log Viewer** (NEW)
   - Filterable table: by user, action, resource, date range
   - Color-coded by action type (create=green, delete=red, etc.)
   - Expandable details panel
   - Export logs functionality

5. **Settings Enhancement**
   - Tabbed interface: Server, Clients, Security, Maintenance
   - Database backup/restore UI
   - Auto-cleanup settings (logs > 90 days, metrics > 30 days)
   - Email notifications (future)

#### CSS Framework Decision:
- Current: Custom CSS (app.css)
- **Proposed**: Upgrade to modern utility framework
  - Option A: Tailwind CSS (most flexible, enterprise standard)
  - Option B: Keep custom CSS but enhance significantly
  - Option C: Shadcn/UI-style component system

#### JavaScript Enhancements:
- Alpine.js or Vue.js for reactive components
- Chart.js for bandwidth/metrics visualization
- htmx for partial page updates (already used)
- DataTables or TanStack Table for advanced grids

### Phase 4: Enhanced Security & Reliability

#### Security Enhancements:
1. **Rate Limiting**: Already implemented, enhance with database tracking
2. **2FA Support**: TOTP-based two-factor authentication (optional)
3. **API Keys**: Generate API keys for programmatic access
4. **IP Whitelisting**: Restrict dashboard access to specific IPs
5. **Audit Alerts**: Webhook notifications for critical events

#### Reliability Features:
1. **Automated Backups**: Scheduled database + config backups
2. **Health Checks**: `/health` endpoint with detailed diagnostics
3. **Graceful Degradation**: Dashboard works even if database is unavailable (read-only mode)
4. **Database Optimization**: Auto-VACUUM, index optimization
5. **Monitoring**: Prometheus metrics endpoint (future)

### Phase 5: Advanced Features

1. **Client Groups/Tags**
   - Organize clients by department, location, etc.
   - Bulk apply expiration policies

2. **Bandwidth Quotas**
   - Set monthly bandwidth limits per client
   - Auto-disable when quota exceeded
   - Email/webhook notifications

3. **Multi-Admin Support**
   - Role-based access control (Admin, Operator, Viewer)
   - Per-admin audit trails

4. **Webhook Integrations**
   - Slack/Discord notifications
   - Custom webhook endpoints

5. **Client Portal** (Separate interface)
   - Clients can download their own configs
   - View their bandwidth usage
   - Request expiration extension

## Database Migration Strategy

### Step 1: Initial Migration (Automatic on first run)
```go
// On dashboard startup:
1. Check if /var/lib/wireshield/database.db exists
2. If not, create and initialize schema
3. Scan /etc/wireguard/*.conf for existing clients
4. Parse client configs and import to DB
5. Log migration results
```

### Step 2: Dual-Storage Mode (v2.1.0 - v2.2.0)
- Write to both database AND file system
- Read from database first, fallback to files
- Ensures backward compatibility
- Allows rollback if issues occur

### Step 3: Database-Primary (v2.2.0+)
- Database is source of truth
- File system configs generated from database
- Old file-based clients gradually migrated

## Testing Plan

### Unit Tests
- Database repository methods
- Migration logic
- API endpoint handlers

### Integration Tests
- End-to-end client lifecycle (add → use → revoke)
- Audit log accuracy
- Metrics collection
- Backup/restore

### Performance Tests
- Database query performance with 1000+ clients
- Concurrent user access
- Large file uploads (backup restore)

### Security Tests
- SQL injection attempts
- CSRF validation
- Rate limiting effectiveness
- Session hijacking prevention

## Deployment Guide (WIP)

### Prerequisites
```bash
# SQLite3 (already present on most Linux systems)
apt-get install -y sqlite3  # Debian/Ubuntu
yum install -y sqlite       # RHEL/CentOS
```

### Installation
```bash
# Pull latest code
cd /home/ubuntu/WireShield
git pull origin master

# Rebuild dashboard
cd dashboard
go build -o /usr/local/bin/wireshield-dashboard ./cmd/wireshield-dashboard

# Restart service
systemctl restart wireshield-dashboard

# Verify
journalctl -u wireshield-dashboard -f
```

### Migration
```bash
# Database will be auto-created on first run at:
# /var/lib/wireshield/database.db

# Check migration status
sqlite3 /var/lib/wireshield/database.db "SELECT * FROM migrations;"

# View imported clients
sqlite3 /var/lib/wireshield/database.db "SELECT name, created_at FROM clients;"
```

## Rollback Plan

If issues occur:
```bash
# Stop dashboard
systemctl stop wireshield-dashboard

# Checkout previous version
git checkout v2.0.0

# Rebuild
go build -o /usr/local/bin/wireshield-dashboard ./cmd/wireshield-dashboard

# Restart
systemctl start wireshield-dashboard
```

Database is preserved and can be used when upgrading again.

## Performance Considerations

### Database Sizing
- Typical deployment: ~1MB per 100 clients
- With 1 year of metrics: ~50MB per 100 clients
- Auto-cleanup keeps database lean

### Query Optimization
- Indexes on all foreign keys and frequently queried columns
- WAL mode for concurrent reads during writes
- Prepared statements for all queries
- Connection pooling (25 max connections)

### Caching Strategy (Future)
- Redis for session storage
- In-memory cache for frequently accessed settings
- ETags for static assets

## UI/UX Inspiration Sources

1. **Tailscale Admin Console**
   - Clean client list with status indicators
   - Simple add/remove workflow
   - Real-time connection status

2. **Cloudflare Zero Trust**
   - Comprehensive audit logs
   - Analytics dashboard with charts
   - Dark mode toggle

3. **WireGuard-UI (by ngoduykhanh)**
   - QR code generation
   - Config download
   - Client expiration handling

4. **pfSense/OPNsense**
   - Detailed system metrics
   - Status dashboard
   - Professional color scheme

## Success Metrics

### Technical Metrics
- ✅ All database operations < 100ms (p95)
- ✅ Zero data loss during migration
- ✅ 100% API endpoint test coverage
- ✅ Dashboard page load < 2s

### User Experience Metrics
- ✅ Client search returns results < 500ms
- ✅ All actions require ≤ 3 clicks
- ✅ Mobile-responsive (100% features on phone)
- ✅ Accessibility score > 95 (Lighthouse)

### Reliability Metrics
- ✅ 99.9% uptime
- ✅ Graceful handling of WireGuard service restart
- ✅ Database corruption recovery
- ✅ Audit log retention (90 days minimum)

## Timeline (Estimated)

- **Phase 1** (Database Foundation): ✅ COMPLETE (Dec 7, 2024)
- **Phase 2** (Server Integration): 4-6 hours
- **Phase 3** (UI Redesign): 8-12 hours
- **Phase 4** (Security/Reliability): 4-6 hours
- **Phase 5** (Advanced Features): 8-12 hours

**Total Estimated Time**: 24-36 hours of focused development

## Questions for Product Owner

1. **UI Framework Choice**: Stick with custom CSS or adopt Tailwind/Bootstrap?
2. **Chart Library**: Chart.js, ApexCharts, or lightweight alternative?
3. **Mobile Priority**: Should mobile experience be equal to desktop?
4. **Database Location**: `/var/lib/wireshield/` acceptable or prefer `/etc/wireshield/`?
5. **Audit Log Retention**: 90 days, 1 year, or configurable?
6. **Backup Schedule**: Daily auto-backups enabled by default?

## Next Steps

### Immediate (Next Session):
1. Integrate database into server.go
2. Add audit logging middleware
3. Implement migration utility
4. Create enhanced clients API endpoints
5. Begin UI redesign with improved client table

### Short Term (This Week):
6. Add analytics dashboard
7. Implement search functionality
8. Create audit log viewer
9. Comprehensive testing

### Medium Term (Next Week):
10. Advanced features (groups, quotas)
11. Security hardening
12. Performance optimization
13. Production deployment

---

**Document Version**: 1.0
**Last Updated**: December 7, 2024
**Status**: Phase 1 Complete, Phase 2 Planning
