# Changelog

All notable changes to the Sonicwall Advanced Syslog Server project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-03-18

### Added
- **Pre-computed dashboard statistics** — dashboard now reads from `dashboard_stats` table updated every 60 seconds by a background worker, eliminating all multi-million row scans
- **Hourly rollup table** (`hourly_stats`) — aggregates per-hour per-host event counts, severity breakdowns, bytes, denied/threat counts; dashboard charts and counters read from this instead of scanning `syslog_entries`
- **Stats worker** (`stats_worker.py`) — background thread in the syslog receiver that incrementally updates `hourly_stats` from the last 2 hours of data, then calls `refresh_dashboard_stats()` stored procedure
- **MariaDB scheduled event** (`evt_refresh_dashboard`) — refreshes dashboard stats every 1 minute as a safety net alongside the stats worker
- **Schema upgrade script** (`schema_upgrade_v1.2.sql`) with `dashboard_stats` table, `hourly_stats` table, and `refresh_dashboard_stats` stored procedure
- **Upgrade script** (`upgrade_v1.2.sh`) for existing v1.1.x installations — includes initial stats seeding

### Changed
- **Dashboard page** loads in milliseconds regardless of table size (was 25+ seconds at 8M+ rows)
- **Dashboard API** (`/api/stats`) reads pre-computed values instead of running `COUNT(*)` queries
- **Recent critical logs** query bounded to last 1 hour (was 24 hours)
- Install script now deploys all schema files including v1.2

### Includes all v1.1.1 fixes
- MariaDB buffer pool auto-tuning (128 MB → auto-scaled to RAM)
- InnoDB batch flush mode and larger log file
- DB connection pool health checks and auto-reconnect
- Gunicorn: 3 workers × 2 threads, 30s timeout, worker recycling
- Fixed Gunicorn read-only filesystem error
- Removed broken python3-dtls dependency
- Fixed datetime.utcnow() deprecation warnings

## [1.1.1] - 2026-03-16

### Fixed
- **Dashboard query performance** — total log count now uses fast `information_schema.table_rows` instead of `COUNT(*)` full table scan on multi-million row tables
- **Recent critical logs query** — bounded to last 24 hours; previously scanned entire `syslog_entries` table with no time limit
- **Unique hosts count** — bounded to last 24 hours instead of `COUNT(DISTINCT)` across all rows
- **Database connection pool exhaustion** — added connection health checks (`ping`/reconnect) and `pool_reset_session` to prevent stale connections from hanging Gunicorn workers
- **Gunicorn worker hangs** — reduced timeout from 120s to 30s (fast-fail), added `--max-requests 1000` with jitter to recycle workers and prevent memory/connection leaks
- **Gunicorn read-only filesystem error** — added `/tmp` to `ReadWritePaths` in systemd service for Gunicorn control socket
- **`datetime.utcnow()` deprecation warnings** — replaced with `datetime.now(timezone.utc)` across all Python files
- **DTLS `libcrypto.so.1.1` crash on startup** — removed `python3-dtls` dependency (incompatible with Ubuntu 24.04 OpenSSL 3.x); DTLS listener falls back cleanly to plain UDP

### Added
- **MariaDB performance tuning config** (`mariadb-tuning.cnf`) deployed to `/etc/mysql/mariadb.conf.d/99-syslog-tuning.cnf`
  - `innodb_buffer_pool_size` auto-scaled to system RAM (default 1 GB for 4 GB servers)
  - `innodb_flush_log_at_trx_commit = 2` for batch write performance
  - `innodb_log_file_size = 256M` for sustained ingestion throughput
  - Increased `sort_buffer_size`, `join_buffer_size`, `table_open_cache` for report queries
- **Upgrade script** (`upgrade_v1.1.1.sh`) for existing v1.1.0 installations

### Changed
- Gunicorn workers increased from 2 sync to 3 workers × 2 threads (6 concurrent requests)
- DB connection pool now uses `connection_timeout=10` and `autocommit=True`
- Install script auto-detects RAM and scales MariaDB buffer pool accordingly

## [1.1.0] - 2026-03-13

### Added
- **SonicWall Enhanced Syslog parser** (`fw_parser.py`)
  - Extracts 50+ structured fields from SonicWall key=value log format
  - Parses source/destination IP, port, interface, zone, MAC, hostname
  - Extracts protocol, application, bytes sent/received, packet counts
  - Captures firewall action, rule name, session type
  - Parses IPS alerts (SID, category, priority)
  - Extracts URL/web filtering data (category, destination hostname, URL path)
  - Handles VPN events (user, portal, domain)
  - Automatic event classification into: traffic, denied, threat, vpn, auth, admin, web, system
- **Parsed firewall events table** (`fw_events`) with 50+ indexed columns
- **SonicWall message ID reference table** with 60+ common event ID mappings
- **Comprehensive reporting engine** (`reports.py`) with 20 report types:
  - Security & Threats: Top denied hosts, denied destinations, permitted apps, threats/attacks, threat summary, failed auth, failed auth by IP, top infected hosts
  - Traffic & Bandwidth: Top talkers, inbound vs outbound, top protocols, VPN activity, hourly traffic volume
  - Policy & Rules: Firewall rule utilization, configuration change log
  - Compliance & Audit: URL/web filtering, top websites, admin activity, event type summary, geo-IP/botnet blocks
- **Reports web UI** with report catalog, chart visualizations (bar, line, doughnut), data tables, time period selector, CSV export, and navigation between related reports
- **Alerts system** with database tables for alert rules, alert log, and pre-configured default rules:
  - High volume of denied connections
  - Port scan detected
  - Failed admin login attempts
  - Failed VPN login attempts
  - IPS threat detected
  - Configuration change detected
- **Alerts dashboard** showing rule status, trigger counts, and recent alert events
- Navigation sidebar updated with Reports, Security, Traffic, and Alerts links
- Database schema upgrade script (`schema_upgrade_v1.1.sql`) for existing installations

### Changed
- Syslog receiver now also writes parsed firewall events to `fw_events` in real-time alongside raw `syslog_entries`
- Install script updated to deploy new files and apply upgrade schema

## [1.0.0] - 2026-03-13

### Added
- Multi-protocol syslog receiver (UDP/514, TCP/514, TLS/6514, DTLS/6514)
- RFC 3164 and RFC 5424 syslog message parsing
- SonicWall enhanced syslog format support
- MariaDB storage backend with batched inserts
- Full-text search indexing on log messages
- Automatic log retention and cleanup via scheduled MariaDB event
- Web dashboard with real-time statistics
  - Total log count, 24-hour and 1-hour event counters
  - Hourly log volume chart (Chart.js)
  - Severity breakdown doughnut chart
  - Top 10 hosts by volume
  - Recent critical/error alerts
  - Auto-refresh every 30 seconds
- Advanced log search with filters
  - Hostname, source IP, severity, facility, app name
  - Full-text message search (MariaDB MATCH/AGAINST)
  - Date range filtering
  - Pagination with configurable results per page
- Live tail view with real-time log streaming
- CSV export of filtered log data
- Host management GUI
  - Add, edit, delete syslog source entries
  - Device type categorization (SonicWall, server, switch, router, AP, generic)
  - Protocol and port configuration per host
  - Log count and last-seen tracking per host
  - SonicWall configuration guide built into the add-host form
- User authentication system
  - Admin and viewer roles
  - PBKDF2-SHA256 password hashing
  - Session management with 8-hour expiry
- Application settings page
  - Configurable log retention period
  - Results per page setting
  - Auto-register hosts toggle
  - Default severity filter
- Self-signed TLS certificate generation during install
  - CA certificate for client distribution
  - SAN-enabled server certificate
- Systemd service integration
  - Separate services for receiver and web UI
  - Security hardening (NoNewPrivileges, ProtectSystem, PrivateTmp)
  - Automatic restart on failure
- Automated installer script for Ubuntu 22.04/24.04 LTS
  - MariaDB installation and secure configuration
  - Python virtual environment setup
  - UFW firewall rule configuration
  - Default admin user creation
- REST API endpoints
  - `/api/stats` — real-time dashboard statistics
  - `/api/logs/recent` — recent log entries for live tail
  - `/api/export` — CSV export with filters
- Comprehensive README with deployment and troubleshooting documentation
