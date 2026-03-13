# Changelog

All notable changes to the Sonicwall Advanced Syslog Server project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
