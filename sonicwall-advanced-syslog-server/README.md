# Sonicwall Advanced Syslog Server

[![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)](https://github.com/YOUR_USERNAME/sonicwall-advanced-syslog-server/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20|%2024.04%20LTS-orange.svg)](https://ubuntu.com/)
[![Python](https://img.shields.io/badge/Python-3.10+-yellow.svg)](https://www.python.org/)
[![MariaDB](https://img.shields.io/badge/MariaDB-10.6+-003545.svg)](https://mariadb.org/)

A self-hosted syslog collection and **firewall analytics** server with 20+ built-in security, traffic, and compliance reports. Designed primarily for SonicWall firewalls with deep Enhanced Syslog parsing, but compatible with any syslog source. Built for Ubuntu LTS with MariaDB.

> **Looking for a basic syslog server without analytics?** Check out [Sonicwall Syslog Server](https://github.com/YOUR_USERNAME/sonicwall-syslog-server) — the lightweight v1.0 that handles collection, search, and host management without the reporting layer.

## Features

### Syslog Collection
- **Multi-protocol receiver**: UDP/514, TCP/514, TLS/6514, DTLS/6514
- **RFC 3164 and RFC 5424** syslog parsing for any device
- **MariaDB storage** with full-text search, partitioning, and automatic retention cleanup
- **Batched inserts** for high-throughput ingestion
- **Self-signed TLS certificates** generated during install (or bring your own)

### SonicWall Deep Parsing
- **Enhanced Syslog key=value parser** extracting 50+ structured fields per event
- Source/destination IP, port, interface, zone, MAC, hostname
- Protocol, application, bytes sent/received, packet counts
- Firewall action, rule name, NAT translations
- IPS alerts with SID, category, and priority
- URL/web filtering with category, destination hostname, and URL path
- VPN events with user, portal, and domain
- **Automatic event classification** into 8 types: traffic, denied, threat, vpn, auth, admin, web, system
- **60+ SonicWall message ID mappings** for human-readable event names

### Security & Threat Reports
- **Top Denied Hosts/IPs** — frequently blocked hosts indicating reconnaissance or malicious intent
- **Top Denied Destinations** — blocked outbound targets suggesting data exfiltration or C2
- **Top Permitted Applications** — applications passing through the firewall for shadow IT detection
- **Security Threats & Attacks** — IPS alerts, virus detections, port scans, protocol anomalies
- **Threat Summary by Category** — aggregated view grouped by IPS category
- **Failed Authentication Attempts** — failed VPN and admin logins indicating brute-force attacks
- **Failed Auth by Source IP** — top brute-force candidate IPs
- **Top Potentially Infected Hosts** — internal IPs triggering the most threat alerts

### Traffic & Bandwidth Reports
- **Top Talkers / Bandwidth Usage** — IPs consuming the most bandwidth
- **Inbound vs Outbound Traffic** — traffic flow by zone for detecting exfiltration
- **Top Protocols & Services** — primary protocols (TCP, UDP, ICMP) and applications
- **VPN Activity Report** — active users, login/failure counts, bandwidth, source IPs
- **Hourly Traffic Volume** — time-series breakdown with denied/threat overlay

### Policy & Rule Management
- **Firewall Rule Utilization** — identifies unused or heavily-used rules for policy optimization
- **Configuration Change Log** — tracks who changed what and when

### Compliance & Audit
- **URL / Web Filtering** — website category access tracking (social, gambling, malicious, etc.)
- **Top Websites Accessed** — most visited destinations by hit count and user count
- **Admin Activity Report** — every administrator action on the firewall console
- **Event Type Summary** — overview of all event types for compliance dashboards
- **Geo-IP & Botnet Blocks** — connections blocked by geographic or botnet filtering

### Alerts
- **6 pre-configured alert rules**: high denied volume, port scans, failed admin/VPN logins, IPS threats, config changes
- **Alerts dashboard** with rule status, trigger counts, and event history
- Extensible alert rules stored in the database

### Web UI
- **Dashboard** with real-time stats, Chart.js charts, severity breakdown, top hosts, recent critical events
- **Advanced log search** with filters for hostname, IP, severity, facility, app name, date range, full-text
- **Report viewer** with charts (bar, line, doughnut), data tables, time period selector (1h to 90d)
- **Host management GUI** to register and track syslog sources with SonicWall config guide built in
- **Live tail** view for real-time log monitoring
- **CSV export** for logs and reports
- **User authentication** with admin and viewer roles
- **Dark-themed professional interface** with responsive design

## Architecture

```
┌──────────────────┐     ┌─────────────────────────┐     ┌──────────────┐
│  SonicWall / Any │────▶│    Syslog Receiver       │────▶│   MariaDB    │
│  Syslog Source   │     │   (Python daemon)        │     │              │
│                  │     │                          │     │ syslog_entries│
│  UDP/514         │     │  - UDP/TCP/TLS/DTLS      │     │ (raw logs)   │
│  TCP/514         │     │  - RFC 3164/5424 parse   │     │              │
│  TLS/6514        │     │  - SonicWall KV parser ──┼────▶│ fw_events    │
│  DTLS/6514       │     │  - Event classification  │     │ (parsed)     │
└──────────────────┘     └─────────────────────────┘     └──────┬───────┘
                                                                │
                         ┌─────────────────────────┐            │
                         │       Web UI             │◀───────────┘
                         │   (Flask + Gunicorn)     │
                         │                          │
                         │  - Dashboard             │
                         │  - Log search            │
                         │  - 20 Firewall reports   │
                         │  - Alerts dashboard      │
                         │  - Host management       │
                         │  - User auth / settings  │
                         │                          │
                         │  http://<IP>:8443        │
                         └─────────────────────────┘
```

## Requirements

- Ubuntu 22.04 LTS or 24.04 LTS
- Root/sudo access
- At least 2 GB RAM (4 GB recommended)
- Sufficient disk for log storage

## Quick Install

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/sonicwall-advanced-syslog-server.git
cd sonicwall-advanced-syslog-server

# Run the installer
chmod +x install.sh
sudo ./install.sh
```

The installer will prompt for:
1. **MariaDB root password** — for initial database setup
2. **Syslog database user password** — used by the application
3. **Web admin password** — for the web UI (default: admin)
4. **Server hostname/IP** — for the TLS certificate SAN

## What the Installer Does

1. Installs MariaDB, Python 3, and dependencies
2. Creates and secures the MariaDB database (both base + analytics schemas)
3. Generates self-signed TLS certificates (CA + server)
4. Creates a `syslog-server` system user
5. Sets up a Python virtual environment with all packages
6. Writes the configuration file
7. Installs and starts two systemd services
8. Configures UFW firewall rules
9. Creates the default admin user

## Post-Install

### Access the Web UI

Open your browser to `http://<server-ip>:8443` and log in with the admin credentials you set during installation.

### Configure SonicWall for Full Analytics

For the reports and analytics to work properly, your SonicWall **must** be configured to use **Enhanced Syslog** format:

1. Log in to your SonicWall management console
2. Navigate to **Device → Log → Syslog**
3. Click **Add** to create a new syslog server
4. Enter the syslog server's IP address
5. Choose your protocol and port:
   - **UDP 514** — Standard (fastest, no encryption)
   - **TCP 514** — Reliable delivery, no encryption
   - **TCP 6514** — TLS encrypted (recommended)
6. **Set Syslog Format to `Enhanced Syslog`** — this is critical for reports
7. Click the Configure icon and **Select All** enhanced syslog fields
8. Set the **Syslog ID** to `firewall`
9. For TLS: Upload the CA certificate from `/etc/syslog-server/certs/ca.crt`
10. Select which log categories to forward (recommend all)
11. Click **OK** then **Accept**

> **Important**: Standard syslog format will still be collected and searchable, but the 20 analytics reports require the Enhanced Syslog key=value fields (src, dst, proto, sent, rcvd, rule, etc.)

### Configure Other Devices

Any syslog-capable device can send logs to this server. Non-SonicWall devices will be stored and searchable in the raw log search, but won't appear in the parsed firewall reports.

**Linux (rsyslog):**
```bash
# /etc/rsyslog.d/remote.conf
*.* @<server-ip>:514          # UDP
*.* @@<server-ip>:514         # TCP
*.* @@<server-ip>:6514        # TLS (requires rsyslog-gnutls)
```

**Generic network devices:**
Most switches, routers, and APs have a syslog configuration page. Enter the server IP and port 514 (UDP).

## Reports

Access reports at `http://<server-ip>:8443/reports`. All reports support configurable time periods (1 hour to 90 days) and CSV export.

| Category | Reports |
|----------|---------|
| **Security & Threats** | Top Denied Hosts, Top Denied Destinations, Top Permitted Apps, Threats & Attacks, Threat Summary, Failed Auth, Failed Auth by IP, Top Infected Hosts |
| **Traffic & Bandwidth** | Top Talkers, Inbound vs Outbound, Top Protocols, VPN Activity, Hourly Traffic Volume |
| **Policy & Rules** | Rule Utilization, Configuration Change Log |
| **Compliance & Audit** | URL/Web Filtering, Top Websites, Admin Activity, Event Type Summary, Geo-IP/Botnet Blocks |

### Key Data Fields Parsed

The SonicWall parser extracts these fields from each log event:

| Field Group | Parsed Fields |
|-------------|---------------|
| **Network** | Source/Dest IP, Port, Interface, Zone, MAC, Hostname |
| **Traffic** | Bytes Sent/Received, Packets Sent/Received |
| **Protocol** | Transport (TCP/UDP/ICMP), Application (HTTP/HTTPS/DNS/etc.) |
| **Policy** | Firewall Action, Rule Name, Session Type |
| **Security** | IPS SID, IPS Category, IPS Priority |
| **Web** | URL Category, URL Code, Destination Hostname, URL Path |
| **Identity** | VPN User, Portal, Domain, Admin User |
| **Device** | Serial Number, Firmware IP, Message ID, Event Count |

## Alerts

Access at `http://<server-ip>:8443/alerts`. Six pre-configured alert rules monitor for:

1. **High denied connection volume** — more than 1,000 denies in 5 minutes
2. **Port scan detected** — SonicWall message IDs 82/83
3. **Failed admin login attempts** — 3+ failures in 10 minutes
4. **Failed VPN login attempts** — 5+ failures in 10 minutes
5. **IPS threat detected** — any IPS/threat event
6. **Configuration change** — any rule add/delete/modify event

Alert rules are stored in the `alert_rules` database table and can be customized via SQL.

## Service Management

```bash
# Check status
sudo systemctl status syslog-receiver
sudo systemctl status syslog-web

# View live logs
sudo journalctl -u syslog-receiver -f
sudo journalctl -u syslog-web -f

# Restart services
sudo systemctl restart syslog-receiver
sudo systemctl restart syslog-web

# Stop services
sudo systemctl stop syslog-receiver syslog-web
```

## Configuration

Edit `/etc/syslog-server/config.json`:

| Setting | Default | Description |
|---------|---------|-------------|
| `db_host` | 127.0.0.1 | MariaDB host |
| `db_port` | 3306 | MariaDB port |
| `db_user` | syslog | Database username |
| `db_password` | — | Database password |
| `db_name` | syslog_db | Database name |
| `db_pool_size` | 5 | Connection pool size |
| `udp_port` | 514 | Standard UDP syslog port |
| `tcp_port` | 514 | Standard TCP syslog port |
| `tls_port` | 6514 | TLS syslog port |
| `dtls_port` | 6514 | DTLS syslog port |
| `tls_cert` | — | Path to server TLS certificate |
| `tls_key` | — | Path to server TLS private key |
| `tls_ca` | — | Path to CA certificate |
| `batch_size` | 50 | DB insert batch size |
| `batch_timeout` | 2.0 | Max seconds before flushing batch |
| `web_port` | 8443 | Web UI port |
| `log_level` | INFO | Logging level (DEBUG/INFO/WARNING/ERROR) |

After editing, restart both services:
```bash
sudo systemctl restart syslog-receiver syslog-web
```

## Database

### Tables

| Table | Purpose |
|-------|---------|
| `syslog_entries` | Raw syslog messages (all sources) |
| `fw_events` | Parsed firewall events with 50+ structured fields |
| `fw_message_ids` | SonicWall message ID reference (60+ entries) |
| `syslog_hosts` | Registered host entries |
| `alert_rules` | Alert rule definitions |
| `alert_log` | Triggered alert history |
| `app_settings` | Application configuration |
| `users` | Web UI user accounts |

### Maintenance

Automatic log cleanup runs daily at 3:00 AM UTC. Configure retention via the web UI Settings page.

```bash
# Manual cleanup
mysql -u root -p syslog_db -e "CALL cleanup_old_logs();"

# Database size check
mysql -u root -p syslog_db -e "
  SELECT table_name,
    ROUND(data_length / 1024 / 1024, 2) AS data_mb,
    ROUND(index_length / 1024 / 1024, 2) AS index_mb,
    table_rows
  FROM information_schema.tables
  WHERE table_schema = 'syslog_db';
"

# Backup
mysqldump -u root -p syslog_db > syslog_backup_$(date +%Y%m%d).sql
```

## Using Your Own TLS Certificates

```bash
sudo cp your-cert.crt /etc/syslog-server/certs/server.crt
sudo cp your-cert.key /etc/syslog-server/certs/server.key
sudo cp your-ca.crt   /etc/syslog-server/certs/ca.crt
sudo chown syslog-server:syslog-server /etc/syslog-server/certs/*
sudo chmod 600 /etc/syslog-server/certs/server.key
sudo systemctl restart syslog-receiver
```

## Performance Tuning

The installer automatically deploys MariaDB tuning to `/etc/mysql/mariadb.conf.d/99-syslog-tuning.cnf` and scales the InnoDB buffer pool based on available RAM:

| Server RAM | Buffer Pool | Suitable For |
|------------|-------------|-------------|
| 2 GB | 512 MB | Small / lab (~5 hosts) |
| 4 GB | 1 GB | Small-medium (~10 hosts, ~1.5M logs/day) |
| 8 GB | 2 GB | Medium (~25 hosts, ~5M logs/day) |
| 16 GB+ | 4 GB | Large (~50+ hosts, ~10M+ logs/day) |

To adjust manually:
```bash
sudo nano /etc/mysql/mariadb.conf.d/99-syslog-tuning.cnf
# Change innodb_buffer_pool_size = ...
sudo systemctl restart mariadb
```

### Verifying Performance

Check the InnoDB buffer pool hit ratio (should be above 99%):
```bash
mysql -u root -p -e "
  SELECT
    ROUND(100 - (
      (SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME = 'Innodb_buffer_pool_reads') /
      (SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME = 'Innodb_buffer_pool_read_requests') * 100
    ), 2) AS buffer_pool_hit_pct;
"
```

If the hit ratio is below 99%, increase `innodb_buffer_pool_size`.

## HTTPS for the Web UI (Recommended)

For production, put the web UI behind an Nginx reverse proxy with HTTPS:

```bash
sudo apt install nginx certbot python3-certbot-nginx

sudo tee /etc/nginx/sites-available/syslog <<'EOF'
server {
    listen 443 ssl;
    server_name syslog.yourdomain.com;
    ssl_certificate     /etc/letsencrypt/live/syslog.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/syslog.yourdomain.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
server {
    listen 80;
    server_name syslog.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
EOF

sudo ln -s /etc/nginx/sites-available/syslog /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## Testing

```bash
# Standard syslog test
echo "<14>$(date '+%b %d %H:%M:%S') testhost myapp[1234]: Test message" | nc -u -w1 localhost 514

# SonicWall-format test (will be parsed into fw_events)
echo '<134> id=firewall sn=TEST123 time="2026-03-13 12:00:00" fw=10.0.0.1 pri=6 c=1024 m=97 msg="Web site hit" src=192.168.1.10:12345:X0 srcZone=LAN dst=93.184.216.34:443:X1 dstZone=WAN proto=tcp/https sent=1024 rcvd=4096 rule="Allow LAN to WAN" dstname=example.com Category="Information Technology" fw_action="forward"' | nc -u -w1 localhost 514

# TLS test
echo "<14>$(date '+%b %d %H:%M:%S') testhost myapp: TLS test" | \
  openssl s_client -connect localhost:6514 -CAfile /etc/syslog-server/certs/ca.crt -quiet 2>/dev/null
```

## Troubleshooting

**Services not starting:**
```bash
sudo journalctl -u syslog-receiver -n 50 --no-pager
sudo journalctl -u syslog-web -n 50 --no-pager
```

**Reports showing no data:**
- Verify SonicWall is using **Enhanced Syslog** format (not Default or ArcSight)
- Check that logs contain `id=firewall` key-value pairs
- Look at raw logs in Log Search to confirm format
- Check `fw_events` table: `mysql -u root -p syslog_db -e "SELECT COUNT(*) FROM fw_events;"`

**Permission denied on port 514:**
```bash
sudo setcap cap_net_bind_service=+ep /opt/syslog-server/venv/bin/python3
```

**No logs appearing:**
```bash
sudo ss -ulnp | grep 514
sudo ss -tlnp | grep 514
sudo tcpdump -i any port 514 -n
```

## File Locations

| Path | Description |
|------|-------------|
| `/opt/syslog-server/` | Application code |
| `/opt/syslog-server/fw_parser.py` | SonicWall log parser |
| `/opt/syslog-server/reports.py` | Report engine (20 reports) |
| `/etc/syslog-server/config.json` | Configuration |
| `/etc/syslog-server/certs/` | TLS certificates |
| `/var/log/syslog-server/` | Application logs |
| `/etc/systemd/system/syslog-receiver.service` | Receiver service |
| `/etc/systemd/system/syslog-web.service` | Web UI service |

## Related Projects

- **[Sonicwall Syslog Server v1.0](https://github.com/YOUR_USERNAME/sonicwall-syslog-server)** — Lightweight syslog collection with search and host management (no analytics/reports)

## Uninstall

```bash
sudo systemctl stop syslog-receiver syslog-web
sudo systemctl disable syslog-receiver syslog-web
sudo rm /etc/systemd/system/syslog-receiver.service
sudo rm /etc/systemd/system/syslog-web.service
sudo systemctl daemon-reload
sudo rm -rf /opt/syslog-server
sudo rm -rf /etc/syslog-server
sudo rm -rf /var/log/syslog-server
sudo userdel syslog-server
# Optionally drop the database:
# mysql -u root -p -e "DROP DATABASE syslog_db; DROP USER 'syslog'@'localhost';"
```

## License

This project is provided under the [MIT License](LICENSE) for personal and commercial use.
