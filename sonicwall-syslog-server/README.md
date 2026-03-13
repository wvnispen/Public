# Sonicwall Syslog Server

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/YOUR_USERNAME/sonicwall-syslog-server/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20|%2024.04%20LTS-orange.svg)](https://ubuntu.com/)
[![Python](https://img.shields.io/badge/Python-3.10+-yellow.svg)](https://www.python.org/)
[![MariaDB](https://img.shields.io/badge/MariaDB-10.6+-003545.svg)](https://mariadb.org/)

A self-hosted syslog collection server with a web-based search interface, designed primarily for SonicWall firewalls but compatible with any syslog source. Built for Ubuntu LTS with MariaDB.

> **Note**: While this project is optimized for SonicWall firewall logs, it fully supports standard RFC 3164 and RFC 5424 syslog from any device — routers, switches, Linux servers, access points, and more.

## Features

- **Multi-protocol syslog receiver**: UDP/514, TCP/514, TLS/6514, DTLS/6514
- **MariaDB storage** with full-text search, automatic partitioning, and log retention
- **Web dashboard** with real-time stats, severity breakdown, and volume charts
- **Advanced log search** with filters for hostname, IP, severity, facility, app name, date range, and full-text message search
- **Host management GUI** to register and track syslog sources (SonicWall, servers, switches, etc.)
- **Live tail** view for real-time log monitoring
- **CSV export** of filtered log data
- **User authentication** with admin and viewer roles
- **Automatic log cleanup** via scheduled MariaDB event
- **Systemd integration** with security hardening
- **Self-signed TLS certificates** generated during install (or bring your own)

## Architecture

```
┌──────────────────┐     ┌─────────────────────┐     ┌──────────────┐
│  SonicWall / Any │────▶│   Syslog Receiver    │────▶│   MariaDB    │
│  Syslog Source   │     │  (Python daemon)     │     │  syslog_db   │
│                  │     │                      │     │              │
│  UDP/514         │     │  - UDP listener      │     │  - Batched   │
│  TCP/514         │     │  - TCP listener      │     │    inserts   │
│  TLS/6514        │     │  - TLS listener      │     │  - Full-text │
│  DTLS/6514       │     │  - DTLS listener     │     │    indexes   │
└──────────────────┘     │  - RFC 3164/5424     │     │  - Auto      │
                         │    parser            │     │    cleanup   │
                         └─────────────────────┘     └──────┬───────┘
                                                            │
                         ┌─────────────────────┐            │
                         │     Web UI           │◀───────────┘
                         │  (Flask + Gunicorn)  │
                         │                      │
                         │  - Dashboard         │
                         │  - Log search        │
                         │  - Host management   │
                         │  - Settings          │
                         │  - User auth         │
                         │                      │
                         │  http://<IP>:8443    │
                         └─────────────────────┘
```

## Requirements

- Ubuntu 22.04 LTS or 24.04 LTS
- Root/sudo access
- At least 2 GB RAM (4 GB recommended)
- Sufficient disk for log storage

## Quick Install

```bash
# Clone or copy the project files to the server
cd /path/to/syslog-server

# Make install script executable
chmod +x install.sh

# Run the installer
sudo ./install.sh
```

The installer will prompt for:
1. **MariaDB root password** — for initial database setup
2. **Syslog database user password** — used by the application
3. **Web admin password** — for the web UI (default: admin)
4. **Server hostname/IP** — for the TLS certificate SAN

## What the Installer Does

1. Installs MariaDB, Python 3, and dependencies
2. Creates and secures the MariaDB database
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

### Configure SonicWall to Send Syslog

1. Log in to your SonicWall management console
2. Navigate to **Device → Log → Syslog**
3. Click **Add** to create a new syslog server
4. Enter the syslog server's IP address
5. Choose your protocol and port:
   - **UDP 514** — Standard (fastest, no encryption)
   - **TCP 514** — Reliable delivery, no encryption
   - **TCP 6514** — TLS encrypted (recommended)
6. For TLS: Upload the CA certificate from `/etc/syslog-server/certs/ca.crt`
7. Select which log categories to forward
8. Click **OK** then **Accept**

### Configure Other Devices

Most network devices and Linux servers can send syslog. Common configurations:

**Linux (rsyslog):**
```bash
# /etc/rsyslog.d/remote.conf

# UDP
*.* @<server-ip>:514

# TCP
*.* @@<server-ip>:514

# TLS (requires rsyslog-gnutls)
*.* @@<server-ip>:6514
```

**Linux (systemd-journal):**
```bash
# Forward journal to syslog
# /etc/systemd/journald.conf
ForwardToSyslog=yes
```

**Generic network devices:**
Most switches, routers, and APs have a syslog configuration page. Enter the server IP and port 514 (UDP).

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

## Database Maintenance

### Automatic Cleanup
A MariaDB event runs daily at 3:00 AM UTC, deleting logs older than the retention period (default: 90 days). Configure via the web UI Settings page.

### Manual Cleanup
```sql
mysql -u root -p syslog_db -e "CALL cleanup_old_logs();"
```

### Database Size Check
```sql
mysql -u root -p syslog_db -e "
  SELECT
    table_name,
    ROUND(data_length / 1024 / 1024, 2) AS data_mb,
    ROUND(index_length / 1024 / 1024, 2) AS index_mb,
    table_rows
  FROM information_schema.tables
  WHERE table_schema = 'syslog_db';
"
```

### Backup
```bash
mysqldump -u root -p syslog_db > syslog_backup_$(date +%Y%m%d).sql
```

## Using Your Own TLS Certificates

Replace the self-signed certificates with your own:

```bash
# Copy your certificates
sudo cp your-cert.crt /etc/syslog-server/certs/server.crt
sudo cp your-cert.key /etc/syslog-server/certs/server.key
sudo cp your-ca.crt   /etc/syslog-server/certs/ca.crt

# Fix permissions
sudo chown syslog-server:syslog-server /etc/syslog-server/certs/*
sudo chmod 600 /etc/syslog-server/certs/server.key

# Restart
sudo systemctl restart syslog-receiver
```

## Putting the Web UI Behind HTTPS (Recommended)

For production, put the web UI behind an Nginx reverse proxy with HTTPS:

```bash
sudo apt install nginx certbot python3-certbot-nginx

# Create Nginx config
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

### Send a test syslog message

```bash
# UDP
echo "<14>$(date '+%b %d %H:%M:%S') testhost myapp[1234]: Test syslog message via UDP" | nc -u -w1 localhost 514

# TCP
echo "<14>$(date '+%b %d %H:%M:%S') testhost myapp[1234]: Test syslog message via TCP" | nc -w1 localhost 514

# TLS (using openssl)
echo "<14>$(date '+%b %d %H:%M:%S') testhost myapp[1234]: Test syslog message via TLS" | \
  openssl s_client -connect localhost:6514 -CAfile /etc/syslog-server/certs/ca.crt -quiet 2>/dev/null

# Using logger command
logger -n localhost -P 514 --udp "Test message from logger"
logger -n localhost -P 514 --tcp "Test message from logger TCP"
```

## Troubleshooting

**Services not starting:**
```bash
sudo journalctl -u syslog-receiver -n 50 --no-pager
sudo journalctl -u syslog-web -n 50 --no-pager
```

**Permission denied on port 514:**
The systemd service includes `AmbientCapabilities=CAP_NET_BIND_SERVICE`. If still failing:
```bash
sudo setcap cap_net_bind_service=+ep /opt/syslog-server/venv/bin/python3
```

**Database connection errors:**
```bash
# Test database connection
mysql -u syslog -p syslog_db -e "SELECT 1;"
```

**No logs appearing:**
```bash
# Check if port is listening
sudo ss -ulnp | grep 514
sudo ss -tlnp | grep 514

# Test with tcpdump
sudo tcpdump -i any port 514 -n
```

**TLS handshake failures:**
```bash
# Test TLS connection
openssl s_client -connect localhost:6514 -CAfile /etc/syslog-server/certs/ca.crt
```

## File Locations

| Path | Description |
|------|-------------|
| `/opt/syslog-server/` | Application code |
| `/etc/syslog-server/config.json` | Configuration |
| `/etc/syslog-server/certs/` | TLS certificates |
| `/var/log/syslog-server/` | Application logs |
| `/etc/systemd/system/syslog-receiver.service` | Receiver service |
| `/etc/systemd/system/syslog-web.service` | Web UI service |

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

This project is provided as-is for personal and commercial use.
