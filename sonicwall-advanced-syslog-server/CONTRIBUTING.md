# Contributing to Sonicwall Advanced Syslog Server

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check the existing issues to avoid duplicates.

When filing a bug report, include:
- **OS version** (e.g., Ubuntu 24.04 LTS)
- **Python version** (`python3 --version`)
- **MariaDB version** (`mariadb --version`)
- **Steps to reproduce** the issue
- **Expected behavior** vs. **actual behavior**
- **Relevant log output** from `journalctl -u syslog-receiver` or `journalctl -u syslog-web`

### Suggesting Features

Open an issue with the `enhancement` label describing:
- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

### Submitting Changes

1. **Fork** the repository
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following the coding standards below
4. **Test your changes** thoroughly
5. **Commit** with a clear, descriptive message:
   ```bash
   git commit -m "Add: brief description of what was added"
   ```
6. **Push** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Open a Pull Request** against `main`

## Coding Standards

### Python
- Follow [PEP 8](https://peps.python.org/pep-0008/) style guidelines
- Use type hints where practical
- Add docstrings to functions and classes
- Keep functions focused and reasonably short
- Use meaningful variable and function names

### HTML / CSS / JavaScript
- Use semantic HTML elements
- Follow the existing CSS variable naming convention
- Keep JavaScript minimal and vanilla (no heavy frameworks in templates)
- Ensure responsive design works on mobile

### SQL
- Use uppercase for SQL keywords
- Include `IF NOT EXISTS` / `IF EXISTS` for safety
- Add comments explaining non-obvious queries
- Always parameterize queries (never string-concatenate user input)

### Commit Messages

Use clear, descriptive commit messages with a prefix:
- `Add:` — new features or files
- `Fix:` — bug fixes
- `Update:` — changes to existing functionality
- `Remove:` — removed features or files
- `Docs:` — documentation changes only
- `Refactor:` — code restructuring without behavior change
- `Security:` — security-related changes

### Example:
```
Add: SNMP trap receiver support for network devices
Fix: TLS handshake timeout causing dropped connections
Docs: Add Fortinet FortiGate syslog configuration guide
```

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/sonicwall-syslog-server.git
cd sonicwall-syslog-server

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy the example config
cp config.json config.local.json
# Edit config.local.json with your local MariaDB credentials

# Run the web UI in debug mode
SYSLOG_CONFIG=config.local.json python3 web_app.py

# In another terminal, run the receiver
sudo SYSLOG_CONFIG=config.local.json python3 syslog_receiver.py
```

## Testing

Before submitting a pull request, verify:

1. **Syslog receiver** starts without errors on all four ports
2. **Web UI** loads correctly and all pages render
3. **Log search** returns correct results with various filters
4. **Host management** CRUD operations work
5. **TLS connections** succeed with the generated certificates
6. Test with actual syslog messages:
   ```bash
   # UDP test
   echo "<14>Mar 13 12:00:00 testhost myapp: Test message" | nc -u -w1 localhost 514
   
   # TCP test
   echo "<14>Mar 13 12:00:00 testhost myapp: Test message" | nc -w1 localhost 514
   ```

## Areas Where Help Is Especially Welcome

- Support for additional syslog formats (CEF, LEEF)
- LDAP / Active Directory authentication integration
- Grafana dashboard templates
- Docker / Docker Compose packaging
- Automated test suite
- Performance optimization for high-volume deployments
- Additional device configuration guides (Fortinet, Palo Alto, Ubiquiti, etc.)
- Internationalization (i18n) for the web UI
- SNMP trap receiver support
- Syslog forwarding / relay capability

## Code of Conduct

Be respectful and constructive in all interactions. We're all here to build something useful together.

## Questions?

Open an issue with the `question` label — we're happy to help!
