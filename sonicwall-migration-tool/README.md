# SonicWall Firewall Migration Tool v1.0

A Python tool that migrates configuration between SonicWall firewalls using the SonicOS REST API. Supports **Gen 6** (SonicOS 6.5.x), **Gen 7** (SonicOS 7.x), and **Gen 8** (SonicOS 8.x), including cross-generation migrations.

Includes a CLI config parser for offline migration when the source firewall's API is disabled.

## Supported Migration Paths

| From → To | Status |
|-----------|--------|
| Gen 6.5 → Gen 7 | ✅ Supported |
| Gen 6.5 → Gen 8 | ✅ Supported |
| Gen 7 → Gen 8 | ✅ Best compatibility |
| Gen 8 → Gen 7 | ⚠️ Works, some Gen 8 features may not exist on Gen 7 |

> **Note:** Always migrate from older to newer generation for best results.

## What Gets Migrated

| Category | Resources |
|---|---|
| **Zones** | Custom security zones |
| **Address Objects** | IPv4, IPv6, FQDN, MAC host/range/network objects |
| **Address Groups** | IPv4 and IPv6 address groups |
| **Service Objects** | Custom TCP/UDP/IP protocol definitions |
| **Service Groups** | Service object groups |
| **Schedule Objects** | Time-based schedules and groups |
| **Route Policies** | IPv4 and IPv6 static/policy routes |
| **NAT Policies** | IPv4 and IPv6 NAT translation rules |
| **Access Rules** | IPv4 and IPv6 firewall rules |
| **VPN Policies** | Site-to-site VPN configurations |
| **Content Filter** | CFS profiles |
| **Users & Groups** | Local user accounts and groups |
| **Interfaces** | Physical interface settings (IP, zone, mode) — optional |
| **VLANs** | VLAN sub-interfaces — mapped to selected interfaces |

## Quick Start

### 1. Install Dependencies

```bash
pip install requests
```

### 2. Prepare the Source Firewall

Enable the SonicOS API and configure authentication:

**Gen 7/8 (GUI):** Navigate to `Device > Settings > Administration > Audit/SonicOS API`:
- Enable **SonicOS API**
- Enable **RFC-2617 HTTP Basic Access Authentication**
- **Disable** Session Security (RFC-7616 Digest Authentication)
- Click **Accept**

**Gen 6.5 (GUI):** Navigate to `MANAGE > Appliance > Base Settings`:
- Enable **SonicOS API**
- Enable **RFC-2617 HTTP Basic Access Authentication**

**Important:** Session Security must be disabled for the API to work with Basic Auth. If you see `E_UNAUTHORIZED` errors after successful login, this is the cause.

### 3. Run the Migration

```bash
# Interactive mode (recommended for first run)
python3 sonicwall_migrator.py

# Dry run first to see what would happen
python3 sonicwall_migrator.py --dry-run --verbose
```

## Usage Modes

### Interactive Migration (API to API)
```bash
python3 sonicwall_migrator.py
```
Prompts for source and target firewall details, then walks through the migration interactively.

### CLI Import (When Source API Is Disabled)
```bash
python3 sonicwall_migrator.py --cli-import putty_log.txt
```
Parses a `show current-config` CLI output file as the source configuration. Use this when you can't or don't want to enable the API on the source firewall.

**To capture the CLI config:**
1. SSH/PuTTY into the source firewall (enable PuTTY session logging)
2. Enter config mode: `config`
3. Run: `show current-config`
4. Save the full output to a text file

### Export Only (Backup)
```bash
python3 sonicwall_migrator.py --export-only
```
Exports the source configuration to a JSON file without touching any target.

### Import From Backup
```bash
python3 sonicwall_migrator.py --import-only backup_file.json
```
Imports a previously exported JSON backup to a target firewall.

### Non-Interactive (Config File)
```bash
python3 sonicwall_migrator.py --config migration_config.json
```
See `examples/migration_config.json` for the config file format.

### Dry Run
```bash
python3 sonicwall_migrator.py --dry-run --verbose
```
Simulates the entire migration without making any changes. Use `--verbose` to see API response details and filtering decisions.

## Interface Migration

The tool handles interface migration with hardware compatibility checking.

**Safety: X0 is always excluded** from automatic migration. X0 is typically the primary LAN/management interface and must be configured manually when the new firewall is installed in the live network. This prevents you from losing management access to the new device.

When you select interface migration:

1. **Hardware comparison** — displays all physical interfaces and VLANs on both firewalls
2. **Automatic X0 exclusion** — X0 and its VLANs are excluded with a clear message
3. **Port mapping** — if the source has more interfaces than the target, an interactive mapper lets you assign source interfaces to available target ports
4. **VLAN selection** — for each mapped interface, choose to migrate all, some, or no VLANs

Example output:
```
*** X0 is EXCLUDED from migration (safety) ***
X0 is your primary LAN/management interface and must be
configured manually when the new firewall is installed live.

Interface migration plan:
  X0: EXCLUDED (configure manually when firewall goes live)
  X1 -> X1 + 2 VLANs
  X6 -> X6 + 2 VLANs
  X17 -> X3 + 2 VLANs
```

## Command Reference

| Flag | Description |
|------|-------------|
| `--dry-run` | Simulate without making changes |
| `--verbose`, `-v` | Show detailed debug logging |
| `--export-only` | Export source config to JSON, don't import |
| `--import-only FILE` | Import from a previously exported JSON file |
| `--cli-import FILE` | Parse CLI `show current-config` output as source |
| `--config FILE` | Use a JSON config file for non-interactive mode |

## Files

| File | Purpose |
|------|---------|
| `sonicwall_migrator.py` | Main migration tool — API client, migration engine, CLI interface |
| `cli_parser.py` | CLI config parser — parses `show current-config` output (required for `--cli-import`) |
| `examples/migration_config.json` | Example config file for non-interactive mode |

## Logging

Every run creates a detailed log at `migration_logs/migration_<timestamp>.log` containing:
- Every object exported, imported, skipped, or failed
- Interface hardware comparison
- VLAN mapping decisions
- Full API error responses
- Summary table with counts per resource

## Safety Features

- **X0 exclusion** — management interface is never migrated automatically
- **Confirmation prompt** — must type `YES` before any changes are applied
- **Dry-run mode** — test everything without touching the target
- **Automatic backup** — source config saved to JSON before any import
- **Hardware comparison** — warns when source has more interfaces than target
- **Commit per resource** — partial progress preserved if interrupted
- **Update fallback** — if POST fails because object exists, tries PUT to update
- **Verbose mode** — see exactly what the tool is doing at every step

## Troubleshooting

### API returns `E_UNAUTHORIZED` after successful login
**Cause:** Session Security (RFC-7616 Digest Authentication) is enabled on the firewall.
**Fix:** Disable it in the GUI under `Audit/SonicOS API` or via CLI:
```
config
sonicos-api
  no digest
  no sha256-digest
  no session-security
  basic
  enable
  exit
commit
```

### API is disabled and you can't/won't enable it
Use the CLI import mode:
```bash
python3 sonicwall_migrator.py --cli-import your_putty_log.txt
```

### Export returns 0 items
Run with `--verbose` to see API response structure and filtering decisions. Check that the API is returning data by testing with curl:
```bash
curl -k -c cookies.txt -X POST https://<IP>:<PORT>/api/sonicos/auth \
  -H "Content-Type: application/json" -H "Accept: application/json" \
  --user admin:password

curl -k -b cookies.txt -X GET https://<IP>:<PORT>/api/sonicos/address-objects/ipv4 \
  -H "Accept: application/json" --user admin:password
```

### "Only one admin session allowed"
Log out any existing sessions (GUI, CLI, or previous API session):
```bash
curl -k -b cookies.txt -X DELETE https://<IP>:<PORT>/api/sonicos/auth \
  -H "Accept: application/json" --user admin:password
```

## Limitations

- **Certificates/keys** cannot be exported via API
- **Licensed features** (GAV, IPS, anti-spyware signatures) depend on the target's licenses
- **HA configuration** is not migrated
- **SonicWall allows only one admin session** — ensure no one else is logged in
- Some Gen 6 firmware (pre-6.5) may have limited API support
- Downgrade migrations (newer → older) may encounter unsupported features

## Requirements

- Python 3.6+
- `requests` library

## License

Internal use. Provided as-is without warranty.
