# Changelog

## v1.0.0 — 2026-02-20

### Features
- Full API-to-API migration between SonicWall Gen 6.5, Gen 7, and Gen 8 firewalls
- CLI config parser (`--cli-import`) for migrating from firewalls with API disabled
- Interactive interface mapping with hardware compatibility checking
- X0 (management interface) automatically excluded from migration for safety
- VLAN sub-interface migration with per-interface selection
- Dry-run mode (`--dry-run`) to simulate without changes
- Verbose logging (`--verbose`) showing API response details and filtering decisions
- Export-only mode for configuration backups
- Import from previously exported JSON backups
- Non-interactive mode via JSON config file
- Dependency-aware migration ordering (zones → objects → groups → rules)
- POST/PUT fallback — updates existing objects instead of failing
- Per-resource commit for safe partial progress
- Detailed log files with full error context

### Supported Resources
- Zones
- Address Objects (IPv4, IPv6, FQDN, MAC)
- Address Groups (IPv4, IPv6)
- Service Objects and Groups
- Schedule Objects and Groups
- Route Policies (IPv4, IPv6)
- NAT Policies (IPv4, IPv6)
- Access Rules (IPv4, IPv6)
- VPN Policies
- Content Filter Profiles
- Local Users and Groups
- Physical Interfaces and VLANs

### Known Limitations
- Certificates and keys cannot be exported via API
- HA configuration is not migrated
- Licensed feature signatures depend on target licensing
- Single admin session limit on SonicWall devices
