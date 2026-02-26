# SonicWall Configuration Migrator v1.4.0

A Python tool for migrating firewall configurations between SonicWall appliances across different hardware generations (Gen 6, Gen 7, Gen 8) using the SonicOS REST API.

## Features

- **Cross-generation migration** — Gen 6 → Gen 7, Gen 7 → Gen 8, or same-generation
- **Interface & VLAN migration** — physical interface mapping with VLAN sub-interface creation
- **Smart filtering** — automatically skips built-in/auto-generated objects, routes, NAT policies, and access rules
- **20+ resource types** — zones, address objects/groups, service objects/groups, schedules, routes, NAT policies, access rules, VPN policies, content filter profiles, local users/groups
- **Dependency-aware import order** — zones → interfaces → address objects → services → routes → NAT → access rules
- **Safety features** — X0 always excluded, dry-run mode, per-resource commits, automatic backups
- **Interactive & config-file modes** — guided prompts or automated via JSON config
- **CLI config import** — parse `show current-config` output for devices with API disabled

## Requirements

- Python 3.6+
- `requests` library (`pip install requests`)
- SonicOS API enabled on both source and target firewalls

## Quick Start

### Interactive Mode
```bash
python3 sonicwall_migrator.py
```
The tool will prompt for credentials, resource selection, and interface mapping.

### Config File Mode
```bash
python3 sonicwall_migrator.py --config migration_config_sample.json
```

### Dry Run (preview without changes)
```bash
python3 sonicwall_migrator.py --dry-run
```

### Verbose Logging (debug output)
```bash
python3 sonicwall_migrator.py --verbose
```

### CLI Config Import (API disabled on source)
```bash
python3 sonicwall_migrator.py --cli-import show_current_config.txt
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--config FILE` | Use a JSON config file instead of interactive prompts |
| `--dry-run` | Preview migration without making changes |
| `--verbose` | Enable debug-level logging with full API responses |
| `--cli-import FILE` | Parse a `show current-config` text file as the source |

## Migration Order

The tool follows a strict dependency order to ensure referenced objects exist before they're needed:

1. **Zones** — custom zones (Office, guest, Voice, etc.)
2. **Physical Interfaces** — configured with zone assignment and IP
3. **VLAN Sub-Interfaces** — created on parent interfaces with zone, IP, and VLAN tag
4. **Address Objects** — IPv4, IPv6, FQDN, MAC
5. **Address Groups** — IPv4, IPv6
6. **Service Objects & Groups**
7. **Schedule Objects & Groups**
8. **Route Policies** — IPv4, IPv6
9. **NAT Policies** — IPv4, IPv6
10. **Access Rules** — IPv4, IPv6
11. **VPN Policies, Content Filters, Users**

## Automatic Filtering

The migrator automatically excludes objects that SonicOS creates/manages internally:

### Address Objects
- Interface-specific: `X0 IP`, `X0 Subnet`, `X4:V101 IP`, `MGMT Default Gateway`, etc.
- System aggregates: `All Interface IP`, `Firewalled Subnets`, `WAN RemoteAccess Networks`, etc.
- Zone-derived: `LAN Subnets`, `Office Interface IP`, etc.

### Service Objects
- ICMPv6 subtypes with `type: "none"` (Gen 6 only, not supported on Gen 7/8)

### Service Groups
- Built-in ICMP/ICMPv6 groups: `ICMP`, `ICMPv6`, `Destination Unreachable Group`, etc.

### NAT Policies
- Auto-generated: Management NAT, IKE NAT, auto-added outbound NAT policies
- MGMT interface NATs
- SSL VPN NATs referencing zone-specific Interface IP/IPv6 groups

### Route Policies
- Auto-generated interface subnet routes (`X0 Subnet`, `X4:V101 Subnet`, etc.)
- MGMT interface routes

### Access Rules
- Rules referencing `WLAN RemoteAccess Networks`, `All MGMT Management IP`, `MGMT Management IPv6 Addresses`

### Default Zones
- Built-in zones: LAN, WAN, DMZ, VPN, SSLVPN, WLAN, MGMT, Multicast, RADIUS

## Cross-Generation Compatibility

When migrating between generations, the tool automatically:
- Strips incompatible fields (`geo_ip_filter`, `botnet_filter`, `manual`, `priority`, etc.)
- Removes interface-specific fields Gen 7 rejects (`link_speed`, `speed`, `duplex`, `mtu`, `auto-negotiate`)
- Cleans empty nested objects that cause validation errors
- Handles UUID format differences between generations

## Interface Migration

### Physical Interfaces
- X0 is **always excluded** for safety (primary LAN/management)
- MGMT is auto-mapped if available on both devices
- When the target has fewer interfaces, you're prompted to map source → target
- Interface zones, IP addresses, and management settings are configured

### VLAN Sub-Interfaces
- Detected from the Gen 6 API (which returns VLANs as duplicated parent interface entries)
- Created on the target using `POST /api/sonicos/interfaces/ipv4` with proper VLAN tag, zone, and IP
- Support for multiple body formats to handle different SonicOS versions

## Enabling the SonicOS API

On each firewall:
1. Log in to the web management interface
2. Navigate to **MANAGE → Administration → SonicOS API**
3. Check **Enable SonicOS API** and **Enable RFC-2617 HTTP Basic**
4. Click **Accept** and save

> **Security tip:** Disable the API after migration is complete.

## File Structure

```
sonicwall-migrator/
├── sonicwall_migrator.py          # Main migration tool
├── cli_parser.py                  # CLI config parser (optional)
├── migration_config_sample.json   # Example config file
├── README.md                      # This file
└── CHANGELOG.md                   # Version history
```

## Troubleshooting

### "API endpoint is incomplete"
The SonicOS API is not enabled or the endpoint doesn't exist on this firmware version. Enable the API or check the SonicOS version.

### "is not a reasonable value"
A field value from the source is not accepted by the target. This usually happens with cross-generation migrations. The tool auto-strips known problematic fields, but custom fields may need manual adjustment.

### Commit returns HTTP 500
This typically means a referenced object doesn't exist on the target yet. The dependency-ordered import should prevent this, but complex cross-references may occasionally cause issues. Re-running the migration usually resolves it since the objects will exist on retry.

### VLANs not detected on source
If the source is Gen 6, VLANs appear as duplicate interface entries in the API response. The tool detects these by comparing zones and IPs of duplicate-named interfaces. If your VLANs still aren't detected, use `--verbose` to see the raw interface data.

## License

Internal use. Modify as needed for your organization.
