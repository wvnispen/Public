# Changelog

## v1.4.3 (2026-02-27)

### Fixed
- **Gen6 `ip_assignment` structure**: Gen6 SonicOS API nests zone and IP configuration inside `ip_assignment.zone` and `ip_assignment.mode.static.{ip,netmask}` — extraction now handles this for both physical interfaces and VLAN sub-interfaces
- **VLAN POST body**: Now sends the full `ip_assignment` nested structure which Gen7 accepts (same format used for physical interfaces)
- **VLAN PUT schema error**: Fixed `"property 'interfaces' expected '['"` by using array wrapper format for PUT endpoint
- **Default NAT Policy filtering**: Built-in "Default NAT Policy" and "IPv6 Default NAT Policy" now filtered (can't be overwritten)
- **SSL VPN NAT filtering**: Extended to also filter IPv6 SSL VPN NATs referencing zone-specific `Interface IPv6 Addresses` groups
- Diagnostic logging moved to DEBUG level for cleaner production output

## v1.2.0 – v1.4.2 (2026-02-26)
Iterative bug fixes during live testing: Gen6 VLAN detection, cross-generation field stripping, auto-generated object filtering (NATs, routes, access rules, service groups, ICMPv6), zone migration ordering, VLAN endpoint discovery, and `ip_assignment` structure handling.

### Fixed
- **VLAN creation endpoint**: Changed from `interfaces/vlan` (doesn't exist on Gen 7) to `POST /api/sonicos/interfaces/ipv4` with proper `ipv4` schema body — the correct endpoint per SonicWall API documentation
- **VLAN creation: PUT endpoint** for existing VLANs now uses `/interfaces/ipv4/name/{PARENT}/vlan/{TAG}`
- **VLAN data extraction**: Fixed subnet mask not being extracted from Gen 6 API response where the field is `netmask` (not `mask`) inside the `ip` dict
- **VLAN body format**: Now sends full ipv4 interface schema with `vlan`, `zone`, `ip`, `ip_assignment` fields instead of the non-standard `vlan` sub-key format
- **SSL VPN NAT filtering**: Auto-generated SSL VPN NATs referencing zone-specific groups (`Office Interface IP`, `guest Interface IPv6 Addresses`) are now properly filtered — these are auto-created by SonicOS when zones are assigned to interfaces
- **Multiple VLAN body fallbacks**: Tries 3 different body formats and endpoints to maximize compatibility across SonicOS versions

## v1.3.0 (2026-02-26)

### Fixed
- **Zone ordering**: Zones now pre-imported before interface migration (interfaces reference custom zones like Office, guest, Voice)
- **ICMPv6 service objects**: 17 Gen 6-only ICMPv6 subtypes with `type: "none"` now filtered out
- **VLAN endpoint fallbacks**: Added multiple endpoint/body format attempts for VLAN creation
- **Debug logging**: Added VLAN POST body logging visible with `--verbose`

## v1.2.0 (2026-02-26)

### Fixed
- **Gen 6 VLAN detection**: `get_interface_summary()` now detects VLANs from Gen 6 API where VLANs appear as duplicate interface entries with `vlan`/`vlan_tag` fields
- **Interface cross-gen fields**: `link_speed`, `speed`, `duplex`, `mtu`, `auto-negotiate` stripped from interface PUT body when migrating Gen 6 → Gen 7
- **Built-in service groups**: ICMP, ICMPv6 and 10 related groups now filtered (not importable)
- **Auto-generated NAT policies**: Management NAT, IKE NAT, auto-added outbound NAT policies filtered by comment keywords
- **Auto-generated route policies**: Interface subnet routes (`X0 Subnet`, `X4:V101 Subnet`) filtered
- **Access rules with system refs**: Rules referencing `WLAN RemoteAccess Networks`, `All MGMT Management IP`, `MGMT Management IPv6 Addresses` filtered

## v1.1.0 (2026-02-26)

### Added
- **VLAN sub-interface creation**: Proper SonicOS VLAN creation with parent-interface, vlan-tag, zone, IP, subnet-mask
- **Enhanced interface mapping**: MGMT auto-mapped, interface count comparison, available target selection
- **12-step workflow**: Full migration workflow from credential collection through dependency-ordered import

### Fixed
- Previously created address objects instead of actual VLAN sub-interfaces

## v1.0.0 (2026-02-26)

### Initial Release
- 20+ resource types with dependency-aware migration
- Cross-generation support (Gen 6, Gen 7, Gen 8)
- Interactive and config-file modes
- Safety features: X0 exclusion, dry-run, per-resource commits, backups
- CLI config parser for devices with API disabled

### Bugs Fixed During Development
1. UUID filter killing Gen 8 objects
2. Overly aggressive name prefix filter
3. Double-wrapping on import
4. POST body schema format
5. Config mode not entered
6. Empty objects rejected
7. Cross-generation field type mismatches (boolean/non-object values)
8. Auto-generated interface objects filter
9. CLI parser integration
