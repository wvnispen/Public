#!/usr/bin/env python3
"""
SonicWall CLI Config Parser v1.0.0
====================================
Parses the output of 'show current-config' from a SonicWall CLI session
(e.g., PuTTY log, SSH capture) into structured JSON that the migration
tool can use to push configuration to a target firewall via API.

This is the offline/fallback path when the SonicOS API is disabled on
the source firewall.

Supports SonicOS 6.5.x, 7.x, and 8.x CLI output.
"""

import re
import json
import logging
from typing import Optional

logger = logging.getLogger("SonicWallMigrator")


class CLIConfigParser:
    """
    Parses SonicWall 'show current-config' CLI output into structured dicts
    that match the SonicOS API JSON format used by SonicWallMigrator.
    """

    def __init__(self, raw_text: str):
        # Clean up PuTTY/terminal artifacts
        self.raw = self._clean_text(raw_text)
        self.lines = self.raw.splitlines()
        self.firmware_version = ""
        self.model = ""
        self.serial = ""
        self._detect_metadata()

    # ------------------------------------------------------------------
    # Text cleanup
    # ------------------------------------------------------------------
    @staticmethod
    def _clean_text(text: str) -> str:
        """Remove terminal control chars, --MORE-- prompts, \r, etc."""
        # Remove \r
        text = text.replace("\r", "")
        # Remove --MORE-- prompts and trailing whitespace on those lines
        text = re.sub(r"--MORE--\s*", "", text)
        # Remove ANSI escape sequences
        text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)
        # Remove null bytes
        text = text.replace("\x00", "")
        return text

    def _detect_metadata(self):
        """Extract firmware version, model, serial from the config header."""
        for line in self.lines[:50]:
            line = line.strip()
            if line.startswith('firmware-version'):
                self.firmware_version = self._extract_quoted(line)
            elif line.startswith('model'):
                self.model = self._extract_quoted(line)
            elif line.startswith('serial-number'):
                self.serial = line.split(None, 1)[1].strip() if " " in line else ""

    @staticmethod
    def _extract_quoted(line: str) -> str:
        """Extract a quoted string value, or the last token if unquoted."""
        m = re.search(r'"([^"]*)"', line)
        if m:
            return m.group(1)
        parts = line.strip().split(None, 1)
        return parts[1] if len(parts) > 1 else ""

    # ------------------------------------------------------------------
    # Generic block extractor
    # ------------------------------------------------------------------
    def _extract_blocks(self, start_pattern: str) -> list:
        """
        Extract config blocks that start with `start_pattern` and end with
        a line containing only 'exit' at the proper indentation level.
        Returns list of (header_line, [body_lines]).
        """
        blocks = []
        i = 0
        while i < len(self.lines):
            line = self.lines[i]
            stripped = line.strip()
            if re.match(start_pattern, stripped):
                header = stripped
                body = []
                depth = 0
                i += 1
                while i < len(self.lines):
                    inner = self.lines[i].strip()
                    if inner == "exit":
                        if depth == 0:
                            i += 1
                            break
                        else:
                            depth -= 1
                            body.append(inner)
                    else:
                        body.append(inner)
                        # Track nested blocks (e.g., ip-assignment ... exit)
                        # A line that leads to a nested exit
                        if inner and not inner.startswith("no ") and i + 1 < len(self.lines):
                            next_lines = self.lines[i+1:i+20]
                            # Heuristic: if the next few lines are indented more, it's a sub-block
                            pass
                    i += 1
                blocks.append((header, body))
            else:
                i += 1
        return blocks

    def _extract_blocks_v2(self, start_pattern: str) -> list:
        """
        Extract config blocks that start with a line matching `start_pattern`
        (at column 0) and end with the next 'exit' at the base indentation.

        SonicWall CLI config format:
            keyword args ...       <- header (indent 0)
                field value        <- body (indent 4+)
                sub-block          <- sub-block opener
                    field          <- sub-body (indent 8+)
                    exit           <- closes sub-block
                field value
                exit               <- closes top-level block

        We track indent depth: the block ends when we hit 'exit' at the
        same indent level as the body (typically indent=4).
        """
        blocks = []
        i = 0
        while i < len(self.lines):
            stripped = self.lines[i].strip()
            if re.match(start_pattern, stripped):
                header = stripped
                body_lines = []
                base_indent = None
                i += 1
                while i < len(self.lines):
                    raw_line = self.lines[i]
                    s = raw_line.strip()

                    # Skip blank lines
                    if not s:
                        i += 1
                        continue

                    # Determine the base indent from the first non-empty body line
                    indent = len(raw_line) - len(raw_line.lstrip())
                    if base_indent is None and s:
                        base_indent = indent

                    # 'exit' at base indent closes this block
                    if s == "exit" and indent <= (base_indent or 4):
                        i += 1
                        break

                    body_lines.append(s)
                    i += 1

                blocks.append((header, body_lines))
            else:
                i += 1
        return blocks

    # ------------------------------------------------------------------
    # Address Object parsers
    # ------------------------------------------------------------------
    def parse_address_objects_ipv4(self) -> list:
        """Parse all 'address-object ipv4 ...' blocks."""
        blocks = self._extract_blocks_v2(r'^address-object ipv4 ')
        objects = []
        for header, body in blocks:
            obj = self._parse_address_object(header, body, "ipv4")
            if obj:
                objects.append(obj)
        return objects

    def parse_address_objects_ipv6(self) -> list:
        """Parse all 'address-object ipv6 ...' blocks."""
        blocks = self._extract_blocks_v2(r'^address-object ipv6 ')
        objects = []
        for header, body in blocks:
            obj = self._parse_address_object(header, body, "ipv6")
            if obj:
                objects.append(obj)
        return objects

    def parse_address_objects_fqdn(self) -> list:
        """Parse all 'address-object fqdn ...' blocks."""
        blocks = self._extract_blocks_v2(r'^address-object fqdn ')
        objects = []
        for header, body in blocks:
            obj = self._parse_fqdn_object(header, body)
            if obj:
                objects.append(obj)
        return objects

    def _parse_address_object(self, header: str, body: list, ip_ver: str) -> Optional[dict]:
        """Parse a single address-object block into API-compatible dict."""
        # header: 'address-object ipv4 "My Object"' or 'address-object ipv4 ObjName'
        name = self._extract_name_from_header(header, f"address-object {ip_ver} ")
        if not name:
            return None

        obj = {"name": name}
        for line in body:
            line = line.strip()
            if line.startswith("zone "):
                obj["zone"] = line.split(None, 1)[1].strip()
            elif line.startswith("host "):
                ip = line.split(None, 1)[1].strip()
                obj["host"] = {"ip": ip}
            elif line.startswith("network "):
                parts = line.split()
                if len(parts) >= 3:
                    obj["network"] = {"subnet": parts[1], "mask": parts[2]}
            elif line.startswith("range "):
                parts = line.split()
                if len(parts) >= 3:
                    obj["range"] = {"begin": parts[1], "end": parts[2]}
            elif line.startswith("uuid "):
                obj["uuid"] = line.split(None, 1)[1].strip()

        return obj

    def _parse_fqdn_object(self, header: str, body: list) -> Optional[dict]:
        """Parse a single FQDN address-object block."""
        name = self._extract_name_from_header(header, "address-object fqdn ")
        if not name:
            return None

        obj = {"name": name}
        for line in body:
            line = line.strip()
            if line.startswith("zone "):
                obj["zone"] = line.split(None, 1)[1].strip()
            elif line.startswith("domain "):
                obj["domain"] = line.split(None, 1)[1].strip()
            elif line.startswith("uuid "):
                obj["uuid"] = line.split(None, 1)[1].strip()
            elif line == "no dns-ttl":
                pass  # default

        return obj

    # ------------------------------------------------------------------
    # Address Group parsers
    # ------------------------------------------------------------------
    def parse_address_groups_ipv4(self) -> list:
        """Parse all 'address-group ipv4 ...' blocks."""
        blocks = self._extract_blocks_v2(r'^address-group ipv4 ')
        groups = []
        for header, body in blocks:
            grp = self._parse_address_group(header, body, "ipv4")
            if grp:
                groups.append(grp)
        return groups

    def parse_address_groups_ipv6(self) -> list:
        blocks = self._extract_blocks_v2(r'^address-group ipv6 ')
        groups = []
        for header, body in blocks:
            grp = self._parse_address_group(header, body, "ipv6")
            if grp:
                groups.append(grp)
        return groups

    def _parse_address_group(self, header: str, body: list, ip_ver: str) -> Optional[dict]:
        name = self._extract_name_from_header(header, f"address-group {ip_ver} ")
        if not name:
            return None

        grp = {"name": name, "address_object": {ip_ver: []}, "address_group": {ip_ver: []}}
        for line in body:
            line = line.strip()
            if line.startswith(f"address-object {ip_ver} "):
                member = self._extract_name_from_header(line, f"address-object {ip_ver} ")
                if member:
                    grp["address_object"][ip_ver].append({"name": member})
            elif line.startswith(f"address-group {ip_ver} "):
                member = self._extract_name_from_header(line, f"address-group {ip_ver} ")
                if member:
                    grp["address_group"][ip_ver].append({"name": member})
            elif line.startswith("uuid "):
                grp["uuid"] = line.split(None, 1)[1].strip()

        return grp

    # ------------------------------------------------------------------
    # Service Object parsers
    # ------------------------------------------------------------------
    def parse_service_objects(self) -> list:
        blocks = self._extract_blocks_v2(r'^service-object ')
        objects = []
        for header, body in blocks:
            obj = self._parse_service_object(header, body)
            if obj:
                objects.append(obj)
        return objects

    def _parse_service_object(self, header: str, body: list) -> Optional[dict]:
        name = self._extract_name_from_header(header, "service-object ")
        if not name:
            return None

        obj = {"name": name}
        for line in body:
            line = line.strip()
            if line.startswith("uuid "):
                obj["uuid"] = line.split(None, 1)[1].strip()
            elif re.match(r'^(TCP|UDP|ICMP|IP)\s', line):
                parts = line.split()
                obj["protocol"] = parts[0]
                if len(parts) >= 3:
                    obj["port_range"] = {"begin": parts[1], "end": parts[2]}
                elif len(parts) >= 2:
                    obj["port_range"] = {"begin": parts[1], "end": parts[1]}

        return obj

    def parse_service_groups(self) -> list:
        blocks = self._extract_blocks_v2(r'^service-group ')
        groups = []
        for header, body in blocks:
            grp = self._parse_service_group(header, body)
            if grp:
                groups.append(grp)
        return groups

    def _parse_service_group(self, header: str, body: list) -> Optional[dict]:
        name = self._extract_name_from_header(header, "service-group ")
        if not name:
            return None

        grp = {"name": name, "service_object": [], "service_group": []}
        for line in body:
            line = line.strip()
            if line.startswith("service-object "):
                member = self._extract_name_from_header(line, "service-object ")
                if member:
                    grp["service_object"].append({"name": member})
            elif line.startswith("service-group "):
                member = self._extract_name_from_header(line, "service-group ")
                if member:
                    grp["service_group"].append({"name": member})
            elif line.startswith("uuid "):
                grp["uuid"] = line.split(None, 1)[1].strip()

        return grp

    # ------------------------------------------------------------------
    # Zone parsers
    # ------------------------------------------------------------------
    def parse_zones(self) -> list:
        """Parse zone blocks. Only matches top-level zone declarations at column 0."""
        zones = []
        i = 0
        while i < len(self.lines):
            raw_line = self.lines[i]
            stripped = raw_line.strip()
            indent = len(raw_line) - len(raw_line.lstrip()) if stripped else 99
            if indent == 0 and re.match(r'^zone \S+$', stripped):
                header = stripped
                body_lines = []
                base_indent = None
                i += 1
                while i < len(self.lines):
                    inner_raw = self.lines[i]
                    s = inner_raw.strip()
                    if not s:
                        i += 1
                        continue
                    ind = len(inner_raw) - len(inner_raw.lstrip())
                    if base_indent is None:
                        base_indent = ind
                    if s == "exit" and ind <= (base_indent or 4):
                        i += 1
                        break
                    body_lines.append(s)
                    i += 1
                z = self._parse_zone(header, body_lines)
                if z:
                    zones.append(z)
            else:
                i += 1
        return zones

    def _parse_zone(self, header: str, body: list) -> Optional[dict]:
        name = self._extract_name_from_header(header, "zone ")
        if not name:
            return None

        zone = {"name": name}
        for line in body:
            line = line.strip()
            if line.startswith("security-type "):
                zone["security_type"] = line.split(None, 1)[1].strip()
            elif line.startswith("uuid "):
                zone["uuid"] = line.split(None, 1)[1].strip()
            elif line == "interface-trust":
                zone["interface_trust"] = True
            elif line.startswith("auto-generate-access-rules "):
                zone.setdefault("auto_generate_access_rules", []).append(
                    line.replace("auto-generate-access-rules ", "")
                )
            elif line == "gateway-anti-virus":
                zone["gateway_anti_virus"] = True
            elif line == "intrusion-prevention":
                zone["intrusion_prevention"] = True
            elif line == "anti-spyware":
                zone["anti_spyware"] = True
            elif line == "app-control":
                zone["app_control"] = True

        return zone

    # ------------------------------------------------------------------
    # Schedule parsers
    # ------------------------------------------------------------------
    def parse_schedules(self) -> list:
        blocks = self._extract_blocks_v2(r'^schedule ')
        schedules = []
        for header, body in blocks:
            s = self._parse_schedule(header, body)
            if s:
                schedules.append(s)
        return schedules

    def _parse_schedule(self, header: str, body: list) -> Optional[dict]:
        name = self._extract_name_from_header(header, "schedule ")
        if not name:
            return None

        sched = {"name": name, "recurring": []}
        for line in body:
            line = line.strip()
            if line.startswith("uuid "):
                sched["uuid"] = line.split(None, 1)[1].strip()
            elif line.startswith("recurring "):
                sched["recurring"].append(line)

        return sched

    # ------------------------------------------------------------------
    # Access Rule parsers
    # ------------------------------------------------------------------
    def parse_access_rules_ipv4(self) -> list:
        blocks = self._extract_blocks_v2(r'^access-rule ipv4 ')
        rules = []
        for header, body in blocks:
            r = self._parse_access_rule(header, body, "ipv4")
            if r:
                rules.append(r)
        return rules

    def parse_access_rules_ipv6(self) -> list:
        blocks = self._extract_blocks_v2(r'^access-rule ipv6 ')
        rules = []
        for header, body in blocks:
            r = self._parse_access_rule(header, body, "ipv6")
            if r:
                rules.append(r)
        return rules

    def _parse_access_rule(self, header: str, body: list, ip_ver: str) -> Optional[dict]:
        rule = {}
        for line in body:
            line = line.strip()
            if line.startswith("uuid "):
                rule["uuid"] = line.split(None, 1)[1].strip()
            elif line.startswith("name "):
                rule["name"] = self._extract_quoted_or_token(line, "name ")
            elif line.startswith("from "):
                rule["from"] = line.split(None, 1)[1].strip()
            elif line.startswith("to "):
                rule["to"] = line.split(None, 1)[1].strip()
            elif line.startswith("action "):
                rule["action"] = line.split(None, 1)[1].strip()
            elif line.startswith("source address "):
                rest = line.replace("source address ", "").strip()
                if rest.startswith("name "):
                    rule["source"] = {"address": {"name": self._extract_quoted_or_token(rest, "name ")}}
                elif rest.startswith("group "):
                    rule["source"] = {"address": {"group": self._extract_quoted_or_token(rest, "group ")}}
                elif rest == "any":
                    rule["source"] = {"address": {"any": True}}
                else:
                    rule["source"] = {"address": rest}
            elif line.startswith("source port "):
                rest = line.replace("source port ", "").strip()
                rule.setdefault("source", {})["port"] = rest
            elif line.startswith("destination address "):
                rest = line.replace("destination address ", "").strip()
                if rest.startswith("name "):
                    rule["destination"] = {"address": {"name": self._extract_quoted_or_token(rest, "name ")}}
                elif rest.startswith("group "):
                    rule["destination"] = {"address": {"group": self._extract_quoted_or_token(rest, "group ")}}
                elif rest == "any":
                    rule["destination"] = {"address": {"any": True}}
                else:
                    rule["destination"] = {"address": rest}
            elif line.startswith("service name "):
                rule["service"] = {"name": self._extract_quoted_or_token(line, "service name ")}
            elif line.startswith("service group "):
                rule["service"] = {"group": self._extract_quoted_or_token(line, "service group ")}
            elif line.startswith("service any"):
                rule["service"] = {"any": True}
            elif line.startswith("schedule "):
                rule["schedule"] = self._extract_quoted_or_token(line, "schedule ")
            elif line.startswith("comment "):
                rule["comment"] = self._extract_quoted_or_token(line, "comment ")
            elif line == "enable":
                rule["enable"] = True
            elif line == "no enable":
                rule["enable"] = False
            elif line.startswith("users included "):
                rule.setdefault("users", {})["included"] = line.split(None, 2)[2] if len(line.split()) > 2 else "all"
            elif line.startswith("users excluded "):
                rule.setdefault("users", {})["excluded"] = line.split(None, 2)[2] if len(line.split()) > 2 else "none"
            elif line == "auto-rule":
                rule["auto_rule"] = True
            elif line == "no auto-rule":
                rule["auto_rule"] = False

        if not rule.get("name"):
            # Derive name from header if not in body
            rule["name"] = header

        return rule

    # ------------------------------------------------------------------
    # NAT Policy parsers
    # ------------------------------------------------------------------
    def parse_nat_policies_ipv4(self) -> list:
        blocks = self._extract_blocks_v2(r'^nat-policy ipv4 ')
        policies = []
        for header, body in blocks:
            p = self._parse_nat_policy(header, body, "ipv4")
            if p:
                policies.append(p)
        return policies

    def _parse_nat_policy(self, header: str, body: list, ip_ver: str) -> Optional[dict]:
        policy = {}
        for line in body:
            line = line.strip()
            if line.startswith("uuid "):
                policy["uuid"] = line.split(None, 1)[1].strip()
            elif line.startswith("name "):
                policy["name"] = self._extract_quoted_or_token(line, "name ")
            elif line.startswith("inbound "):
                policy["inbound"] = line.split(None, 1)[1].strip()
            elif line.startswith("outbound "):
                policy["outbound"] = line.split(None, 1)[1].strip()
            elif line.startswith("source "):
                rest = line.replace("source ", "", 1).strip()
                policy["source"] = self._parse_nat_ref(rest)
            elif line.startswith("translated-source "):
                rest = line.replace("translated-source ", "", 1).strip()
                policy["translated_source"] = self._parse_nat_ref(rest)
            elif line.startswith("destination "):
                rest = line.replace("destination ", "", 1).strip()
                policy["destination"] = self._parse_nat_ref(rest)
            elif line.startswith("translated-destination "):
                rest = line.replace("translated-destination ", "", 1).strip()
                policy["translated_destination"] = self._parse_nat_ref(rest)
            elif line.startswith("service "):
                rest = line.replace("service ", "", 1).strip()
                policy["service"] = self._parse_nat_ref(rest)
            elif line.startswith("translated-service "):
                rest = line.replace("translated-service ", "", 1).strip()
                policy["translated_service"] = self._parse_nat_ref(rest)
            elif line == "enable":
                policy["enable"] = True
            elif line == "no enable":
                policy["enable"] = False
            elif line.startswith("comment "):
                policy["comment"] = self._extract_quoted_or_token(line, "comment ")
            elif line == "dns-doctoring":
                policy["dns_doctoring"] = True
            elif line == "no dns-doctoring":
                policy["dns_doctoring"] = False
            elif line.startswith("priority "):
                policy["priority"] = line.split(None, 1)[1].strip()

        return policy

    def _parse_nat_ref(self, text: str) -> dict:
        """Parse a NAT source/dest/service reference like 'name "X1 IP"' or 'any' or 'original'."""
        if text == "any":
            return {"any": True}
        elif text == "original":
            return {"original": True}
        elif text.startswith("name "):
            return {"name": self._extract_quoted_or_token(text, "name ")}
        elif text.startswith("group "):
            return {"group": self._extract_quoted_or_token(text, "group ")}
        else:
            return {"value": text}

    # ------------------------------------------------------------------
    # Interface parsers
    # ------------------------------------------------------------------
    def parse_interfaces(self) -> list:
        blocks = self._extract_blocks_v2(r'^interface X\d+$')
        interfaces = []
        for header, body in blocks:
            iface = self._parse_interface(header, body)
            if iface:
                interfaces.append(iface)
        return interfaces

    def parse_vlan_interfaces(self) -> list:
        blocks = self._extract_blocks_v2(r'^interface X\d+ vlan \d+')
        vlans = []
        for header, body in blocks:
            vlan = self._parse_interface(header, body)
            if vlan:
                # Extract parent and vlan tag from header
                m = re.match(r'interface (X\d+) vlan (\d+)', header)
                if m:
                    vlan["parent"] = m.group(1)
                    vlan["vlan_tag"] = m.group(2)
                    vlan["name"] = f"{m.group(1)}:V{m.group(2)}"
                vlans.append(vlan)
        return vlans

    def _parse_interface(self, header: str, body: list) -> Optional[dict]:
        # Extract interface name from header
        m = re.match(r'interface (\S+(?:\s+vlan\s+\d+)?)', header)
        name = m.group(1) if m else header.replace("interface ", "")

        iface = {"name": name.replace(" vlan ", ":V")}
        for line in body:
            line = line.strip()
            if line.startswith("ip-assignment "):
                parts = line.split()
                if len(parts) >= 2:
                    iface["zone"] = parts[1]
                if "static" in line:
                    iface["ip_assignment"] = "static"
                elif "portshield" in line:
                    iface["ip_assignment"] = "portshield"
                    if len(parts) >= 3:
                        iface["portshield_to"] = parts[2]
                elif "dhcp" in line.lower():
                    iface["ip_assignment"] = "dhcp"
            elif line.startswith("ip ") and not line.startswith("ip-"):
                iface["ip"] = line.split(None, 1)[1].strip()
            elif line.startswith("netmask "):
                iface["netmask"] = line.split(None, 1)[1].strip()
            elif line.startswith("gateway ") and not line.startswith("no gateway"):
                iface["gateway"] = line.split(None, 1)[1].strip()
            elif line.startswith("comment "):
                iface["comment"] = self._extract_quoted_or_token(line, "comment ")
            elif line == "no ip-assignment":
                iface["ip_assignment"] = "none"
            elif line.startswith("management ") and not line.startswith("no management"):
                iface.setdefault("management", []).append(line.split(None, 1)[1])
            elif line.startswith("mtu "):
                iface["mtu"] = line.split(None, 1)[1].strip()
            elif line.startswith("link-speed "):
                iface["link_speed"] = line.split(None, 1)[1].strip()
            elif line.startswith("sonicpoint limit "):
                iface["sonicpoint_limit"] = line.split()[-1]
            elif line.startswith("bandwidth-management egress "):
                iface["bw_egress"] = line.split()[-1]
            elif line.startswith("bandwidth-management ingress "):
                iface["bw_ingress"] = line.split()[-1]
            elif line == "shutdown-port":
                iface["enabled"] = False
            elif line == "no shutdown-port":
                iface["enabled"] = True

        return iface

    # ------------------------------------------------------------------
    # Route Policy parsers
    # ------------------------------------------------------------------
    def parse_route_policies_ipv4(self) -> list:
        blocks = self._extract_blocks_v2(r'^route-policy ipv4 ')
        routes = []
        for header, body in blocks:
            r = self._parse_route_policy(header, body)
            if r:
                routes.append(r)
        return routes

    def _parse_route_policy(self, header: str, body: list) -> Optional[dict]:
        route = {"_header": header}
        for line in body:
            line = line.strip()
            if line.startswith("uuid "):
                route["uuid"] = line.split(None, 1)[1].strip()
            elif line.startswith("name "):
                route["name"] = self._extract_quoted_or_token(line, "name ")
            elif line.startswith("interface "):
                route["interface"] = line.split(None, 1)[1].strip()
            elif line.startswith("metric "):
                route["metric"] = line.split(None, 1)[1].strip()
            elif line.startswith("destination "):
                rest = line.replace("destination ", "", 1).strip()
                route["destination"] = self._parse_nat_ref(rest)
            elif line.startswith("source "):
                rest = line.replace("source ", "", 1).strip()
                route["source"] = self._parse_nat_ref(rest)
            elif line.startswith("gateway "):
                rest = line.replace("gateway ", "", 1).strip()
                route["gateway"] = self._parse_nat_ref(rest)
            elif line.startswith("distance "):
                route["distance"] = line.split(None, 1)[1].strip()
            elif line == "enable":
                route["enable"] = True
            elif line == "no enable":
                route["enable"] = False
            elif line.startswith("comment "):
                route["comment"] = self._extract_quoted_or_token(line, "comment ")

        # Try to parse name/details from header if not in body
        if "name" not in route:
            route["name"] = header

        return route

    # ------------------------------------------------------------------
    # VPN Policy parsers
    # ------------------------------------------------------------------
    def parse_vpn_policies(self) -> list:
        blocks = self._extract_blocks_v2(r'^vpn policy ')
        vpns = []
        for header, body in blocks:
            vpn = {"_header": header, "name": header.replace("vpn policy ", "")}
            for line in body:
                line = line.strip()
                if line.startswith("uuid "):
                    vpn["uuid"] = line.split(None, 1)[1].strip()
                elif line.startswith("name "):
                    vpn["name"] = self._extract_quoted_or_token(line, "name ")
                elif line == "enable":
                    vpn["enable"] = True
                elif line == "no enable":
                    vpn["enable"] = False
            vpns.append(vpn)
        return vpns

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_name_from_header(header: str, prefix: str) -> str:
        """Extract the object name from a header line after the given prefix."""
        rest = header[len(prefix):].strip()
        # Handle quoted names: 'address-object ipv4 "My Object"'
        if rest.startswith('"'):
            m = re.match(r'"([^"]*)"', rest)
            return m.group(1) if m else rest.strip('"')
        # Unquoted single-token name
        return rest.split()[0] if rest else ""

    @staticmethod
    def _extract_quoted_or_token(line: str, prefix: str) -> str:
        """Extract value after prefix, handling quoted strings."""
        rest = line[len(prefix):].strip() if line.startswith(prefix) else line.strip()
        # Try to find prefix in the line
        idx = line.find(prefix)
        if idx >= 0:
            rest = line[idx + len(prefix):].strip()
        if rest.startswith('"'):
            m = re.match(r'"([^"]*)"', rest)
            return m.group(1) if m else rest.strip('"')
        return rest

    # ------------------------------------------------------------------
    # Master parse: build full config dict
    # ------------------------------------------------------------------
    def parse_all(self) -> dict:
        """
        Parse the entire CLI config into a dict compatible with the
        migration tool's expected format.
        """
        logger.info("Parsing CLI configuration ...")
        logger.info(f"  Model: {self.model}")
        logger.info(f"  Firmware: {self.firmware_version}")

        # Determine generation
        gen = "Unknown"
        if "8." in self.firmware_version:
            gen = "Gen8"
        elif "7." in self.firmware_version:
            gen = "Gen7"
        elif "6." in self.firmware_version:
            gen = "Gen6"

        config = {
            "_metadata": {
                "exported_at": "CLI-parsed",
                "source_host": "cli-export",
                "source_model": self.model,
                "source_firmware": self.firmware_version,
                "source_generation": gen,
                "source_serial": self.serial,
                "parse_mode": "cli",
            },
        }

        # Parse each resource type
        parsers = [
            ("Zones", self.parse_zones),
            ("Address Objects (IPv4)", self.parse_address_objects_ipv4),
            ("Address Objects (IPv6)", self.parse_address_objects_ipv6),
            ("Address Objects (FQDN)", self.parse_address_objects_fqdn),
            ("Address Groups (IPv4)", self.parse_address_groups_ipv4),
            ("Address Groups (IPv6)", self.parse_address_groups_ipv6),
            ("Service Objects", self.parse_service_objects),
            ("Service Groups", self.parse_service_groups),
            ("Schedule Objects", self.parse_schedules),
            ("Access Rules (IPv4)", self.parse_access_rules_ipv4),
            ("Access Rules (IPv6)", self.parse_access_rules_ipv6),
            ("NAT Policies (IPv4)", self.parse_nat_policies_ipv4),
            ("Route Policies (IPv4)", self.parse_route_policies_ipv4),
            ("VPN Policies (Site-to-Site)", self.parse_vpn_policies),
            ("Interfaces", self.parse_interfaces),
            ("VLAN Interfaces", self.parse_vlan_interfaces),
        ]

        for name, parser_func in parsers:
            try:
                items = parser_func()
                config[name] = items
                logger.info(f"  {name}: {len(items)} items parsed")
            except Exception as e:
                logger.warning(f"  {name}: parse error — {e}")
                config[name] = []

        return config
