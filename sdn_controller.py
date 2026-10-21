"""
SDN Controller Engine for Intelligent Traffic Management & Access Control
Simulates an SDN Control Plane managing a 3-switch topology (S1, S2, S3),
flow tables, IP access control (ACL), deterministic BFS routing, and event logging.
"""

from collections import deque
from datetime import datetime
import ipaddress
import threading
import uuid


class SDNController:
    def __init__(self):
        self.lock = threading.Lock()

        # Topology Definition
        # 3 Switches: S1 (Edge A), S2 (Core), S3 (Edge B)
        self.switches = {
            "S1": {
                "id": "S1",
                "name": "Switch 1 (Ingress / Edge A)",
                "dpid": "00:00:00:00:00:01",
                "status": "UP",
                "ports": [
                    {"port_no": 1, "connected_to": "H1", "type": "host"},
                    {"port_no": 2, "connected_to": "H2", "type": "host"},
                    {"port_no": 3, "connected_to": "S2", "type": "switch"},
                    {"port_no": 4, "connected_to": "S3", "type": "switch"},
                ]
            },
            "S2": {
                "id": "S2",
                "name": "Switch 2 (Core Transit)",
                "dpid": "00:00:00:00:00:02",
                "status": "UP",
                "ports": [
                    {"port_no": 1, "connected_to": "H3", "type": "host"},
                    {"port_no": 2, "connected_to": "S1", "type": "switch"},
                    {"port_no": 3, "connected_to": "S3", "type": "switch"},
                ]
            },
            "S3": {
                "id": "S3",
                "name": "Switch 3 (Egress / Edge B)",
                "dpid": "00:00:00:00:00:03",
                "status": "UP",
                "ports": [
                    {"port_no": 1, "connected_to": "H4", "type": "host"},
                    {"port_no": 2, "connected_to": "H5", "type": "host"},
                    {"port_no": 3, "connected_to": "S1", "type": "switch"},
                    {"port_no": 4, "connected_to": "S2", "type": "switch"},
                ]
            }
        }

        # Inter-switch links (Undirected graph adjacency for BFS routing)
        self.switch_links = [
            {"src": "S1", "dst": "S2", "status": "ACTIVE", "latency_ms": 2},
            {"src": "S2", "dst": "S3", "status": "ACTIVE", "latency_ms": 2},
            {"src": "S1", "dst": "S3", "status": "ACTIVE", "latency_ms": 4},
        ]

        # Host database (IP -> Host Info)
        self.hosts = {
            "10.0.0.1": {"id": "H1", "ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "switch": "S1", "port": 1},
            "10.0.0.2": {"id": "H2", "ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "switch": "S1", "port": 2},
            "10.0.0.3": {"id": "H3", "ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "switch": "S2", "port": 1},
            "10.0.0.4": {"id": "H4", "ip": "10.0.0.4", "mac": "00:00:00:00:00:04", "switch": "S3", "port": 1},
            "10.0.0.5": {"id": "H5", "ip": "10.0.0.5", "mac": "00:00:00:00:00:05", "switch": "S3", "port": 2},
        }

        # Flow Rules / ACL Table
        # Default lowest priority rule: ALLOW ALL
        self.rules = [
            {
                "id": "FLOW-DEF-001",
                "priority": 1,
                "match": {
                    "src_ip": "*",
                    "dst_ip": "*",
                    "protocol": "*",
                    "dst_port": "*"
                },
                "match_display": "Source: ANY | Dest: ANY",
                "action": "FORWARD",
                "is_active": True,
                "is_default": True,
                "description": "Default SDN Forwarding Rule (Permit unmatched traffic)",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        ]

        # Event & Packet Decision Log
        self.event_logs = []

        # Real-time traffic statistics
        self.stats = {
            "total_packets": 0,
            "allowed_packets": 0,
            "blocked_packets": 0,
        }

    # -------------------------------------------------------------
    # Topology & Graph Routing Logic (BFS)
    # -------------------------------------------------------------
    def get_topology(self):
        """Returns the full simulated topology definition."""
        with self.lock:
            return {
                "switches": self.switches,
                "switch_links": self.switch_links,
                "hosts": self.hosts
            }

    def _build_switch_adjacency(self):
        """Constructs an adjacency list for the switches based on ACTIVE links."""
        adj = {sw: [] for sw in self.switches}
        for link in self.switch_links:
            if link["status"] == "ACTIVE":
                s1, s2 = link["src"], link["dst"]
                if s1 in adj and s2 in adj:
                    adj[s1].append(s2)
                    adj[s2].append(s1)
        return adj

    def compute_route(self, src_switch, dst_switch):
        """
        Deterministic Breadth-First Search (BFS) to find the shortest hop path
        between two switches in the simulated SDN topology.
        Returns a list of switch IDs, e.g. ['S1', 'S3'] or ['S1', 'S2', 'S3'].
        """
        if src_switch == dst_switch:
            return [src_switch]

        adj = self._build_switch_adjacency()
        queue = deque([[src_switch]])
        visited = {src_switch}

        while queue:
            path = queue.popleft()
            current = path[-1]

            # Deterministic sorting of neighbors for consistent path evaluation
            neighbors = sorted(adj.get(current, []))
            for neighbor in neighbors:
                if neighbor == dst_switch:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])

        return None  # No path found

    # -------------------------------------------------------------
    # Flow Rule & ACL Management
    # -------------------------------------------------------------
    def get_rules(self):
        """Returns all installed flow rules sorted by priority descending."""
        with self.lock:
            # Sort by priority desc so highest priority blocking rules appear first
            sorted_rules = sorted(self.rules, key=lambda r: r["priority"], reverse=True)
            return sorted_rules

    def add_block_rule(self, src_ip, description="Administrator Block Rule"):
        """
        Creates an explicit IP DROP rule with high priority (100).
        """
        with self.lock:
            # Validate IP format
            ipaddress.ip_address(src_ip.strip())

            # Check if an active rule for this src_ip already exists
            for rule in self.rules:
                if not rule.get("is_default") and rule["match"].get("src_ip") == src_ip.strip():
                    return False, f"A rule for Source IP {src_ip} already exists (ID: {rule['id']})."

            rule_id = f"ACL-{str(uuid.uuid4())[:8].upper()}"
            new_rule = {
                "id": rule_id,
                "priority": 100,
                "match": {
                    "src_ip": src_ip.strip(),
                    "dst_ip": "*",
                    "protocol": "*",
                    "dst_port": "*"
                },
                "match_display": f"Source IP: {src_ip.strip()}",
                "action": "DROP",
                "is_active": True,
                "is_default": False,
                "description": description.strip() or f"Access control: Block {src_ip.strip()}",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.rules.append(new_rule)

            # Log this control plane event
            self._log_event(
                event_type="RULE_ADDED",
                src_ip=src_ip.strip(),
                dst_ip="-",
                protocol="-",
                port="-",
                decision="RULE_UPDATE",
                reason=f"Added flow rule {rule_id}: DROP traffic from {src_ip.strip()}",
                path=[]
            )
            return True, new_rule

    def remove_rule(self, rule_id):
        """Removes a user-defined flow rule by ID."""
        with self.lock:
            for i, rule in enumerate(self.rules):
                if rule["id"] == rule_id:
                    if rule.get("is_default"):
                        return False, "Cannot delete default controller flow rule."
                    removed = self.rules.pop(i)
                    self._log_event(
                        event_type="RULE_REMOVED",
                        src_ip=removed["match"].get("src_ip", "-"),
                        dst_ip="-",
                        protocol="-",
                        port="-",
                        decision="RULE_UPDATE",
                        reason=f"Deleted flow rule {rule_id} (Target: {removed['match_display']})",
                        path=[]
                    )
                    return True, f"Rule {rule_id} removed successfully."
            return False, f"Rule with ID {rule_id} not found."

    def toggle_rule(self, rule_id):
        """Enables or disables an access control rule."""
        with self.lock:
            for rule in self.rules:
                if rule["id"] == rule_id:
                    if rule.get("is_default"):
                        return False, "Cannot disable the default controller flow rule."
                    rule["is_active"] = not rule["is_active"]
                    state_str = "ENABLED" if rule["is_active"] else "DISABLED"
                    self._log_event(
                        event_type="RULE_TOGGLED",
                        src_ip=rule["match"].get("src_ip", "-"),
                        dst_ip="-",
                        protocol="-",
                        port="-",
                        decision="RULE_UPDATE",
                        reason=f"Rule {rule_id} {state_str}. Matching: {rule['match_display']}",
                        path=[]
                    )
                    return True, {"id": rule_id, "is_active": rule["is_active"]}
            return False, f"Rule with ID {rule_id} not found."

    # -------------------------------------------------------------
    # Packet Processing & Simulation Engine
    # -------------------------------------------------------------
    def simulate_packet(self, src_ip, dst_ip, protocol, dst_port):
        """
        Executes SDN Controller logic on an incoming simulated packet:
        1. Validates packet headers.
        2. Inspects flow rules in descending order of priority (Explicit DROP before Default ALLOW).
        3. Makes a deterministic ALLOW / BLOCKED decision.
        4. Computes switch routing via BFS if ALLOWED.
        5. Updates controller telemetry and appends to event log.
        """
        with self.lock:
            # Normalize and validate inputs
            src_ip = src_ip.strip()
            dst_ip = dst_ip.strip()
            protocol = protocol.strip().upper()
            dst_port = int(dst_port)

            self.stats["total_packets"] += 1

            # Determine ingress switch and destination switch from topology
            src_host = self.hosts.get(src_ip)
            dst_host = self.hosts.get(dst_ip)

            ingress_switch = src_host["switch"] if src_host else "S1"
            egress_switch = dst_host["switch"] if dst_host else None

            # Sort rules by priority descending (DROP rules are 100, DEFAULT rule is 1)
            sorted_rules = sorted(self.rules, key=lambda r: r["priority"], reverse=True)

            matching_rule = None
            action = None

            for rule in sorted_rules:
                if not rule["is_active"]:
                    continue

                m = rule["match"]

                # Match Source IP
                src_match = (m["src_ip"] == "*" or m["src_ip"] == src_ip)
                # Match Destination IP
                dst_match = (m["dst_ip"] == "*" or m["dst_ip"] == dst_ip)
                # Match Protocol
                proto_match = (m["protocol"] == "*" or m["protocol"] == protocol)
                # Match Port
                port_match = (m["dst_port"] == "*" or str(m["dst_port"]) == str(dst_port))

                if src_match and dst_match and proto_match and port_match:
                    matching_rule = rule
                    action = rule["action"]
                    break

            # Handle BLOCKED / DROP
            if action == "DROP":
                self.stats["blocked_packets"] += 1
                decision = "BLOCKED"
                reason = f"Access Control Policy Violation: Block rule [{matching_rule['id']}] matched Source IP {src_ip}. Packet dropped at ingress {ingress_switch}."
                # Clearly indicate packet was dropped at ingress switch; no destination forwarding
                path = [f"{src_host['id']} ({src_ip})" if src_host else src_ip, ingress_switch, "DROPPED (Access Denied)"]
                hop_details = {
                    "path_nodes": [src_host["id"] if src_host else "H?", ingress_switch],
                    "status": "DROPPED",
                    "drop_point": ingress_switch
                }

                result = {
                    "decision": decision,
                    "action": "DROP",
                    "matching_rule": {
                        "id": matching_rule["id"],
                        "priority": matching_rule["priority"],
                        "match_display": matching_rule["match_display"],
                        "description": matching_rule["description"]
                    },
                    "reason": reason,
                    "path": path,
                    "hop_details": hop_details,
                    "packet": {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol,
                        "dst_port": dst_port,
                        "src_host": src_host["id"] if src_host else "External",
                        "dst_host": dst_host["id"] if dst_host else "External"
                    }
                }
                self._log_event(
                    event_type="PACKET_SIMULATION",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    port=str(dst_port),
                    decision=decision,
                    reason=reason,
                    path=path
                )
                return result

            # If action is FORWARD (Default allow rule)
            if not dst_host:
                # Destination host not in topology
                self.stats["blocked_packets"] += 1
                decision = "BLOCKED"
                reason = f"Routing Error: Destination IP {dst_ip} is unreachable (Host not mapped to any switch)."
                path = [f"{src_host['id']} ({src_ip})" if src_host else src_ip, ingress_switch, "DESTINATION UNREACHABLE"]
                hop_details = {
                    "path_nodes": [src_host["id"] if src_host else "H?", ingress_switch],
                    "status": "UNREACHABLE",
                    "drop_point": ingress_switch
                }
                result = {
                    "decision": decision,
                    "action": "DROP",
                    "matching_rule": {
                        "id": matching_rule["id"] if matching_rule else "UNKNOWN",
                        "priority": matching_rule["priority"] if matching_rule else 0,
                        "match_display": "Unreachable Destination",
                        "description": "Network destination not found in SDN topology"
                    },
                    "reason": reason,
                    "path": path,
                    "hop_details": hop_details,
                    "packet": {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol,
                        "dst_port": dst_port,
                        "src_host": src_host["id"] if src_host else "External",
                        "dst_host": "Unknown"
                    }
                }
                self._log_event(
                    event_type="PACKET_SIMULATION",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    port=str(dst_port),
                    decision=decision,
                    reason=reason,
                    path=path
                )
                return result

            # Check if source host is in topology
            if not src_host:
                self.stats["blocked_packets"] += 1
                decision = "BLOCKED"
                reason = f"Routing Error: Source IP {src_ip} is not mapped to any known simulated host in the topology."
                path = [src_ip, "UNKNOWN SOURCE"]
                hop_details = {
                    "path_nodes": ["Unknown"],
                    "status": "UNREACHABLE",
                    "drop_point": "Ingress"
                }
                result = {
                    "decision": decision,
                    "action": "DROP",
                    "matching_rule": {
                        "id": "NONE",
                        "priority": 0,
                        "match_display": "Invalid Source",
                        "description": "Source not in simulated topology"
                    },
                    "reason": reason,
                    "path": path,
                    "hop_details": hop_details,
                    "packet": {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol,
                        "dst_port": dst_port,
                        "src_host": "Unknown",
                        "dst_host": dst_host["id"]
                    }
                }
                self._log_event(
                    event_type="PACKET_SIMULATION",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    port=str(dst_port),
                    decision=decision,
                    reason=reason,
                    path=path
                )
                return result

            # Compute route using BFS
            switch_route = self.compute_route(ingress_switch, egress_switch)

            if not switch_route:
                # No path available in topology
                self.stats["blocked_packets"] += 1
                decision = "BLOCKED"
                reason = f"Routing Failure: No viable link path between {ingress_switch} and {egress_switch}."
                path = [f"{src_host['id']} ({src_ip})", ingress_switch, "NO ROUTE"]
                hop_details = {
                    "path_nodes": [src_host["id"], ingress_switch],
                    "status": "NO_ROUTE",
                    "drop_point": ingress_switch
                }
                result = {
                    "decision": decision,
                    "action": "DROP",
                    "matching_rule": {
                        "id": matching_rule["id"] if matching_rule else "NONE",
                        "priority": 1,
                        "match_display": "No Link Path",
                        "description": "Partitioned topology"
                    },
                    "reason": reason,
                    "path": path,
                    "hop_details": hop_details,
                    "packet": {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol,
                        "dst_port": dst_port,
                        "src_host": src_host["id"],
                        "dst_host": dst_host["id"]
                    }
                }
                self._log_event(
                    event_type="PACKET_SIMULATION",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    port=str(dst_port),
                    decision=decision,
                    reason=reason,
                    path=path
                )
                return result

            # Successfully ALLOWED & FORWARDED!
            self.stats["allowed_packets"] += 1
            decision = "ALLOWED"

            # Construct full end-to-end hop sequence
            full_path_nodes = [src_host["id"]] + switch_route + [dst_host["id"]]
            path_display = [f"{src_host['id']} ({src_ip})"] + switch_route + [f"{dst_host['id']} ({dst_ip})"]

            hop_details = {
                "path_nodes": full_path_nodes,
                "switches": switch_route,
                "status": "FORWARDED",
                "hop_count": len(full_path_nodes) - 1
            }

            reason = f"Traffic permitted by SDN controller forwarding policy [{matching_rule['id']}]. BFS shortest route selected."

            result = {
                "decision": decision,
                "action": "FORWARD",
                "matching_rule": {
                    "id": matching_rule["id"],
                    "priority": matching_rule["priority"],
                    "match_display": matching_rule["match_display"],
                    "description": matching_rule["description"]
                },
                "reason": reason,
                "path": path_display,
                "hop_details": hop_details,
                "packet": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "dst_port": dst_port,
                    "src_host": src_host["id"],
                    "dst_host": dst_host["id"]
                }
            }

            self._log_event(
                event_type="PACKET_SIMULATION",
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                port=str(dst_port),
                decision=decision,
                reason=reason,
                path=path_display
            )
            return result

    # -------------------------------------------------------------
    # Logging & Statistics
    # -------------------------------------------------------------
    def _log_event(self, event_type, src_ip, dst_ip, protocol, port, decision, reason, path):
        """Appends an event to the internal audit log."""
        log_entry = {
            "id": len(self.event_logs) + 1,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": event_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "port": str(port),
            "decision": decision,
            "reason": reason,
            "path": " → ".join(path) if path else "-"
        }
        # Prepend to display newest first
        self.event_logs.insert(0, log_entry)

    def get_logs(self):
        """Returns the complete event log."""
        with self.lock:
            return list(self.event_logs)

    def clear_logs(self):
        """Clears all event logs."""
        with self.lock:
            self.event_logs.clear()
            return True

    def get_stats(self):
        """Returns overview dashboard statistics."""
        with self.lock:
            active_rules_count = sum(1 for r in self.rules if r["is_active"] and not r.get("is_default"))
            return {
                "switches_count": len(self.switches),
                "hosts_count": len(self.hosts),
                "total_packets": self.stats["total_packets"],
                "allowed_packets": self.stats["allowed_packets"],
                "blocked_packets": self.stats["blocked_packets"],
                "active_rules_count": active_rules_count,
                "total_rules_count": len(self.rules)
            }


# Singleton SDN controller instance
controller = SDNController()
