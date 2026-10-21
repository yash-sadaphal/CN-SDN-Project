"""
Automated Test Suite for SDN Prototype Backend and API Routes.
Verifies all controller logic, access control rules, packet forwarding,
error handling, and logging.
"""

import json
import unittest
from app import app
from sdn_controller import controller


class TestSDNPrototype(unittest.TestCase):
    def setUp(self):
        # Create Flask test client
        self.client = app.test_client()
        # Reset controller state for consistent test baseline
        controller.rules = [
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
                "created_at": "2026-10-19 00:00:00"
            }
        ]
        controller.event_logs = []
        controller.stats = {
            "total_packets": 0,
            "allowed_packets": 0,
            "blocked_packets": 0,
        }

    def test_01_stats_endpoint(self):
        """Test GET /api/stats initial state."""
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["switches_count"], 3)
        self.assertEqual(data["hosts_count"], 5)
        self.assertEqual(data["total_packets"], 0)
        self.assertEqual(data["allowed_packets"], 0)
        self.assertEqual(data["blocked_packets"], 0)
        self.assertEqual(data["active_rules_count"], 0)

    def test_02_topology_endpoint(self):
        """Test GET /api/topology returns switches, links, and hosts."""
        response = self.client.get("/api/topology")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("S1", data["switches"])
        self.assertIn("S2", data["switches"])
        self.assertIn("S3", data["switches"])
        self.assertIn("10.0.0.1", data["hosts"])
        self.assertIn("10.0.0.5", data["hosts"])
        self.assertGreaterEqual(len(data["switch_links"]), 3)

    def test_03_packet_allowed_default(self):
        """Test that with no block rule, packet from 10.0.0.5 to 10.0.0.2 is ALLOWED."""
        payload = {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "dst_port": 80
        }
        response = self.client.post("/api/simulate-packet", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["decision"], "ALLOWED")
        self.assertEqual(data["action"], "FORWARD")
        self.assertEqual(data["matching_rule"]["id"], "FLOW-DEF-001")
        self.assertIn("H5 (10.0.0.5)", data["path"][0])
        self.assertIn("H2 (10.0.0.2)", data["path"][-1])

        # Verify stats updated
        stats_resp = self.client.get("/api/stats")
        stats = stats_resp.get_json()
        self.assertEqual(stats["total_packets"], 1)
        self.assertEqual(stats["allowed_packets"], 1)
        self.assertEqual(stats["blocked_packets"], 0)

    def test_04_add_blocking_rule_and_block_traffic(self):
        """Test adding block rule for 10.0.0.5, then verifying packet is BLOCKED."""
        # 1. Add rule
        rule_payload = {
            "src_ip": "10.0.0.5",
            "description": "Block untrusted host H5"
        }
        res_rule = self.client.post("/api/rules", json=rule_payload)
        self.assertEqual(res_rule.status_code, 201)
        rule_data = res_rule.get_json()["rule"]
        rule_id = rule_data["id"]
        self.assertEqual(rule_data["match"]["src_ip"], "10.0.0.5")
        self.assertEqual(rule_data["action"], "DROP")

        # 2. Simulate packet from 10.0.0.5 to 10.0.0.2
        packet_payload = {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "dst_port": 80
        }
        res_packet = self.client.post("/api/simulate-packet", json=packet_payload)
        self.assertEqual(res_packet.status_code, 200)
        pkt_data = res_packet.get_json()
        self.assertEqual(pkt_data["decision"], "BLOCKED")
        self.assertEqual(pkt_data["action"], "DROP")
        self.assertEqual(pkt_data["matching_rule"]["id"], rule_id)
        # Blocked packets must not be reported as forwarded
        self.assertIn("DROPPED", pkt_data["path"][-1])
        self.assertEqual(pkt_data["hop_details"]["status"], "DROPPED")

        # Verify stats updated
        stats = self.client.get("/api/stats").get_json()
        self.assertEqual(stats["total_packets"], 1)
        self.assertEqual(stats["blocked_packets"], 1)
        self.assertEqual(stats["allowed_packets"], 0)

    def test_05_toggle_and_remove_rule(self):
        """Test disabling a rule allows traffic, and removing a rule restores default."""
        # Add rule
        res_rule = self.client.post("/api/rules", json={"src_ip": "10.0.0.5", "description": "Block H5"})
        rule_id = res_rule.get_json()["rule"]["id"]

        packet_payload = {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "dst_port": 80
        }

        # Verify it's blocked first
        res = self.client.post("/api/simulate-packet", json=packet_payload)
        self.assertEqual(res.get_json()["decision"], "BLOCKED")

        # Toggle rule to DISABLED
        toggle_res = self.client.patch(f"/api/rules/{rule_id}/toggle")
        self.assertEqual(toggle_res.status_code, 200)
        self.assertFalse(toggle_res.get_json()["rule"]["is_active"])

        # Packet should now be ALLOWED
        res_after_toggle = self.client.post("/api/simulate-packet", json=packet_payload)
        self.assertEqual(res_after_toggle.get_json()["decision"], "ALLOWED")

        # Remove the rule
        del_res = self.client.delete(f"/api/rules/{rule_id}")
        self.assertEqual(del_res.status_code, 200)

        # Packet should still be ALLOWED
        res_after_del = self.client.post("/api/simulate-packet", json=packet_payload)
        self.assertEqual(res_after_del.get_json()["decision"], "ALLOWED")

    def test_06_input_validation(self):
        """Test invalid IPs, ports, and protocols are properly rejected."""
        # Invalid Source IP
        res = self.client.post("/api/simulate-packet", json={
            "src_ip": "999.999.999.999",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "dst_port": 80
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("Invalid Source IP", res.get_json()["error"])

        # Invalid Destination IP
        res = self.client.post("/api/simulate-packet", json={
            "src_ip": "10.0.0.1",
            "dst_ip": "not_an_ip",
            "protocol": "TCP",
            "dst_port": 80
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("Invalid Destination IP", res.get_json()["error"])

        # Invalid Protocol
        res = self.client.post("/api/simulate-packet", json={
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "ICMP",
            "dst_port": 80
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("Allowed protocols are 'TCP' or 'UDP'", res.get_json()["error"])

        # Invalid Port (> 65535)
        res = self.client.post("/api/simulate-packet", json={
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "dst_port": 70000
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("Port must be an integer between 1 and 65535", res.get_json()["error"])

        # Invalid Port (negative)
        res = self.client.post("/api/simulate-packet", json={
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "dst_port": -5
        })
        self.assertEqual(res.status_code, 400)

        # Invalid Rule Add IP
        res = self.client.post("/api/rules", json={"src_ip": "invalid-ip"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Invalid IP address", res.get_json()["error"])

    def test_07_routing_and_unreachable_hosts(self):
        """Test destination host not in topology returns BLOCKED / unreachable."""
        res = self.client.post("/api/simulate-packet", json={
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.100",  # Valid IP, but not in simulated topology
            "protocol": "TCP",
            "dst_port": 80
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["decision"], "BLOCKED")
        self.assertIn("unreachable", data["reason"].lower())

    def test_08_event_logging_and_clear(self):
        """Test logs are recorded and can be cleared."""
        # Simulate a packet to generate log
        self.client.post("/api/simulate-packet", json={
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.4",
            "protocol": "TCP",
            "dst_port": 443
        })
        logs_resp = self.client.get("/api/logs")
        self.assertEqual(logs_resp.status_code, 200)
        logs = logs_resp.get_json()
        self.assertGreaterEqual(len(logs), 1)
        self.assertEqual(logs[0]["src_ip"], "10.0.0.1")
        self.assertEqual(logs[0]["dst_ip"], "10.0.0.4")
        self.assertEqual(logs[0]["decision"], "ALLOWED")

        # Clear logs
        del_logs = self.client.delete("/api/logs")
        self.assertEqual(del_logs.status_code, 200)
        cleared_logs = self.client.get("/api/logs").get_json()
        self.assertEqual(len(cleared_logs), 0)


if __name__ == "__main__":
    unittest.main()
