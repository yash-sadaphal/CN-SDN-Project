"""
Flask Application for SDN-Based Intelligent Traffic Management and Access Control.
Provides REST API endpoints and serves the modern interactive dashboard.
Binds strictly to 127.0.0.1:5000.
"""

import ipaddress
from flask import Flask, jsonify, render_template, request
from sdn_controller import controller

app = Flask(__name__)


# ---------------------------------------------------------------------------
# UI View Route
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Serves the main SDN Management & Simulation Dashboard."""
    return render_template("index.html")


# ---------------------------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Retrieves real-time SDN overview statistics."""
    return jsonify(controller.get_stats()), 200


@app.route("/api/topology", methods=["GET"])
def get_topology():
    """Retrieves the simulated SDN topology (switches, links, and hosts)."""
    return jsonify(controller.get_topology()), 200


@app.route("/api/rules", methods=["GET"])
def get_rules():
    """Retrieves all active and default flow rules."""
    return jsonify(controller.get_rules()), 200


@app.route("/api/rules", methods=["POST"])
def add_rule():
    """
    Adds a new access control block rule for a source IP.
    Validates the IP address using Python's ipaddress library.
    """
    data = request.get_json() or {}
    src_ip = data.get("src_ip", "").strip()
    description = data.get("description", "").strip()

    if not src_ip:
        return jsonify({"error": "Source IP address is required."}), 400

    # Validate IP address syntax strictly
    try:
        ipaddress.ip_address(src_ip)
    except ValueError:
        return jsonify({
            "error": f"Invalid IP address format: '{src_ip}'. Please provide a valid IPv4 address (e.g., 10.0.0.5)."
        }), 400

    success, result = controller.add_block_rule(src_ip, description)
    if not success:
        return jsonify({"error": result}), 400

    return jsonify({
        "message": "Block rule added successfully.",
        "rule": result
    }), 201


@app.route("/api/rules/<rule_id>/toggle", methods=["PATCH"])
def toggle_rule(rule_id):
    """Enables or disables an access control rule."""
    success, result = controller.toggle_rule(rule_id)
    if not success:
        return jsonify({"error": result}), 400

    return jsonify({
        "message": f"Rule {rule_id} status updated.",
        "rule": result
    }), 200


@app.route("/api/rules/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    """Deletes an access control rule."""
    success, result = controller.remove_rule(rule_id)
    if not success:
        return jsonify({"error": result}), 400

    return jsonify({"message": result}), 200


@app.route("/api/simulate-packet", methods=["POST"])
def simulate_packet():
    """
    Processes a simulated packet through the SDN Controller:
    Validates input headers, applies flow rules, determines ALLOW/BLOCK,
    computes BFS switch forwarding if allowed, and updates metrics.
    """
    data = request.get_json() or {}
    src_ip = data.get("src_ip", "").strip()
    dst_ip = data.get("dst_ip", "").strip()
    protocol = data.get("protocol", "").strip().upper()
    dst_port_raw = data.get("dst_port")

    # 1. Validate required fields
    if not src_ip or not dst_ip or not protocol or dst_port_raw is None:
        return jsonify({
            "error": "Missing required fields: src_ip, dst_ip, protocol, and dst_port are required."
        }), 400

    # 2. Validate Source IP
    try:
        ipaddress.ip_address(src_ip)
    except ValueError:
        return jsonify({
            "error": f"Invalid Source IP address: '{src_ip}'. Please provide a valid IPv4 address."
        }), 400

    # 3. Validate Destination IP
    try:
        ipaddress.ip_address(dst_ip)
    except ValueError:
        return jsonify({
            "error": f"Invalid Destination IP address: '{dst_ip}'. Please provide a valid IPv4 address."
        }), 400

    # 4. Validate Protocol
    if protocol not in ["TCP", "UDP"]:
        return jsonify({
            "error": f"Invalid protocol: '{protocol}'. Allowed protocols are 'TCP' or 'UDP'."
        }), 400

    # 5. Validate Port number
    try:
        dst_port = int(dst_port_raw)
        if dst_port < 1 or dst_port > 65535:
            return jsonify({
                "error": f"Invalid port number: {dst_port}. Port must be an integer between 1 and 65535."
            }), 400
    except (ValueError, TypeError):
        return jsonify({
            "error": f"Invalid port format: '{dst_port_raw}'. Must be an integer between 1 and 65535."
        }), 400

    # Execute simulation in the controller
    result = controller.simulate_packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        dst_port=dst_port
    )

    return jsonify(result), 200


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """Retrieves all packet decisions and flow-rule events."""
    return jsonify(controller.get_logs()), 200


@app.route("/api/logs", methods=["DELETE"])
def clear_logs():
    """Clears all audit and packet event logs."""
    controller.clear_logs()
    return jsonify({"message": "Event logs cleared successfully."}), 200


# ---------------------------------------------------------------------------
# Server Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Security requirement: bind explicitly to 127.0.0.1, never 0.0.0.0
    print("Starting SDN Controller Prototype on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False)
