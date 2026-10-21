# Software-Defined Networking (SDN) for Intelligent Traffic Management & Access Control

A complete, beginner-friendly working prototype built for the **TY BTech Computer Engineering Computer Networks** presentation.

> **Project Topic:** *Software-Defined Networking (SDN) for Intelligent Traffic Management*  
> **Academic Context:** College demonstration prototype showing SDN centralized control plane logic, OpenFlow-inspired flow rule processing, deterministic BFS packet routing, and dynamic IP-based Access Control (ACL).

---

## 1. Project Overview & Architecture

In traditional networks, routing and access control decisions are distributed across individual hardware switches. In **Software-Defined Networking (SDN)**, the control plane is decoupled from the data plane and centralized in a software controller.

This prototype demonstrates:
- **Centralized SDN Controller:** Manages network state, installs flow rules, and computes routes.
- **Simulated 3-Switch Data Plane:** Switches **S1** (Edge A), **S2** (Core Transit), and **S3** (Edge B) interconnected in a mesh topology with 5 simulated hosts (`10.0.0.1` to `10.0.0.5`).
- **Deterministic BFS Routing:** Shortest hop path computation across switches for allowed traffic.
- **Priority-Based Flow Engine:** High-priority (100) explicit `DROP` rules override the default fallback (1) `FORWARD` rule.
- **Dynamic Access Control:** Add, toggle (enable/disable), and delete blocking rules in real time without restarting switches.
- **Audit Logging & Telemetry:** Real-time metrics and event history with confirmation safeguards.

---

## 2. Required Software

- **Operating System:** Windows 10 or 11
- **Python:** Python 3.10 or newer (tested on Python 3.13)
- **Editor:** Visual Studio Code (VS Code)
- **Web Browser:** Google Chrome, Microsoft Edge, or Mozilla Firefox

---

## 3. Step-by-Step Setup Guide (Windows PowerShell)

Follow these exact commands in **Windows PowerShell**:

### Step 1: Open the Project in VS Code
1. Open VS Code.
2. Select **File > Open Folder...** and select:
   ```
   e:\sadap\Documents\OneDrive\OfficeMobile\Desktop\CN prototype
   ```
3. Open a new terminal inside VS Code: press ``Ctrl + ` `` (Backtick) or go to **Terminal > New Terminal**. Ensure the terminal profile is **PowerShell**.

### Step 2: Create a Python Virtual Environment
Run the following command to create a virtual environment named `.venv`:
```powershell
python -m venv .venv
```

### Step 3: Activate the Virtual Environment
Activate the virtual environment:
```powershell
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell displays an `Execution_Policies` script restriction warning, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` once in your terminal session, then run the activation command again).*

Your terminal prompt will now show `(.venv)` at the beginning of the line.

### Step 4: Install Dependencies
Install the required lightweight Flask framework:
```powershell
pip install -r requirements.txt
```

### Step 5: Start the SDN Application
Start the local Flask development server:
```powershell
python app.py
```

### Step 6: Open the Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 4. Live Presentation Demo Script (8–10 Minutes)

Here is a recommended script to follow during your viva or presentation:

### Phase 1: Introduction to SDN Architecture (1–2 mins)
- Point to the **Top Header**: *"Our project decouples the control plane from the data plane. The dashboard connects to a centralized SDN Controller running on 127.0.0.1."*
- Point to the **Overview Metrics**: Show the 3 simulated switches, 5 connected hosts, total packets, and active ACL rules.
- Point to the **Network Topology (SVG)**:
  - Explain the 3 switches: **S1** (Edge A), **S2** (Core Transit), and **S3** (Edge B).
  - Point out the connected hosts: H1 (`10.0.0.1`) and H2 (`10.0.0.2`) on S1; H3 (`10.0.0.3`) on S2; H4 (`10.0.0.4`) and H5 (`10.0.0.5`) on S3.

### Phase 2: Default Forwarding & Shortest Path Routing (2–3 mins)
1. In the **Simulate Packet Transmission** card, click the demo preset **"H1 → H4 (TCP:80)"** (or enter Source: `10.0.0.1`, Destination: `10.0.0.4`, Protocol: `TCP`, Port: `80`).
2. Click **"Send Packet to SDN Controller"**.
3. **Observations to explain:**
   - Decision shows **ALLOWED** (Green badge).
   - Reason explains that the default rule `FLOW-DEF-001` (Priority 1) matched.
   - The controller computed the shortest path using **Breadth-First Search (BFS)**: `H1 (10.0.0.1) → S1 → S3 → H4 (10.0.0.4)`.
   - Point to the SVG canvas: Notice the glowing green transit line and moving packet particle showing the route.
   - Point to the **Traffic Activity Log**: An audit entry was generated with timestamps and hop sequence.

### Phase 3: IP Access Control & Explicit Blocking (2–3 mins)
1. Go to the **IP-Based Access Control** section.
2. In **Block Source IP**, enter `10.0.0.5` and description: *"Rogue host blacklisted"*.
3. Click **"Install Block Rule"**.
4. **Observations to explain:**
   - A new rule (e.g. `ACL-XXXXXXXX`) appears under **Installed Security Policies** with Priority 100 and Action `DROP`.
   - In the **SDN Controller Flow-Rule Table**, point out that Priority 100 sits at the top above the fallback Priority 1 rule.
5. In the **Packet Simulator**, click preset **"H5 → H2 (Target Block)"** (Source: `10.0.0.5`, Destination: `10.0.0.2`, Port `80`).
6. Click **"Send Packet to SDN Controller"**.
7. **Observations to explain:**
   - Decision immediately changes to **BLOCKED** (Red badge).
   - Reason states: *"Access Control Policy Violation: Block rule matched Source IP 10.0.0.5. Packet dropped at ingress switch S3."*
   - Point to the SVG topology: The ingress switch S3 glows red, and the path shows `DROPPED (Access Denied)`. The packet is **never forwarded** to S1 or H2!

### Phase 4: Dynamic Rule Modification & Rule Removal (1–2 mins)
1. Under **Installed Security Policies**, flip the **toggle switch** for `10.0.0.5` to **Disabled**.
2. Click **"Send Packet to SDN Controller"** with the same packet (`10.0.0.5` to `10.0.0.2`).
3. **Observation:** The packet is now **ALLOWED** because the block rule is disabled!
4. Click the delete button (`✕`) on the rule. It is permanently removed, and the flow table updates instantaneously.
5. Click **"Clear Activity Log"** to demonstrate log clearing with modal confirmation.

---

## 5. Troubleshooting Common Issues

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | Windows PowerShell execution policy restriction | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in PowerShell, then re-run `.\.venv\Scripts\Activate.ps1`. |
| `Address already in use (Port 5000)` | Another process is bound to port 5000 | In PowerShell run `Get-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess \| Stop-Process -Force` or edit `app.py` to change port to `5001`. |
| `ModuleNotFoundError: No module named 'flask'` | Virtual environment not active or dependencies not installed | Ensure `(.venv)` is visible in your prompt and re-run `pip install -r requirements.txt`. |
| Browser shows *Refused to connect* | Flask application is not running | Verify `python app.py` is actively executing in your terminal. |

---

## 6. Project Files Summary

- `app.py`: Flask application providing REST APIs, strict IP address validation (`ipaddress` library), and web serving bound to `127.0.0.1:5000`.
- `sdn_controller.py`: Core SDN Control Plane logic, topology graph, hosts registry, flow-rule priority table, BFS shortest path algorithm, and packet evaluation engine.
- `templates/index.html`: Modern semantic dashboard layout with SVG topology visualization, packet simulator form, rule management interface, flow table, and event log.
- `static/style.css`: Cyber/networking dark theme, glowing SVG nodes and animated transit paths, responsive layout, and status indicators.
- `static/script.js`: Client-side logic for real-time API communication, SVG animation, quick presets, rule toggling, and audit log rendering.
- `requirements.txt`: Minimal dependencies (`Flask`).
- `README.md`: Setup instructions, live presentation script, and troubleshooting.

---

## 7. Educational Disclaimer & Limitations

- **Simulated Environment:** This prototype is designed specifically for college academic demonstrations to explain SDN control plane logic, OpenFlow flow-table matching, and algorithmic path selection. It does not interface with physical hardware switches or Mininet OpenFlow daemons.
- **In-Memory Storage:** Flow rules and activity logs are stored in controller memory during execution and reset when the server restarts.
#   C N - S D N - P r o j e c t  
 #   C N - S D N - P r o j e c t  
 