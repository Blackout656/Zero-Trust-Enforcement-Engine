import time
import datetime
import sys

# ==========================================================
# 1. TELEMETRY INGESTION LAYER
# ==========================================================
class AccessRequest:
    def __init__(self, username, device_id, location, request_type):
        self.username = username
        self.device_id = device_id
        self.location = location
        self.request_type = request_type  
        self.timestamp = datetime.datetime.now()


# ==========================================================
# 2. CORE POLICY AND RISK ASSESSMENT ENGINE
# ==========================================================
class ZeroTrustPolicyEngine:
    def __init__(self):
        self.user_trust_scores = {}
        self.blacklisted_devices = set()
        
    def get_trust_score(self, username):
        if username not in self.user_trust_scores:
            self.user_trust_scores[username] = 100.0
        return self.user_trust_scores[username]

    def log_security_action(self, username, status, message):
        score = self.get_trust_score(username)
        print(f"\n[SECURITY METRIC] TRUST SCORE: {score:.1f} | ACCOUNT: {username} | STATUS: {status}")
        print(f"[*] POLICY EVALUATION: {message}")

    def evaluate_access_risk(self, request: AccessRequest, last_known_location=None, last_request_time=None):
        username = request.username
        current_score = self.get_trust_score(username)
        
        # Check if hardware MAC is blacklisted
        if request.device_id in self.blacklisted_devices:
            self.user_trust_scores[username] = 0.0
            self.log_security_action(username, "REJECTED_BLOCKED", f"Hardware MAC [{request.device_id}] is permanently banned.")
            return "ACCESS_DENIED"

        penalties = 0.0
        evaluation_notes = []

        # 1. Impossible Travel Velocity Check
        if last_known_location and last_request_time:
            if last_known_location != request.location:
                time_delta = (request.timestamp - last_request_time).total_seconds() / 60.0
                if time_delta < 60.0:
                    penalties += 45.0
                    evaluation_notes.append(f"Anomalous Location Shift to {request.location} detected in {time_delta:.1f} mins.")

        # 2. Hostile Operation Check
        if request.request_type == "DB_DESTRUCTION_ATTEMPT":
            penalties += 80.0
            evaluation_notes.append("CRITICAL: Destructive database signature intercepted!")
        elif request.request_type == "SUDO_EXEC":
            penalties += 10.0
            evaluation_notes.append("Administrative credentials applied.")

        # Recalculate score matrix
        self.user_trust_scores[username] = max(0.0, current_score - penalties)
        new_score = self.user_trust_scores[username]

        if penalties > 0:
            self.log_security_action(username, "WARNING_LEVEL_RAISED", " | ".join(evaluation_notes))
        else:
            self.log_security_action(username, "VERIFIED_CLEAN", "Parameters conform to standard trust baseline profiles.")

        if new_score >= 70.0:
            return "FULL_ACCESS"
        elif new_score >= 40.0:
            return "RESTRICTED_SANDBOX"
        else:
            return "ACCESS_DENIED"


# ==========================================================
# 3. LIVE COMPLIANCE & AUDIT REPORT GENERATOR
# ==========================================================
def generate_audit_dashboard(engine, parsed_scenarios):
    """
    Takes live input history from your console sessions and writes 
    them instantly into a beautiful visual dashboard interface.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    blacklist_rows = ""
    if not engine.blacklisted_devices:
        blacklist_rows = "<tr><td colspan='2' style='color:#8b949e; text-align:center;'>No hardware endpoints currently quarantined.</td></tr>"
    else:
        for device in engine.blacklisted_devices:
            blacklist_rows += f"""
            <tr style='background-color: #2c1a1d;'>
                <td><code style='color:#ff7b72;'>DROP / BANNED</code></td>
                <td><strong>{device}</strong> (Automated MAC Layer Block)</td>
            </tr>"""

    traffic_rows = ""
    for item in parsed_scenarios:
        status_color = "#56d364" if item["decision"] == "FULL_ACCESS" else "#f0883e" if item["decision"] == "RESTRICTED_SANDBOX" else "#ff7b72"
        traffic_rows += f"""
        <tr>
            <td><code>{item['user']}</code></td>
            <td>{item['loc']}</td>
            <td>{item['type']}</td>
            <td style='color: {status_color}; font-weight: bold;'>{item['decision']}</td>
        </tr>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Zero-Trust Identity & Access Governance Console</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background-color: #0d1117; color: #c9d1d9; margin: 40px; }}
        h1 {{ color: #58a6ff; border-bottom: 1px solid #21262d; padding-bottom: 10px; }}
        .grid {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .card {{ background-color: #161b22; padding: 20px; border-radius: 6px; border: 1px solid #30363d; flex: 1; }}
        .card h3 {{ margin: 0 0 10px 0; color: #8b949e; font-size: 13px; text-transform: uppercase; }}
        .card div {{ font-size: 28px; font-weight: bold; color: #58a6ff; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; background-color: #161b22; border-radius: 6px; overflow: hidden; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #30363d; }}
        th {{ background-color: #21262d; color: #58a6ff; }}
        code {{ background-color: #21262d; padding: 3px 6px; border-radius: 4px; color: #f0883e; font-family: monospace; }}
    </style>
</head>
<body>

    <h1>🛡️ Zero-Trust Access Governance & Enforcement Console</h1>
    <p>Perimeter Enforcement State Grid Updated: {timestamp}</p>

    <div class="grid">
        <div class="card" style="border-left: 4px solid #58a6ff;">
            <h3>Policy Enforcement Status</h3>
            <div style="color: #56d364;">ACTIVE / LIVE_LAB_MODE</div>
        </div>
        <div class="card" style="border-left: 4px solid #ff7b72;">
            <h3>Active Hardware Blocks</h3>
            <div style="color: #ff7b72;">{len(engine.blacklisted_devices)}</div>
        </div>
    </div>

    <h2>🚫 Active Edge Firewall Blocks (IPTABLES Rules)</h2>
    <table>
        <thead>
            <tr><th>Enforcement Action</th><th>Target Identification Parameter</th></tr>
        </thead>
        <tbody>
            {blacklist_rows}
        </tbody>
    </table>

    <h2>📊 Live Identity Verification Feed</h2>
    <table>
        <thead>
            <tr><th>Subject User</th><th>Context Location</th><th>Resource Requested</th><th>Decision Guard State</th></tr>
        </thead>
        <tbody>
            {traffic_rows}
        </tbody>
    </table>

</body>
</html>
"""
    with open("audit_log.html", "w", encoding="utf-8") as f:
        f.write(html_content)


# ==========================================================
# 4. INTERACTIVE RUNTIME ENVIRONMENT
# ==========================================================
if __name__ == "__main__":
    active_guard = ZeroTrustPolicyEngine()
    
    # State tracking history arrays
    audit_trail = []
    last_loc = None
    last_time = None

    print("=" * 65)
    print("🛡️ LIVE INTERACTIVE ZERO-TRUST POLICY ENFORCEMENT LAB")
    print("=" * 65)
    print("[+] Engine initialized. Dashboard compiled at -> audit_log.html\n")

    # Generate an initial empty dashboard file on launch
    generate_audit_dashboard(active_guard, audit_trail)

    while True:
        print("-----------------------------------------------------------------")
        print(" CHOOSE TRAFFIC PROFILE TYPE:")
        print("  [1] Normal Authentication Attempt (SSH)")
        print("  [2] Malicious Database Attack Vector")
        print("  [3] Shutdown Lab Environment")
        print("-----------------------------------------------------------------")
        
        choice = input("Select an option (1, 2, or 3) -> ").strip()

        if choice == "3":
            print("\n[+] Tearing down laboratory environment. Goodbye.")
            sys.exit(0)
            
        if choice not in ["1", "2"]:
            print("\n[-] Invalid selection! Please enter 1, 2, or 3.")
            continue

        print("\n[!] Enter packet context variables below:")
        user = input(" -> Input Username: ").strip()
        mac  = input(" -> Input Device MAC Address: ").strip()
        loc  = input(" -> Input Connection Location Country: ").strip()
        
        req_type = "SSH_AUTH" if choice == "1" else "DB_DESTRUCTION_ATTEMPT"

        # Construct live data object
        request = AccessRequest(username=user, device_id=mac, location=loc, request_type=req_type)

        # Process calculations
        decision = active_guard.evaluate_access_risk(request, last_known_location=last_loc, last_request_time=last_time)

        if decision == "ACCESS_DENIED":
            active_guard.blacklisted_devices.add(mac)
            print(f"    [FIREWALL COMMAND INJECTED]: iptables -A INPUT -m mac --mac-source {mac} -j DROP")

        # Save metadata history
        audit_trail.append({"user": user, "loc": loc, "type": req_type, "decision": decision})
        last_loc = loc
        last_time = request.timestamp

        # INSTANT AUTOMATION FLUSH TO WEB FILE
        generate_audit_dashboard(active_guard, audit_trail)
        print("\n[+] Dashboard Updated Live! Refresh audit_log.html to view shifts.")
        print("\n\n")