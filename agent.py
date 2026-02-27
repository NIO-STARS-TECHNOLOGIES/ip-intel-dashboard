#!/usr/bin/env python3
"""
IP-Intel Remote Agent
Runs nmap locally, parses results, and sends findings to the C2 server.

Requirements:
    pip install requests
    nmap must be installed and on PATH

Usage:
    python agent.py --server http://<server-ip>:5002 --key <api-key> --target 192.168.1.1
    python agent.py --server http://<server-ip>:5002 --key <api-key> --target 10.0.0.1,10.0.0.2 --mode full
"""

import subprocess
import re
import json
import argparse
import socket
import sys

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' module not found. Install it with: pip install requests")
    sys.exit(1)


# --- Embedded NmapParser (from backend/parser.py) ---

class NmapParser:
    def __init__(self):
        self.HOST_RE = re.compile(r"Nmap scan report for (?:.* \()?([\d\.]+)\)?")
        self.PORT_LINE_RE = re.compile(r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+([^\s]+)\s*(.*)")
        self.VULN_LINE_RE = re.compile(r"(CVE-\d{4}-\d+)")

    def parse(self, nmap_text):
        results = {"ports": [], "target": {"ip": "Unknown"}}
        current_ip = "Unknown"

        for line in nmap_text.split('\n'):
            line = line.strip()

            host_match = self.HOST_RE.search(line)
            if host_match:
                current_ip = host_match.group(1)
                results["target"]["ip"] = current_ip
                continue

            port_match = self.PORT_LINE_RE.search(line)
            if port_match:
                results["ports"].append({
                    "ip": current_ip,
                    "port": port_match.group(1),
                    "service": port_match.group(4),
                    "version": port_match.group(5),
                    "findings": []
                })
                continue

            vuln_match = self.VULN_LINE_RE.search(line)
            if vuln_match and results["ports"]:
                results["ports"][-1]["findings"].append({
                    "id": vuln_match.group(1),
                    "cvss": 0.0
                })

        return results


# --- Embedded run_nmap (from backend/nmap_runner.py) ---

def run_nmap(target, scan_mode="top1000"):
    cmd = ["nmap", "-sV", "-T4", "--script=vuln,vulners", "-Pn"]

    if scan_mode == "full":
        cmd.append("-p-")
    else:
        cmd.extend(["--top-ports", "1000"])

    targets = target.replace(',', ' ').split()
    cmd.extend(targets)

    print(f"[AGENT] Executing: {' '.join(cmd)}")

    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
    except FileNotFoundError:
        print("[ERROR] nmap not found on PATH. Ensure nmap is installed.")
        sys.exit(1)

    full_output = ""
    for line in process.stdout:
        full_output += line
        stripped = line.strip()
        if "About" in stripped:
            print(f"  [PROGRESS] {stripped}")

    process.wait()
    if process.returncode != 0:
        print(f"[WARNING] nmap exited with code {process.returncode}")

    return full_output


# --- Embedded threat classification (from backend/scraper.py) ---

def calculate_threat_info(score):
    try:
        score = float(score)
    except Exception:
        score = 0
    if score >= 9.0:
        return "CRITICAL", "risk-critical"
    elif score >= 7.0:
        return "HIGH", "risk-high"
    elif score >= 4.0:
        return "MEDIUM", "risk-medium"
    return "LOW", "risk-low"


# --- Build results in dashboard-compatible format ---

def build_results(parsed_data, target):
    raw_cves = []
    for p in parsed_data["ports"]:
        host_ip = p.get("ip", target)
        for f in p["findings"]:
            if f["id"].startswith("CVE-"):
                raw_cves.append({
                    "ip": host_ip,
                    "Service": p["service"],
                    "Version": p["version"],
                    "Vulnerability ID": f["id"],
                    "CVSS Score": f["cvss"],
                    "Reference URL": f"https://nvd.nist.gov/vuln/detail/{f['id']}",
                    "description": "Pending server enrichment"
                })

    threat_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in raw_cves:
        t_cat, risk_class = calculate_threat_info(item["CVSS Score"])
        item["risk_class"] = risk_class
        if t_cat in threat_counts:
            threat_counts[t_cat] += 1

    unique_ips = sorted(set(item["ip"] for item in raw_cves))
    scores = [float(x["CVSS Score"]) for x in raw_cves]
    max_score = max(scores) if scores else 0
    t_level, _ = calculate_threat_info(max_score)

    return {
        "results": raw_cves,
        "unique_ips": unique_ips,
        "threat_counts": threat_counts,
        "total_findings": len(raw_cves),
        "max_score": max_score,
        "threat_level": t_level
    }


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="IP-Intel Remote Agent - Run nmap locally and report to C2 server"
    )
    parser.add_argument("--server", required=True, help="C2 server URL (e.g. http://1.2.3.4:5002)")
    parser.add_argument("--key", required=True, help="API key for authentication")
    parser.add_argument("--target", required=True, help="Target IPs (comma-separated)")
    parser.add_argument("--mode", default="top1000", choices=["top1000", "full"],
                        help="Scan mode: top1000 (default) or full port scan")
    args = parser.parse_args()

    print(f"[AGENT] IP-Intel Remote Agent")
    print(f"[AGENT] Target: {args.target}")
    print(f"[AGENT] Mode: {args.mode}")
    print(f"[AGENT] Server: {args.server}")
    print()

    # Step 1: Run nmap
    print("[AGENT] Step 1/3: Running nmap scan...")
    nmap_output = run_nmap(args.target, args.mode)

    # Step 2: Parse results
    print("[AGENT] Step 2/3: Parsing scan results...")
    nmap_parser = NmapParser()
    parsed = nmap_parser.parse(nmap_output)

    # Step 3: Build and submit payload
    print("[AGENT] Step 3/3: Building and submitting payload...")
    payload = build_results(parsed, args.target)
    payload["target"] = args.target
    payload["agent_name"] = socket.gethostname()

    print(f"[AGENT] Found {payload['total_findings']} CVE findings")

    url = args.server.rstrip("/") + "/agent/submit"
    try:
        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {args.key}"},
            timeout=30
        )
        if resp.status_code == 201:
            print(f"[AGENT] Successfully submitted to server: {resp.json()}")
        elif resp.status_code == 401:
            print("[AGENT] Authentication failed. Check your API key.")
        else:
            print(f"[AGENT] Server error {resp.status_code}: {resp.text}")
    except requests.ConnectionError:
        print(f"[AGENT] Could not connect to {args.server}. Is the server running?")
    except requests.Timeout:
        print(f"[AGENT] Request timed out connecting to {args.server}")


if __name__ == "__main__":
    main()
