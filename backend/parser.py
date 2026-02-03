import re

class NmapParser:
    def __init__(self):
        # Matches the host line: "Nmap scan report for 192.168.0.1"
        self.HOST_RE = re.compile(r"Nmap scan report for (?:.* \()?([\d\.]+)\)?")
        # Matches port lines: "80/tcp open http Apache 2.4.41"
        self.PORT_LINE_RE = re.compile(r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+([^\s]+)\s*(.*)")
        # Matches CVE IDs in script output
        self.VULN_LINE_RE = re.compile(r"(CVE-\d{4}-\d+)")

    def parse(self, nmap_text):
        results = {"ports": [], "target": {"ip": "Unknown"}}
        current_ip = "Unknown"
        
        lines = nmap_text.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 1. Check for a new host section
            host_match = self.HOST_RE.search(line)
            if host_match:
                current_ip = host_match.group(1)
                # Keep target updated for backward compatibility
                results["target"]["ip"] = current_ip 
                continue

            # 2. Check for port lines
            port_match = self.PORT_LINE_RE.search(line)
            if port_match:
                # Associate this port with the specific IP it was found under
                port_data = {
                    "ip": current_ip, 
                    "port": port_match.group(1),
                    "service": port_match.group(4),
                    "version": port_match.group(5),
                    "findings": []
                }
                results["ports"].append(port_data)
                continue

            # 3. Check for vulnerabilities and add them to the LAST port found
            vuln_match = self.VULN_LINE_RE.search(line)
            if vuln_match and results["ports"]:
                vuln_id = vuln_match.group(1)
                # Ensure the CVE is added to the port on the correct host
                results["ports"][-1]["findings"].append({
                    "id": vuln_id,
                    "cvss": 0.0  # Placeholder for scraper enrichment
                })

        return results