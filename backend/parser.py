import re

class NmapParser:
    def __init__(self):
        self.TARGET_RE = re.compile(r'^Nmap scan report for (?:(?P<host>.+?) \()?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)?$')
        self.PORT_LINE_RE = re.compile(r'^(\d+)/(\w+)\s+(\w+)\s+([\w\-\.]+)\s*(.*)$')
        # Simplified Regex to reliably catch CVEs
        self.VULN_LINE_RE = re.compile(r'(CVE-\d{4}-\d+)') 

    def parse(self, text):
        target = {"ip": None, "hostname": None}
        ports = []
        current_port = None
        lines = text.splitlines()
        
        for raw_line in lines:
            line = raw_line.rstrip()
            t_match = self.TARGET_RE.match(line.strip())
            if t_match:
                target["ip"] = t_match.group("ip")
                target["hostname"] = t_match.group("host")
                continue
                
            p_match = self.PORT_LINE_RE.match(line.strip())
            if p_match:
                if current_port:
                    ports.append(current_port)
                port_num, proto, state, service, version = p_match.groups()
                current_port = {"port": port_num, "service": service, "version": version.strip(), "findings": []}
                continue
                
            if current_port:
                v_match = self.VULN_LINE_RE.search(line)
                if v_match:
                    # FIX: Only unpack 1 value because the regex only has 1 group
                    vuln_id = v_match.group(1) 
                    
                    # Since we simplified the regex, we set CVSS to 0.0 here.
                    # The scraper will fetch the real CVSS from NIST later.
                    current_port["findings"].append({"id": vuln_id, "cvss": 0.0})
                    
        if current_port:
            ports.append(current_port)
        return {"target": target, "ports": ports}