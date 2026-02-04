import requests
from bs4 import BeautifulSoup

def get_nvd_data(vuln_id, timeout=10):
    if not vuln_id or not vuln_id.startswith("CVE"):
        return "N/A", 0.0 # Return 0.0 as default score
        
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(nvd_url, timeout=timeout, headers=headers)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. Scrape Description
            desc_tag = soup.find("p", {"data-testid": "vuln-description"})
            description = desc_tag.get_text().strip() if desc_tag else "Description not found."
            
            # Helper to extract float score from NIST anchor tags
            def extract_score(anchor_id):
                tag = soup.find("a", {"id": anchor_id})
                if tag:
                    try:
                        # NIST format is usually "X.X SEVERITY" (e.g., "10.0 CRITICAL")
                        return float(tag.get_text().split()[0])
                    except (ValueError, IndexError):
                        pass
                return 0.0

            # 2. Scrape Scores from all available standards
            v4_score = extract_score("Cvss4NistCalculatorAnchor")
            v3_score = extract_score("Cvss3NistCalculatorAnchor") #
            v2_score = extract_score("Cvss2CalculatorAnchor")    # Added CVSS v2.0

            # 3. Use the highest score available (Ensures 10.0 is used if found in any version)
            final_score = max(v4_score, v3_score, v2_score)
                    
            return description, final_score
            
    except Exception as e:
        return f"Neural Interface Error: {e}", 0.0
    return "Enrichment failed.", 0.0

def calculate_threat_info(score):
    """Categorizes the threat based on the numerical CVSS score."""
    try:
        score = float(score)
    except Exception:
        score = 0
    if score >= 9.0:
        return "CRITICAL", "risk-critical" #
    elif score >= 7.0:
        return "HIGH", "risk-high" #
    elif score >= 4.0:
        return "MEDIUM", "risk-medium" #
    return "LOW", "risk-low" #