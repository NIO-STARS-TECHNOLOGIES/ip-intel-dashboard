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
            
            # Scrape Description
            desc_tag = soup.find("p", {"data-testid": "vuln-description"})
            description = desc_tag.get_text().strip() if desc_tag else "Description not found."
            
            # Scrape CVSS Score
            # Look for the CVSS v3.x base score link
            score_tag = soup.find("a", {"id": "Cvss3NistCalculatorAnchor"})
            score = 0.0
            if score_tag:
                try:
                    # Extracts numerical value from text like "8.8 HIGH"
                    score = float(score_tag.get_text().split()[0])
                except:
                    score = 0.0
                    
            return description, score
    except Exception as e:
        return f"Error: {e}", 0.0
    return "Enrichment failed.", 0.0


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