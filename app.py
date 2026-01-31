from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import requests
from bs4 import BeautifulSoup
from lxml import etree
import re
import time
import json

app = Flask(__name__)

def calculate_threat_info(score):
    """Determines risk level based on the CVSS score."""
    try:
        score = float(score)
    except (ValueError, TypeError):
        score = 0
    if score >= 9.0: return "CRITICAL", "risk-critical"
    elif score >= 7.0: return "HIGH", "risk-high"
    elif score >= 4.0: return "MEDIUM", "risk-medium"
    return "LOW", "risk-low"

def get_nvd_data(vuln_id):
    """Flexible scraper for NIST NVD descriptions and scores."""
    if not vuln_id or not vuln_id.startswith("CVE"):
        return "N/A", None
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        response = requests.get(nvd_url, timeout=15, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            desc_tag = soup.find("p", {"data-testid": "vuln-description"}) or \
                       soup.find("td", {"data-testid": "vuln-description-td"}) or \
                       soup.select_one('p[property="vuln:summary"]')
            description = desc_tag.get_text().strip() if desc_tag else "Description not found."
            score_tag = soup.find("a", {"id": "Cvss3NistFullId"}) or \
                        soup.find("a", {"id": "Cvss3CnaCalculatorAnchor"})
            score = None
            if score_tag:
                score_match = re.search(r"(\d+\.\d+)", score_tag.get_text())
                if score_match: score = float(score_match.group(1))
            return description, score
        elif response.status_code == 403:
            return "NIST Access Denied (Rate Limited).", None
    except Exception as e:
        print(f"Server Error for {vuln_id}: {e}")
    return "Could not retrieve live data from NIST.", None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    input_data = request.json
    if not input_data:
        return jsonify({"error": "No data received"}), 400

    def generate():
        raw_results = []
        target_ip = "N/A"

        # Step 1: Parsing Data
        if isinstance(input_data, list):
            for host in input_data:
                target_ip = host.get('target', {}).get('ip', 'N/A')
                for port in host.get('ports', []):
                    for script_name, findings in port.get('scripts', {}).items():
                        if isinstance(findings, list):
                            for finding in findings:
                                vuln_id = (finding.get('cve') or finding.get('raw', '').split('\t')[0]).strip()
                                raw_results.append({
                                    "Service": port.get('service', 'N/A'),
                                    "Version": port.get('version', ''),
                                    "Vulnerability ID": vuln_id,
                                    "CVSS Score": finding.get('cvss') or 0,
                                    "Reference URL": finding.get('raw', '').split('\t')[2] if '\t' in finding.get('raw', '') else '#'
                                })

        # Step 2: Streaming Enrichment
        seen_ids = set()
        final_data = []
        total = len(raw_results)

        for i, item in enumerate(raw_results):
            vuln_id = item["Vulnerability ID"]
            score = float(item["CVSS Score"])

            if vuln_id not in seen_ids or score > 0:
                if re.match(r"CVE-\d{4}-\d{4,}", vuln_id):
                    # Progress update for the frontend
                    progress = int(((i + 1) / total) * 100)
                    yield f"data: {json.dumps({'progress': progress, 'msg': f'[AI ENGINE] Deep scanning {vuln_id}...'})}\n\n"
                    
                    nvd_desc, nvd_score = get_nvd_data(vuln_id)
                    item['description'] = nvd_desc
                    if nvd_score: item['CVSS Score'] = nvd_score
                    time.sleep(0.6)
                else:
                    item['description'] = f"Threat Intel finding ({vuln_id}). No NIST record available."
                
                _, risk_class = calculate_threat_info(item["CVSS Score"])
                item['risk_class'] = risk_class
                
                if not any(d['Vulnerability ID'] == vuln_id for d in final_data):
                    final_data.append(item)
                    seen_ids.add(vuln_id)

        # Final Summary Metrics
        scores = [float(item["CVSS Score"]) for item in final_data]
        max_score = max(scores) if scores else 0
        threat_level, _ = calculate_threat_info(max_score)

        # Send final data payload
        # The final yield in app.py
        yield f"data: {json.dumps({
            'complete': True, 
            'results': final_data, 
            'max_score': max_score, 
            'threat_level': threat_level, 
            'total_findings': len(final_data), 
            'target_ip': target_ip
        })}\n\n"
    return Response(stream_with_context(generate()), mimetype='text/event-stream') #

if __name__ == '__main__':
    app.run(debug=True, port=5000)