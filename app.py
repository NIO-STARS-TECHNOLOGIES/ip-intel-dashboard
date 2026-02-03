from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import time
import json
import threading
import re
import os
from werkzeug.utils import secure_filename

from backend.nmap_runner import run_nmap
from backend.parser import NmapParser
from backend.scraper import get_nvd_data, calculate_threat_info

app = Flask(__name__)

# Configure temporary storage for -iL files
UPLOAD_FOLDER = 'temp_scans'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # Handle both JSON (manual IP) and Form Data (File Upload)
    target_file = None
    if request.is_json:
        ui_data = request.json
        target_ip = ui_data.get('ip', 'N/A')
        scan_mode = ui_data.get('mode', 'top1000')
    else:
        target_ip = request.form.get('ip', 'N/A')
        scan_mode = request.form.get('mode', 'top1000')
        uploaded_file = request.files.get('file')
        
        if uploaded_file:
            filename = secure_filename(uploaded_file.filename)
            target_file = os.path.join(UPLOAD_FOLDER, filename)
            uploaded_file.save(target_file)
    
    print(f"\n[TERMINAL] Initiating {scan_mode.upper()} Analysis for: {target_ip if not target_file else target_file}", flush=True)

    def generate():
        full_nmap_output = ""
        try:
            yield f"data: {json.dumps({'progress': 10, 'msg': '[SYSTEM] Initiating Neural Interface...'})}\n\n"

            progress_msgs = []
            full_out = {"out": ""}

            def cb(msg):
                progress_msgs.append(msg)

            def runner():
                try:
                    # Pass target_file to the runner if it exists
                    out = run_nmap(target_ip=target_ip, target_file=target_file, scan_mode=scan_mode, progress_callback=cb)
                    full_out['out'] = out
                    # Clean up the temp file after scan
                    if target_file and os.path.exists(target_file):
                        os.remove(target_file)
                except Exception as e:
                    full_out['error'] = str(e)

            t = threading.Thread(target=runner, daemon=True)
            t.start()

            while t.is_alive() or progress_msgs:
                while progress_msgs:
                    m = progress_msgs.pop(0)
                    print(f"[NMAP-RAW] {m}", flush=True)
                    percent_match = re.search(r"About (\d+\.\d+)%", m)
                    if percent_match:
                        ai_percent = percent_match.group(1)
                        yield f"data: {json.dumps({'progress': float(ai_percent), 'msg': f'[AI] Neural Scanning: {ai_percent}% Analysis Complete'})}\n\n"
                    else:
                        if "Stats" not in m:
                            yield f"data: {json.dumps({'msg': f'[AI] {m}'})}\n\n"
                time.sleep(0.1)

            t.join()
            full_nmap_output = full_out.get('out', '')

        except Exception as e:
            yield f"data: {json.dumps({'msg': f'[ERROR] Engine Exception: {e}'})}\n\n"
            return

        # Scraper Phase with IP tracking
        parser = NmapParser()
        parsed_data = parser.parse(full_nmap_output)
        raw_cves = []
        
        target_host = parsed_data.get("target", {}).get("ip", target_ip)

        for p in parsed_data["ports"]:
            for f in p["findings"]:
                if f["id"].startswith("CVE-"):
                    raw_cves.append({
                        "ip": target_host, 
                        "Service": p["service"], "Version": p["version"], 
                        "Vulnerability ID": f["id"], "CVSS Score": f["cvss"],
                        "Reference URL": f"https://nvd.nist.gov/vuln/detail/{f['id']}"
                    })

        final_data = []
        threat_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for i, item in enumerate(raw_cves):
            v_id = item["Vulnerability ID"]
            print(f"[SCRAPER] Processing {v_id}...", flush=True)
            yield f"data: {json.dumps({'progress': 50 + int((i/len(raw_cves))*45), 'msg': f'[AI] Scraping Neural Intelligence for {v_id}', 'ticker': v_id})}\n\n"
            
            desc, nist_score = get_nvd_data(v_id)
            item["description"] = desc
            if nist_score and nist_score > 0:
                item["CVSS Score"] = nist_score
                
            # Get threat category (e.g., 'CRITICAL') and risk class (e.g., 'risk-critical')
            t_cat, risk_class = calculate_threat_info(item["CVSS Score"])
            item["risk_class"] = risk_class
            
            # Increment the corresponding counter
            if t_cat in threat_counts:
                threat_counts[t_cat] += 1
            final_data.append(item)

        unique_ips = sorted(list(set([item['ip'] for item in final_data if 'Vulnerability ID' in item])))

        # Prepare clear display name for History
        display_ip = target_ip if not target_file else f"List: {os.path.basename(target_file)}"
        max_score = max([float(x['CVSS Score']) for x in final_data]) if final_data else 0
        t_level, _ = calculate_threat_info(max_score)
        yield f"data: {json.dumps({
            'complete': True, 
            'results': final_data, 
            'unique_ips': unique_ips,
            'max_score': max_score, 
            'threat_level': t_level,
            'threat_counts': threat_counts,
            'total_findings': len(final_data), 
            'target_ip': display_ip
        })}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream', headers={'X-Accel-Buffering': 'no'})

if __name__ == '__main__':
    app.run(debug=True, port=5001, use_reloader=False)