from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import time
import json
import threading
import re

from backend.nmap_runner import run_nmap
from backend.parser import NmapParser
from backend.scraper import get_nvd_data, calculate_threat_info

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    ui_data = request.json
    target_ip = ui_data.get('ip', 'N/A')
    
    # Original technical log for terminal
    print(f"\n[TERMINAL] Initiating Analysis for: {target_ip}", flush=True)

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
                    out = run_nmap(target_ip, progress_callback=cb)
                    full_out['out'] = out
                except Exception as e:
                    full_out['error'] = str(e)

            t = threading.Thread(target=runner, daemon=True)
            t.start()

            # The Loop: Technical to Terminal, AI to Frontend
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

        # Scraper Phase
        parser = NmapParser()
        parsed_data = parser.parse(full_nmap_output)
        raw_cves = []
        for p in parsed_data["ports"]:
            for f in p["findings"]:
                if f["id"].startswith("CVE-"):
                    raw_cves.append({
                        "Service": p["service"], "Version": p["version"], 
                        "Vulnerability ID": f["id"], "CVSS Score": f["cvss"],
                        "Reference URL": f"https://nvd.nist.gov/vuln/detail/{f['id']}"
                    })

        final_data = [] # New list for enriched results
        for i, item in enumerate(raw_cves):
            v_id = item["Vulnerability ID"]
            print(f"[SCRAPER] Processing {v_id}...", flush=True)
            
            yield f"data: {json.dumps({'progress': 50 + int((i/len(raw_cves))*45), 'msg': f'[AI] Scraping Neural Intelligence for {v_id}', 'ticker': v_id})}\n\n"
            
            # Unpack both description and numerical score
            desc, nist_score = get_nvd_data(v_id)
            item["description"] = desc
            
            # Update score if found, otherwise keep original
            if nist_score > 0:
                item["CVSS Score"] = nist_score
                
            # Recalculate color-coded risk class
            _, risk_class = calculate_threat_info(item["CVSS Score"])
            item["risk_class"] = risk_class
            
            final_data.append(item)

        # Calculate final summary based on enriched data
        max_score = max([float(x['CVSS Score']) for x in final_data]) if final_data else 0
        t_level, _ = calculate_threat_info(max_score)

        yield f"data: {json.dumps({
            'complete': True, 
            'results': final_data, 
            'max_score': max_score, 
            'threat_level': t_level, 
            'total_findings': len(final_data), 
            'target_ip': target_ip
        })}\n\n"

    return Response(stream_with_context(generate()), 
                   mimetype='text/event-stream', 
                   headers={'X-Accel-Buffering': 'no'})

if __name__ == '__main__':
    app.run(debug=True, port=5001, use_reloader=False)