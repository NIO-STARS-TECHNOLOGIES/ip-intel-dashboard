from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import time
import json
import threading
import re
import os
import datetime

from werkzeug.utils import secure_filename
from flask_apscheduler import APScheduler
from backend.nmap_runner import run_nmap
from backend.parser import NmapParser
from backend.scraper import get_nvd_data, calculate_threat_info

app = Flask(__name__)
scheduler = APScheduler()

# Global Trigger State
system_trigger = {"run_now": False, "target": "", "mode": ""}

class Config:
    SCHEDULER_API_ENABLED = True

app.config.from_object(Config())
scheduler.init_app(app)
scheduler.start()

# --- SCHEDULER TASK ---
def scheduled_scan_task(target_ip, scan_mode):
    global system_trigger
    # This sends the "signal" to the browser
    system_trigger = {
        "run_now": True, 
        "target": target_ip, 
        "mode": scan_mode
    }
    print(f"[SIGNAL] Triggering frontend for {target_ip}")

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check-trigger')
def check_trigger():
    global system_trigger
    # Send state and reset immediately to prevent loops
    state = system_trigger.copy()
    system_trigger = {"run_now": False, "target": "", "mode": ""}
    return jsonify(state)

@app.route('/schedule-scan', methods=['POST'])
def schedule_scan():
    data = request.json
    target_ip = data.get('ip')
    scan_mode = data.get('mode')
    run_time_str = data.get('time')

    try:
        run_date = datetime.datetime.strptime(run_time_str, '%Y-%m-%dT%H:%M')
        job_id = f"scan_{target_ip}_{int(time.time())}"
        
        scheduler.add_job(
            id=job_id,
            func=scheduled_scan_task,
            trigger='date',
            run_date=run_date,
            args=[target_ip, scan_mode]
        )
        return jsonify({"status": "success", "msg": f"AI Scan Queued for {run_date.strftime('%H:%M')}"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 400

@app.route('/analyze', methods=['POST'])
def analyze():
    target_file = None
    target_ip = None
    scan_mode = 'top1000' # Default fallback
    
    # 1. Attempt to get JSON first (used by scheduled tasks)
    ui_data = request.get_json(silent=True)
    
    if ui_data:
        raw_target = ui_data.get('ip', '').strip()
        scan_mode = ui_data.get('mode', 'top1000')
        
        if raw_target.upper().startswith("FILE:"):
            # Extract filename regardless of space after colon
            clean_name = raw_target.split(":", 1)[1].strip()
            target_file = os.path.join('temp_scans', clean_name)
        else:
            target_ip = raw_target
    else:
        # 2. Handling Form Data (manual analysis button)
        scan_mode = request.form.get('mode', 'top1000')
        uploaded_file = request.files.get('file')
        raw_ip = request.form.get('ip', '').strip()

        if uploaded_file and (raw_ip.upper().startswith("FILE:") or not raw_ip):
            os.makedirs('temp_scans', exist_ok=True)
            filename = secure_filename(uploaded_file.filename)
            target_file = os.path.join('temp_scans', filename)
            uploaded_file.save(target_file)
        else:
            target_ip = raw_ip

    # --- ENHANCED CRITICAL GUARD ---
    # If target_ip is an empty string, Python truthiness sees it as False
    if not target_file and (not target_ip or target_ip == ""):
        return Response(
            f"data: {json.dumps({'msg': '[ERROR] Nmap Execution Failed: No valid IP or file provided.'})}\n\n",
            mimetype='text/event-stream'
        )
    
    print(f"\n[TERMINAL] Initiating {scan_mode.upper()} Analysis for: {target_ip if not target_file else target_file}", flush=True)

    def generate():
        full_nmap_output = ""
        try:
            # NEURAL SCRUBBER: Clean the file content for Nmap compatibility (-iL)
            if target_file and os.path.exists(target_file):
                yield f"data: {json.dumps({'msg': '[SYSTEM] Neural Scrubber: Cleaning target list...'})}\n\n"
                with open(target_file, 'r') as f:
                    content = f.read()
                
                # Regex for IPv4 addresses to remove noise like ""
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
                
                if not ips:
                    yield f"data: {json.dumps({'msg': '[ERROR] No valid IP addresses found in the uploaded file.'})}\n\n"
                    return

                with open(target_file, 'w') as f:
                    f.write("\n".join(ips))
                
                yield f"data: {json.dumps({'msg': f'[AI] Neural Scrubber: Extracted {len(ips)} IPs.'})}\n\n"

            yield f"data: {json.dumps({'progress': 10, 'msg': '[SYSTEM] Initiating Neural Interface...'})}\n\n"

            progress_msgs = []
            full_out = {"out": ""}

            def cb(msg):
                progress_msgs.append(msg)

            def runner():
                try:
                    # nmap_runner.py handles the selection of -iL vs raw target
                    out = run_nmap(target_ip=target_ip, target_file=target_file, scan_mode=scan_mode, progress_callback=cb)
                    full_out['out'] = out
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

            if 'error' in full_out:
                yield f"data: {json.dumps({'msg': f'[ERROR] Nmap Execution Failed: {full_out['error']}'})}\n\n"
                return

        except Exception as e:
            yield f"data: {json.dumps({'msg': f'[ERROR] Engine Exception: {e}'})}\n\n"
            return

        # Scraper Phase
        parser = NmapParser()
        parsed_data = parser.parse(full_nmap_output)
        raw_cves = []
        
        for p in parsed_data["ports"]:
            host_ip = p.get('ip', target_ip)
            for f in p["findings"]:
                if f["id"].startswith("CVE-"):
                    raw_cves.append({
                        "ip": host_ip, 
                        "Service": p["service"], "Version": p["version"], 
                        "Vulnerability ID": f["id"], "CVSS Score": f["cvss"],
                        "Reference URL": f"https://nvd.nist.gov/vuln/detail/{f['id']}"
                    })

        final_data = []
        threat_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        if not raw_cves:
             yield f"data: {json.dumps({'msg': '> [AI] No Vulnerabilities detected in neural stream.'})}\n\n"
        
        for i, item in enumerate(raw_cves):
            v_id = item["Vulnerability ID"]
            scraper_progress = 50 + int((i/len(raw_cves))*45) if raw_cves else 95
            yield f"data: {json.dumps({'progress': scraper_progress, 'msg': f'[AI] Scraping Neural Intelligence for {v_id}', 'ticker': v_id})}\n\n"
            
            desc, nist_score = get_nvd_data(v_id)
            item["description"] = desc
            if nist_score and nist_score > 0:
                item["CVSS Score"] = nist_score
                
            t_cat, risk_class = calculate_threat_info(item["CVSS Score"])
            item["risk_class"] = risk_class
            
            if t_cat in threat_counts:
                threat_counts[t_cat] += 1
            final_data.append(item)

        unique_ips = sorted(list(set([item['ip'] for item in final_data if 'Vulnerability ID' in item])))
        display_ip = target_ip if not target_file else f"List: {os.path.basename(target_file)}"
        extracted_scores = [float(x['CVSS Score']) for x in final_data]
        max_score = max(extracted_scores) if extracted_scores else 0
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
    os.makedirs('temp_scans', exist_ok=True)
    app.run( host="0.0.0.0",debug=True, port=5002, use_reloader=False)