import subprocess
import re

def run_nmap(target_ip=None, target_file=None, scan_mode="top1000", progress_callback=None):
    """
    Run nmap with dynamic port selection, multi-IP support, and file input (-iL).
    Ensures command arguments are correctly formatted for subprocess execution.
    """
    # 1. Base command structure with T4 for speed and -Pn to skip host discovery
    cmd = ["nmap", "-sS", "-sV", "-T4", "--stats-every", "10s", "--script=vuln,vulners", "-Pn"]
    
    # 2. Port selection logic based on mode
    if scan_mode == "full":
        # Full scan uses the -p- flag
        cmd.append("-p-")
    else:
        # FIX: Flag and value MUST be separate list items for the shell to parse them
        cmd.extend(["--top-ports", "1000"])

    # 3. Target Specification rules
    if target_file:
        # Use -iL for file-based scanning
        cmd.extend(["-iL", target_file])
    elif target_ip:
        # Sanitize input: Replace commas with spaces and split into individual targets
        targets = target_ip.replace(',', ' ').split()
        cmd.extend(targets)
    else:
        raise ValueError("Neural Error: No target or input file provided.")

    # Debug: Print the final command to the VS Code terminal for verification
    print(f"[ENGINE] Executing: {' '.join(cmd)}", flush=True)

    try:
        # bufsize=1 enables line-buffered output for real-time AI terminal tracking
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError:
        raise RuntimeError("nmap not found on PATH. Ensure it is installed on your system.")

    full_output = ""
    # Stream the output line by line to the dashboard
    for line in process.stdout:
        full_output += line
        # Capture progress lines to trigger the frontend AI terminal updates
        if progress_callback and ("Stats:" in line or "About" in line or "Remaining" in line):
            clean_msg = line.strip().replace('|', '')
            try:
                progress_callback(clean_msg)
            except Exception:
                pass
                
    process.wait()
    return full_output