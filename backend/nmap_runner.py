import subprocess
import re


def run_nmap(target_ip, progress_callback=None):
    """Run nmap and call progress_callback for progress lines.

    Returns the full nmap output as a string.
    """
    #cmd = ["nmap", "-sS", "-sV", "-p-", "--stats-every", "10s", "--script=vuln,vulners", "-Pn", target_ip]
    # Added -T4 for speed and --top-ports 1000 for faster testing
    cmd = ["nmap", "-sS", "-sV", "-T4", "--top-ports", "1000", "--stats-every", "10s", "--script=vuln,vulners", "-Pn", target_ip]
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError as e:
        raise RuntimeError("nmap not found on PATH") from e

    full_output = ""
    for line in process.stdout:
        full_output += line
        if progress_callback and ("Stats:" in line or "About" in line or "Remaining" in line):
            clean_msg = line.strip().replace('|', '')
            try:
                progress_callback(clean_msg)
            except Exception:
                pass
    process.wait()
    return full_output
