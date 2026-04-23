import os
import sys
import time
import json
import requests
from datetime import datetime
import google.generativeai as genai
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CẤU HÌNH ---
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
LOG_FILE = "/home/client1/Downloads/VelLMes/Logs/SSH/ssh.log"
config_file = "config.ini"
if (not MISP_URL or not MISP_KEY) and os.path.exists(config_file):
    # Nếu chưa có cấu hình qua env, thử đọc file config.ini
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read(config_file)
        if not MISP_URL:
            MISP_URL = config.get("MISP", "url", fallback=None)
        if not MISP_KEY:
            MISP_KEY = config.get("MISP", "key", fallback=None)
        GEMINI_API_KEY = config.get("GEMINI", "key", fallback=None)
        if GEMINI_API_KEY:
            GEMINI_API_KEY = GEMINI_API_KEY
    except Exception as e:
        print(f"Error reading config file: {e}", file=sys.stderr)

if not all([MISP_URL, MISP_KEY, GEMINI_API_KEY]):
    print("Missing environment variables: MISP_URL, MISP_KEY, GEMINI_API_KEY")
    sys.exit(1)		

# Cấu hình Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-2.0-flash")

HEADERS = {
    "Authorization": MISP_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}
MISP_API_URL = MISP_URL.rstrip("/") + "/events"
VERIFY_SSL = False

# --- Theo dõi file log (tail -f) ---
def follow(path):
    with open(path, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            yield line.strip()

# --- Gọi Gemini trích xuất IP nguồn và lệnh shell ---
def extract_ssh_ioc(log_line):
    prompt = (
        "You are a cybersecurity assistant. Given this SSH log entry, extract the source IP address and the shell command executed. "
        "Respond with a JSON object containing exactly two keys: 'ip_src' and 'shell_cmd'. "
        "Do not include any other text."
        f"\nLog: {log_line}"
    )
    response = model.generate_content(prompt)
    text = response.text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Fallback: find JSON substring
        import re
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            return json.loads(m.group(0))
        raise ValueError(f"Non-JSON from Gemini: {text}")

# --- Gửi IOC lên MISP ---
def send_to_misp(ioc):
    ip = ioc.get("ip_src")
    cmd = ioc.get("shell_cmd")
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    info = f"SSH Command from {ip}"

    def attr(t, v, c, ids=True, comment=None):
        d = {"type": t, "value": v, "category": c, "to_ids": ids, "distribution": "0"}
        if comment:
            d["comment"] = comment
        return d

    attrs = []
    if ip:
        attrs.append(attr("ip-src", ip, "Network activity", comment="Attacker IP"))
    if cmd:
        attrs.append(attr("text", cmd, "External analysis", False, comment="Shell command"))

    if not attrs:
        print(f"No IOC extracted for line: {ioc}")
        return

    event = {"Event": {
        "info": info,
        "date": date_str,
        "distribution": "0",
        "threat_level_id": "2",
        "analysis": "0",
        "Attribute": attrs,
        "Tag": [{"name": "ssh_log"}, {"name": "shell_cmd"}]
    }}
    r = requests.post(MISP_API_URL, headers=HEADERS, json=event, verify=VERIFY_SSL)
    if r.status_code >= 300:
        print(f"Error sending to MISP: {r.status_code} {r.text}")
    else:
        print(f"Sent event SSH")

# --- Main loop ---
if __name__ == "__main__":

    if not os.path.exists(LOG_FILE):
        print(f"Log file not found: {LOG_FILE}")
        sys.exit(1)

    print(f"Monitoring SSH log: {LOG_FILE}")
    for line in follow(LOG_FILE):
        try:
            ioc = extract_ssh_ioc(line)
            send_to_misp(ioc)
        except Exception as e:
            print(f"Error processing line: {e}")

