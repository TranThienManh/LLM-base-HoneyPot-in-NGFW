import os
import sys
import json
from ruamel.yaml import YAML
import google.generativeai as genai
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CẤU HÌNH ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
config_file = "config.ini"
if os.path.exists(config_file):
    # Nếu chưa có cấu hình qua env, thử đọc file config.ini
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read(config_file)
        GEMINI_API_KEY = config.get("GEMINI", "key", fallback=None)
        if GEMINI_API_KEY:
            GEMINI_API_KEY = GEMINI_API_KEY
    except Exception as e:
        print(f"Error reading config file: {e}", file=sys.stderr)

if not all([GEMINI_API_KEY]):
    print("Missing environment variables: MISP_URL, MISP_KEY, GEMINI_API_KEY")
    sys.exit(1)

# Cấu hình Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-2.0-flash")	

input_file = "cves_raw_15_07_2025.json"
output_file = {
        "SSH": "configSSH.yml",
        "HTTP": "configHTTP.yml",
    }

# --- XỬ LÝ CVE ---
def generate_prompt(cve):
    return f"""You are a honeypot simulation analyst. Your task is to generate an extremely detailed, technically precise paragraph describing how a specific CVE vulnerability is exploited on a Linux/Unix system.

You will receive CVE metadata in JSON format. Based on that:

1. Describe the attack scenario in exhaustive detail, including:
   - How the attacker identifies or reaches the vulnerable system
   - The step-by-step actions taken by the attacker to exploit the vulnerability
   - What commands or techniques might be used
   - What responses or behaviors are triggered in the system
   - What specific parts of the system misbehave or allow the attack
   - What visible evidence (logs, sockets, environment variables, background processes) is generated

2. The paragraph must reflect **realistic system behavior**, including:
   - What the attacker sees
   - What the system allows or mistakenly enables
   - Any security controls that are bypassed
   - How the environment changes during or after the attack

3. The output must be **a single uninterrupted paragraph** with no line breaks, no bullet points, and no markdown formatting.

4. The CVE ID (e.g., CVE-2025-32728) must be **explicitly included** in the paragraph.

5. Do not describe or repeat the CVE metadata structure; only focus on the **practical attack scenario**.

6. Do not simplify or shorten the description — include **as much technical depth as possible**, even if it results in a long paragraph.

Constraints:
- Maintain complete realism based on standard Linux server behavior.
- Assume default configurations unless CVE indicates misconfiguration.
- Avoid generic language — tailor the description to this exact CVE.

Here is the CVE context:

CVE ID: {cve["id"]}  
Method: {cve["method"]}  
Description: {cve["description"]}
Severity: {cve["severity"]}
Cvss_score: {cve["cvss_score"]}
Attack_vector: {cve["attack_vector"]}
Privileges_required: {cve["privileges_required"]}
User_interaction: {cve["user_interaction"]}
Confidentiality_impact: {cve["confidentiality_impact"]}
Integrity_impact: {cve["integrity_impact"]}
Availability_impact: {cve["availability_impact"]}
Vulnerable_cpe: {cve["vulnerable_cpe"]}
Exploit_refs: {cve["exploit_refs"]}
"""
def append_to_personality_prompt(cve, gemini_output):
    method = cve["method"].strip().upper()
    file_map = {
        "SSH": "app/configs/configSSH.yml",
        "HTTP": "configHTTP.yml"
    }

    config_file = file_map.get(method)
    if not config_file:
        print(f"[!] Unknown method: {method}")
        return

    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)

    try:
        with open(config_file, "r", encoding="utf-8") as f:
            data = yaml.load(f)
    except FileNotFoundError:
        data = {}

    # Đảm bảo personality_prompt là string
    existing_text = data.get("personality_prompt", "")
    if not isinstance(existing_text, str):
        print("[!] Warning: 'personality_prompt' is not a string. Overwriting as string.")
        existing_text = ""

    # Nối thêm kết quả Gemini vào cuối, phân cách bằng 2 dòng xuống hàng
    new_text = existing_text.rstrip() + "\n\n" + gemini_output.strip()
    data["personality_prompt"] = new_text

    # Ghi lại YAML
    with open(output_file[method], "w", encoding="utf-8") as f:
        yaml.dump(data, f)

    print(f"[+] Appended interactions from {cve['id']} to {output_file[method]} under personality_prompt.")


def main():
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            cves = json.load(f)
    except Exception as e:
        print(f"Error reading {input_file}: {e}")
        return

    for cve in cves:
        # print(f"\n=== {cve['id']} ===\n")
        prompt = generate_prompt(cve)
        try:
            response = model.generate_content(prompt)
            # print(response.text)
            append_to_personality_prompt(cve, response.text)
        except Exception as e:
            print(f"Error querying Gemini for {cve['id']}: {e}")

if __name__ == "__main__":
    main()
