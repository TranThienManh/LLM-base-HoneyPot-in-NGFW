import requests
import datetime
import json
filename = f"cves_raw_{datetime.datetime.now().strftime('%d_%m_%Y')}.json"

def CVE_From_NVD(filename):
    # ==== Thiết lập ngày truy vấn ====
    today = datetime.datetime.utcnow()
    start_date = (today - datetime.timedelta(days=100)).strftime('%Y-%m-%dT00:00:00.000Z')
    end_date = today.strftime('%Y-%m-%dT23:59:59.000Z')

    # ==== Các keyword cần tìm ====
    keywords = ["HTTP"]
    

    # ==== Danh sách kết quả ====
    all_cves = []

    for keyword in keywords:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "pubStartDate": start_date,
            "pubEndDate": end_date,
            "resultsPerPage": 10
        }
        
        response = requests.get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                cve_id = cve["id"]
                description = cve["descriptions"][0]["value"]
                published = cve["published"][:10]
                metrics = cve.get("metrics", {})
                configs = cve.get("configurations", [])
                refs = cve.get("references", [])

                # === Lấy thông tin CVSS v3.1 nếu có ===
                base_severity = "UNKNOWN"
                base_score = "UNKNOWN"
                attack_vector = privileges = user_interaction = "UNKNOWN"
                confidentiality = integrity = availability = "UNKNOWN"

                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]
                    base_severity = cvss.get("baseSeverity", "UNKNOWN")
                    base_score = cvss.get("baseScore", "UNKNOWN")
                    attack_vector = cvss.get("attackVector", "UNKNOWN")
                    privileges = cvss.get("privilegesRequired", "UNKNOWN")
                    user_interaction = cvss.get("userInteraction", "UNKNOWN")
                    confidentiality = cvss.get("confidentialityImpact", "UNKNOWN")
                    integrity = cvss.get("integrityImpact", "UNKNOWN")
                    availability = cvss.get("availabilityImpact", "UNKNOWN")

                # === Trích cpeMatch để biết sản phẩm bị ảnh hưởng ===
                cpe_list = []
                for config in configs:
                    for node in config.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            if cpe.get("vulnerable"):
                                cpe_list.append(cpe.get("criteria"))

                # === Trích link liên quan ===
                exploit_refs = []
                for ref in refs:
                    if "Exploit" in ref.get("tags", []):
                        exploit_refs.append(ref["url"])

                if cpe_list:
                    all_cves.append({
                        "id": cve_id,
                        "method": keyword,
                        "description": description,
                        "severity": base_severity,
                        "cvss_score": base_score,
                        "attack_vector": attack_vector,
                        "privileges_required": privileges,
                        "user_interaction": user_interaction,
                        "confidentiality_impact": confidentiality,
                        "integrity_impact": integrity,
                        "availability_impact": availability,
                        "vulnerable_cpe": cpe_list,
                        "exploit_refs": exploit_refs,
                    })
        else:
            print(f"⚠️ Lỗi truy cập với từ khóa {keyword}: {response.status_code}")

    # ==== Ghi ra file JSON để Gemini dễ xử lý ====
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(all_cves, f, indent=2)

    print(f"Đã lưu {len(all_cves)} CVE vào file: {filename} ")

CVE_From_NVD(filename)