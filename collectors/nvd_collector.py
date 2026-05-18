import os
import requests
from datetime import datetime, timedelta, timezone
from sqlalchemy import text
from dotenv import load_dotenv

# 1. Import our unified cloud-ready connection engine
from database.connection import engine

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

def fetch_recent_cves(days_back=1):
    """Fetches newly published vulnerabilities from the official NVD API."""
    print(f"⏳ Contacting NIST National Vulnerability Database API...")
    
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=days_back)
    
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    end_str = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_str,
        "pubEndDate": end_str
    }
    
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        if response.status_code != 200:
            print(f"❌ NVD API returned an error status: {response.status_code}")
            return []
            
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        print(f"📥 Successfully fetched {len(vulnerabilities)} vulnerabilities from the last {days_back} day(s).")
        return vulnerabilities
    except Exception as e:
        print(f"❌ Failed to reach NVD API stream: {e}")
        return []

def process_and_save_cves(vulnerabilities):
    """Parses JSON payload data shapes and appends records cleanly to Supabase."""
    if not vulnerabilities:
        print("💡 No new records found to process.")
        return

    records_inserted = 0
    
    # 2. Open a standard connection thread compatible with transaction pooling
    with engine.connect() as connection:
        try:
            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                
                descriptions = cve.get("descriptions", [])
                description_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available.")
                
                metrics = cve.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                
                cvss_score = None
                cvss_severity = "UNKNOWN"
                vector_string = None
                
                if cvss_v3:
                    cvss_data = cvss_v3[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity")
                    vector_string = cvss_data.get("vectorString")

                configurations = cve.get("configurations", [])
                software_list = []
                for config in configurations:
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            cpe_str = match.get("criteria", "")
                            if cpe_str:
                                parts = cpe_str.split(":")
                                if len(parts) > 4:
                                    software_list.append(f"{parts[3]} ({parts[4]})")
                
                affected_software = ", ".join(list(set(software_list))[:10]) if software_list else "General / Unspecified"
                
                published_date = cve.get("published")
                last_modified = cve.get("lastModified")
                source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                query = text("""
                    INSERT INTO cve_records (cve_id, published_date, last_modified, description, cvss_v3_score, cvss_v3_severity, vector_string, affected_software, source_url)
                    VALUES (:cve_id, :pub, :mod, :desc, :score, :sev, :vector, :soft, :url)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        last_modified = EXCLUDED.last_modified,
                        description = EXCLUDED.description,
                        cvss_v3_score = EXCLUDED.cvss_v3_score,
                        cvss_v3_severity = EXCLUDED.cvss_v3_severity;
                """)
                
                connection.execute(query, {
                    "cve_id": cve_id,
                    "pub": published_date,
                    "mod": last_modified,
                    "desc": description_text,
                    "score": cvss_score,
                    "sev": cvss_severity,
                    "vector": vector_string,
                    "soft": affected_software,
                    "url": source_url
                })
                records_inserted += 1
                
            print(f"🚀 Success! {records_inserted} CVE records have been processed down the pipeline.")
        except Exception as e:
            print(f"❌ Error during data ingestion streaming pipeline: {e}")

if __name__ == "__main__":
    raw_vulnerabilities = fetch_recent_cves(days_back=5)
    # This block only runs if you execute THIS file directly!
    process_and_save_cves(raw_vulnerabilities)