import os
import requests
from sqlalchemy import text
from dotenv import load_dotenv

# Import our unified, cloud-ready connection engine
from database.connection import engine

load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_telegram_notification(message):
    """Sends a native secure real-time push alert straight to Telegram app devices."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("⚠️ Telegram credentials missing in .env configurations. Skipping dispatch.")
        return
        
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        res = requests.post(url, json=payload, timeout=10)
        if res.status_code == 200:
            print("📱 Instant security message successfully pushed to your devices!")
        else:
            print(f"⚠️ Telegram server returned dispatch error status: {res.status_code}")
    except Exception as err:
        print(f"❌ Failed to reach notification gateway: {err}")

def run_alert_spike_analysis():
    print("🧠 Initializing Threat Intelligence Alert Analytics Engine...")
    
    with engine.begin() as connection:
        # 1. Fetch your active automated watchlist keywords
        keyword_query = text("SELECT keyword, alert_threshold FROM monitored_keywords WHERE active = 1;")
        active_keywords = connection.execution_options(prepared_statement=False).execute(keyword_query).fetchall()
        
        if not active_keywords:
            print("💡 Watchlist is empty. Run your auto-extractor script first!")
            return

        alerts_triggered = 0
        print(f"🧐 Scanning database logs against {len(active_keywords)} watchlist targets...")
        
        # 2. Process each keyword sequentially
        for row in active_keywords:
            keyword = row[0]
            threshold = row[1]
            
            # Count ONLY vulnerabilities that arrived or changed in the last 24 hours!
            cve_check_query = text("""
                SELECT COUNT(*), COALESCE(MAX(cvss_v3_score), 0.0) 
                FROM cve_records 
                WHERE LOWER(affected_software) LIKE :match_str
                  AND (published_date >= NOW() - INTERVAL '1 day' 
                       OR last_modified >= NOW() - INTERVAL '1 day');
            """)
            
            cve_res = connection.execution_options(prepared_statement=False).execute(
                cve_check_query, {"match_str": f"%{keyword}%"}
            ).fetchone()
            
            threat_count = cve_res[0]
            highest_cvss = cve_res[1]
            
            # 3. CRITICAL OPTIMIZATION: Alert ONLY if matches bust past the threshold setting
            if threat_count >= threshold:
                print(f"🚨 ALERT TRIGGERED! Keyword '{keyword}' has breached limits with {threat_count} bugs!")
                
                severity = "LOW"
                if highest_cvss >= 9.0: severity = "🔴 CRITICAL"
                elif highest_cvss >= 7.0: severity = "🟠 HIGH"
                elif highest_cvss >= 4.0: severity = "🟡 MEDIUM"
                
                # Compose a structured notification template card
                tg_alert_card = (
                    f"🚨 *SECURITY CLUSTER OUTBREAK DETECTED* 🚨\n\n"
                    f"🛡️ *Target Component:* `{keyword.upper()}`\n"
                    f"⚠️ *Active Vulnerabilities:* `{threat_count}`\n"
                    f"📊 *Peak Impact Metric:* `{highest_cvss} CVSS`\n"
                    f"🔥 *Calculated Severity Level:* {severity}\n\n"
                    f"👉 _Check your centralized Supabase dashboard metrics for deep analysis profiles._"
                )
                
                # 4. Fire the push alert out to the cloud channel network!
                send_telegram_notification(tg_alert_card)

                # 5. Save the record into your alert_spikes table for Power BI tracking
                insert_spike = text("""
                    INSERT INTO alert_spikes (spike_type, target_identifier, article_count_window, triggered_by_cvss, severity_level, alert_message)
                    VALUES ('CVE_CLUSTER_SPIKE', :target, :count, :cvss, :severity, :msg);
                """)
                connection.execution_options(prepared_statement=False).execute(insert_spike, {
                    "target": keyword,
                    "count": threat_count,
                    "cvss": highest_cvss,
                    "severity": severity.replace("🔴 ", "").replace("🟠 ", "").replace("🟡 ", ""),
                    "msg": f"Automated cluster outbreak of {threat_count} vulnerabilities targeting {keyword}."
                })
                
                # Update flag inside master CVE table
                update_cve_flag = text("UPDATE cve_records SET spike_flag = 1 WHERE LOWER(affected_software) LIKE :match_str;")
                connection.execution_options(prepared_statement=False).execute(update_cve_flag, {"match_str": f"%{keyword}%"})
                
                alerts_triggered += 1
                
        print(f"🎉 Analysis Complete! {alerts_triggered} high-priority threat alerts written to your cloud.")

if __name__ == "__main__":
    run_alert_spike_analysis()