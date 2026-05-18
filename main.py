import os
import time
from datetime import datetime
from sqlalchemy import text
from dotenv import load_dotenv

# 1. Import our unified engine from your connection configuration
from database.connection import engine  

# 2. Import the core execution functions from your clean collector modules
from collectors.nvd_collector import fetch_recent_cves, process_and_save_cves
from collectors.news_collector import fetch_and_save_news
from processing.alert_engine import run_alert_spike_analysis

def run_complete_threat_pipeline():
    print("🚀 =================================================== 🚀")
    print(f"⏰ Starting Central Threat Intelligence Pipeline Run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("🚀 =================================================== 🚀")
    
    start_time = time.time()
    status = "SUCCESS"
    error_message = None
    total_fetched = 0
    
    try:
        # Phase 1: Ingest Live CVE Vulnerabilities
        print("\n=== PHASE 1: INGESTING CVE RECORDS ===")
        raw_cves = fetch_recent_cves(days_back=1)
        total_fetched += len(raw_cves)
        process_and_save_cves(raw_cves)
        
        # Phase 2: Ingest Live Cybersecurity News Streams
        print("\n=== PHASE 2: INGESTING RSS NEWS ARTICLES ===")
        fetch_and_save_news()
        
        # Phase 3: Execute Threat Analytics & System Alert Triggers
        print("\n=== PHASE 3: RUNNING THREAT ALERT METRICS ===")
        run_alert_spike_analysis()
        
    except Exception as pipeline_err:
        status = "FAILED"
        error_message = str(pipeline_err)
        print(f"❌ CRITICAL PIPELINE FAILURE: {pipeline_err}")
        
    finally:
        duration = round(time.time() - start_time, 2)
        print("\n=== PHASE 4: WRITING PERFORMANCE METRICS TO LOG ===")
        print(f"⏱️ Total Execution Duration: {duration} seconds. Status: {status}")
        
        # Write clean heartbeat row into your pipeline_log table using our shared connection channel
        try:
            with engine.connect() as connection:
                log_query = text("""
                    INSERT INTO pipeline_log (source, records_fetched, records_inserted, records_skipped, duration_seconds, status, error_message)
                    VALUES ('CLOUD_MASTER_SCHEDULER', :fetched, :inserted, 0, :duration, :status, :err);
                """)
                connection.execute(log_query, {
                    "fetched": int(total_fetched),
                    "inserted": int(total_fetched),
                    "duration": float(duration),
                    "status": str(status),
                    "err": str(error_message) if error_message else None
                })
            print("📊 Performance metric details successfully logged to pipeline_log table!")
        except Exception as log_err:
            print(f"⚠️ Warning: Metric logging details skipped: {log_err}")
            
    print("\n🏁 =================================================== 🏁")
    print("🎉 Central System Coordination Routine Fully Executed.")
    print("🏁 =================================================== 🏁")

if __name__ == "__main__":
    run_complete_threat_pipeline()