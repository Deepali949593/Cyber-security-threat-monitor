import os
from collections import Counter
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL)

def discover_and_seed_keywords():
    print("🔍 Scanning live CVE database records for trending technologies...")
    
    # 1. Fetch all the affected software text currently in your database
    with engine.connect() as connection:
        query = text("SELECT affected_software FROM cve_records WHERE affected_software IS NOT NULL;")
        result = connection.execute(query)
        rows = result.fetchall()
    
    # 2. Break down the text strings into individual product words
    raw_words = []
    for row in rows:
        software_string = row[0]
        # Split by commas and spaces, clean up the words
        parts = software_string.replace(",", " ").replace("(", " ").replace(")", " ").split()
        for part in parts:
            clean_part = part.strip().lower()
            # Filter out generic words, versions, and numbers
            if len(clean_part) > 2 and not clean_part.isdigit() and clean_part not in ["general", "unspecified", "and", "for", "with"]:
                raw_words.append(clean_part)
                
    # 3. Count which technologies appear the most frequently
    word_counts = Counter(raw_words)
    top_discovered_tech = word_counts.most_common(20) # Grab the top 20 most attacked things
    
    print(f"📈 Found {len(word_counts)} unique technology components inside your data!")
    print("🎯 Top detected threats:", [tech for tech, _ in top_discovered_tech[:5]])
    
    # 4. Stream these dynamically discovered keywords straight into your watchlist table
    inserted_count = 0
    with engine.connect() as connection:
        trans = connection.begin()
        try:
            for tech, count in top_discovered_tech:
                insert_query = text("""
                    INSERT INTO monitored_keywords (keyword, category, alert_threshold)
                    VALUES (:keyword, 'Auto-Discovered', 3)
                    ON CONFLICT (keyword) DO NOTHING;
                """)
                res = connection.execute(insert_query, {"keyword": tech})
                if res.rowcount > 0:
                    inserted_count += 1
            trans.commit()
            print(f"🎉 Successfully extracted and injected {inserted_count} trending keywords into your watchlist!")
        except Exception as e:
            trans.rollback()
            print(f"❌ Failed to update dynamic watchlist: {e}")

if __name__ == "__main__":
    discover_and_seed_keywords()