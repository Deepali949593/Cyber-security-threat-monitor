import os
import feedparser
from datetime import datetime, timezone
from time import mktime
from sqlalchemy import text
from dotenv import load_dotenv

# 1. Import our unified cloud-ready connection engine
from database.connection import engine

load_dotenv()

# High-quality RSS Feeds for live Cybersecurity Threat Intelligence
RSS_FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "TheHackerNews": "https://feeds.feedburner.com/TheHackersNews",
    "Threatpost": "https://threatpost.com/feed/"
}

def fetch_and_save_news():
    """Parses live cybersecurity RSS feeds and streams fresh articles to Supabase."""
    print("⏳ Initializing cybersecurity news scraping engine...")
    articles_inserted = 0
    
    # 2. Open a standard connection thread compatible with transaction pooling
    with engine.connect() as connection:
        for source_name, url in RSS_FEEDS.items():
            print(f"📡 Scanning stream feed from: {source_name}...")
            try:
                feed = feedparser.parse(url)
                
                # Removed explicit trans.begin() blocks to rely entirely on autocommit pooling
                for entry in feed.entries[:15]:  # Capture the top 15 trending stories per feed
                    title = entry.get("title")
                    link = entry.get("link")
                    summary = entry.get("summary", entry.get("description", "No summary available."))
                    
                    # Clean up html tags inside summary if any exist
                    if "<" in summary:
                        summary = summary.split("<")[0].strip() or "Click source link to read full disclosure."

                    # Parse publication timestamps cleanly
                    published_parsed = entry.get("published_parsed")
                    if published_parsed:
                        published_at = datetime.fromtimestamp(mktime(published_parsed), timezone.utc)
                    else:
                        published_at = datetime.now(timezone.utc)

                    # Match the column precisely to your schema: content_snippet
                    query = text("""
                        INSERT INTO news_articles (title, source_name, source_type, url, published_at, content_snippet)
                        VALUES (:title, :source, 'RSS_FEED', :url, :pub, :summary)
                        ON CONFLICT (url) DO NOTHING;
                    """)
                    
                    result = connection.execute(query, {
                        "title": title,
                        "source": source_name,
                        "url": link,
                        "pub": published_at,
                        "summary": summary[:500] # Safe text length clipping
                    })
                    
                    if result.rowcount > 0:
                        articles_inserted += 1
                        
            except Exception as e:
                print(f"❌ Failed to process feed stream for {source_name}: {e}")
                
    print(f"🚀 Success! {articles_inserted} brand new security articles streamed into 'news_articles'.")

if __name__ == "__main__":
    # This block only runs if you execute THIS file directly!
    fetch_and_save_news()