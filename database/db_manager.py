import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Load credentials from your local .env file
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

# Force SQLAlchemy to use the new modern psycopg driver seamlessly
if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

# Set up the SQLAlchemy connection engine to talk to Supabase
engine = create_engine(DATABASE_URL)

def init_db():
    """Reads schema.sql and creates the 5 database tables on Supabase cloud."""
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    
    if not os.path.exists(schema_path):
        print(f"❌ Error: Cannot find schema.sql at {schema_path}")
        return

    with open(schema_path, 'r') as file:
        sql_script = file.read()
        
    queries = sql_script.split(';')
    
    print("⏳ Connecting to Supabase Cloud Database...")
    with engine.connect() as connection:
        trans = connection.begin()
        try:
            for query in queries:
                clean_query = query.strip()
                if clean_query:
                    connection.execute(text(clean_query))
            trans.commit()
            print("🎉 Success! All 5 tracking tables initialized on Supabase.")
        except Exception as e:
            trans.rollback()
            print(f"❌ Error building tables: {e}")

if __name__ == "__main__":
    init_db()