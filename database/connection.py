import os
from sqlalchemy import create_engine
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

# Complete PgBouncer/Supabase optimization configuration suite
engine = create_engine(
    DATABASE_URL,
    execution_options={"isolation_level": "AUTOCOMMIT"},
    # This disables prepared statement compilation at the driver level:
    connect_args={"prepare_threshold": None}, 
    pool_pre_ping=True
)