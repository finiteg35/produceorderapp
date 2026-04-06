import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    # Local dev fallback (adjust as needed)
    DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/produce_app"

# CRITICAL: Render's PostgreSQL uses 'postgres://' but SQLAlchemy 1.4+ needs 'postgresql://'
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Add SSL mode for Render compatibility
if "sslmode" not in DATABASE_URL:
    separator = "&" if "?" in DATABASE_URL else "?"
    DATABASE_URL = DATABASE_URL + separator + "sslmode=require"

try:
    connect_timeout = int(os.getenv("DB_CONNECT_TIMEOUT", "10"))
except ValueError:
    connect_timeout = 10

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,  # recycle connections every 5 minutes to prevent silent TCP timeouts
    connect_args={"connect_timeout": connect_timeout},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()