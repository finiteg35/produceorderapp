import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    # Local dev fallback (adjust as needed)
    DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/produce_app"

# CRITICAL: Render's PostgreSQL uses 'postgres://' but SQLAlchemy 1.4+ needs 'postgresql://'
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Add SSL mode for Render compatibility
if "sslmode" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL + "?sslmode=require"

# Use StaticPool for better Render free tier compatibility
# StaticPool reuses connections efficiently without creating new ones per request
engine = create_engine(
    DATABASE_URL,
    poolclass=StaticPool,
    connect_args={"connect_timeout": 5},
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