import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    # Local dev fallback (adjust as needed)
    DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/produce_app"
    logger.warning("DATABASE_URL not set; using local fallback")

# CRITICAL: Render's PostgreSQL uses 'postgres://' but SQLAlchemy 1.4+ needs 'postgresql://'
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    logger.info("Converted postgres:// to postgresql:// in DATABASE_URL")

# Add SSL mode for Render compatibility
if "sslmode" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL + "?sslmode=require"
    logger.info("Added sslmode=require to DATABASE_URL")

logger.info("Initializing database engine with StaticPool")

# Connection timeout in seconds; can be overridden via DB_CONNECT_TIMEOUT env var.
DB_CONNECT_TIMEOUT = int(os.getenv("DB_CONNECT_TIMEOUT", "5"))

# StaticPool reuses a single connection across all requests, keeping overhead
# low on Render's free-tier PostgreSQL which has a tight connection limit.
engine = create_engine(
    DATABASE_URL,
    poolclass=StaticPool,
    connect_args={"connect_timeout": DB_CONNECT_TIMEOUT},
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        logger.exception("Unhandled error in database session")
        raise
    finally:
        db.close()