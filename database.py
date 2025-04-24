# database.py
"""
Database connection setup using SQLAlchemy.

Handles loading the DATABASE_URL from the environment, creating the
SQLAlchemy engine and session factory, providing the declarative Base
for models, and defining the `get_db` dependency for FastAPI routes.
"""

import os
import logging
from urllib.parse import urlparse # For safe URL logging

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# --- Logging Setup ---
# Configure logging early. You might configure this more globally in your app setup.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__) # Get a logger specific to this module

# --- Environment Variable Loading ---
# Construct the absolute path to the .env file relative to this script
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')

if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
    log.info(f"Successfully loaded environment variables from: {dotenv_path}")
else:
    log.warning(f".env file not found at: {dotenv_path}. Relying on OS environment variables.")

# --- Database URL Configuration ---
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    log.critical("FATAL ERROR: DATABASE_URL environment variable is not set.")
    # Stop the application from starting without a database connection string
    raise ValueError("DATABASE_URL environment variable is required but not found.")
else:
    # Log the database URL safely (masking the password)
    try:
        parsed_url = urlparse(DATABASE_URL)
        # Reconstruct URL masking the password, include query params like sslmode
        safe_url = f"{parsed_url.scheme}://{parsed_url.username}:***@{parsed_url.hostname}"
        if parsed_url.port:
            safe_url += f":{parsed_url.port}"
        safe_url += f"{parsed_url.path}"
        if parsed_url.query:
            safe_url += f"?{parsed_url.query}"

        log.info(f"Database URL loaded (Password Masked): {safe_url}")
    except Exception as parse_error:
        log.error(f"Could not parse DATABASE_URL for safe logging: {parse_error}")
        log.info("Database URL loaded from environment (unable to mask).")


# --- SQLAlchemy Engine Creation ---
try:
    # Create the SQLAlchemy engine using the DATABASE_URL
    # Neon typically requires sslmode=require, ensure it's in your DATABASE_URL string
    engine = create_engine(
        DATABASE_URL,
        # You can add pool options here if needed, e.g., pool_size, max_overflow
        # pool_pre_ping=True # Good option to check connections before use
    )
    # Optional: Test the connection immediately to catch configuration errors early
    # with engine.connect() as connection:
    #     log.info("Successfully connected to the database (tested during engine creation).")
    log.info("SQLAlchemy engine created successfully.")

except Exception as engine_error:
    log.critical(f"FATAL ERROR: Failed to create SQLAlchemy engine: {engine_error}", exc_info=True)
    # Stop the application if the engine cannot be created
    raise RuntimeError(f"Could not create database engine: {engine_error}") from engine_error


# --- SQLAlchemy Session Factory ---
# Create a configured "Session" class. Instances of this class will be actual database sessions.
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
log.info("SQLAlchemy SessionLocal factory configured.")


# --- SQLAlchemy Declarative Base ---
# Create a Base class for declarative class definitions (used in models.py)
Base = declarative_base()
log.info("SQLAlchemy declarative_base created.")


# --- FastAPI Dependency for Database Sessions ---
def get_db():
    """
    FastAPI dependency that provides a SQLAlchemy database session.

    Creates a new session for each request, yields it to the endpoint,
    and ensures it's closed afterwards, even if errors occur.
    """
    db = SessionLocal()
    log.debug(f"Database session created: {db}")
    try:
        yield db # Provide the session to the route handler
    # Optional: Catch specific exceptions here if needed for rollback logic,
    # although often rollbacks are handled within the endpoint try/except blocks.
    # except Exception:
    #     db.rollback() # Example: Rollback on any exception within the 'yield' block
    #     raise
    finally:
        log.debug(f"Closing database session: {db}")
        db.close() # Ensure the session is always closed

log.info("Database components (engine, SessionLocal, Base, get_db) initialized.")