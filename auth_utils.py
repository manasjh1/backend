# backend/auth_utils.py
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Any, Literal

from jose import JWTError, jwt
from passlib.context import CryptContext # Needed for Admin password
from pydantic import ValidationError # For token data validation
from fastapi import Depends, HTTPException, status, Request, Response, Cookie # Response not usually needed here

# Project imports
import schemas
import models
from database import get_db
from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

# --- Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60)) # Default 1 hour
AUTH_COOKIE_NAME = "farm_auth_token" # Cookie name used for both user types

if not SECRET_KEY:
    log.critical("FATAL ERROR: SECRET_KEY environment variable is not set for JWT.")
    raise ValueError("SECRET_KEY is required for JWT.")

# --- Password Hashing Setup (For Admins) ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a stored hash."""
    # Check if hashed_password is None or empty, which might happen
    # if trying to verify against a non-existent hash (shouldn't happen in normal flow)
    if not hashed_password:
        return False
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    """Hashes a plain password using bcrypt."""
    return pwd_context.hash(password)

# --- JWT Token Creation ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a JWT access token. Expects 'sub' and 'type' in data."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    # Ensure required fields are present before encoding
    if "sub" not in to_encode or "type" not in to_encode:
         log.error("JWT creation failed: 'sub' or 'type' missing in payload data.")
         raise ValueError("Token data must include 'sub' and 'type'")

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    log.debug(f"Created JWT for sub='{to_encode.get('sub')}', type='{to_encode.get('type')}'")
    return encoded_jwt

# --- Token Decoding Helper ---
def _decode_token_payload(token: str) -> dict:
    """Decodes JWT, raises HTTPException on failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Validate expected fields are present
        token_data = schemas.TokenData(**payload) # Use Pydantic for validation
        if token_data.sub is None or token_data.type is None:
             log.warning("Token payload missing 'sub' or 'type'.")
             raise credentials_exception
        return payload
    except JWTError as e:
        log.warning(f"JWT decoding/validation error: {e}")
        raise credentials_exception from e
    except ValidationError as e: # Pydantic validation error
        log.warning(f"Token payload structure error: {e}")
        raise credentials_exception from e
    except Exception as e: # Catch unexpected errors
         log.error(f"Unexpected error decoding token: {e}", exc_info=True)
         raise credentials_exception from e


# --- Dependency: Get Current FARMER User ---
async def get_current_farmer_user(
    db: Session = Depends(get_db),
    token: Optional[str] = Cookie(None, alias=AUTH_COOKIE_NAME)
) -> models.Farmer:
    """Dependency: Gets the current FARMER user from the auth cookie."""
    if token is None:
        log.debug("Auth cookie missing for farmer user request.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = _decode_token_payload(token)
    user_type = payload.get("type")
    mobile_number = payload.get("sub") # Expecting mobile number for farmers

    if user_type != "farmer":
        log.warning(f"Invalid token type for farmer endpoint. Type: {user_type}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Incorrect user type for this operation")
    if not mobile_number: # Should be caught by _decode, but double check
         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload (missing subject)")


    user = db.query(models.Farmer).filter(models.Farmer.mobile_number == mobile_number).first()
    if user is None:
        log.warning(f"Farmer user '{mobile_number}' from token not found.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User associated with token no longer exists")

    log.debug(f"Authenticated farmer retrieved: {user.id}")
    return user

# --- Dependency: Get Current ADMIN User ---
async def get_current_admin_user(
    db: Session = Depends(get_db),
    token: Optional[str] = Cookie(None, alias=AUTH_COOKIE_NAME) # Using same cookie
) -> models.AdminUser:
    """Dependency: Gets the current ADMIN user from the auth cookie."""
    if token is None:
        log.debug("Auth cookie missing for admin user request.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = _decode_token_payload(token)
    user_type = payload.get("type")
    email = payload.get("sub") # Expecting email for admins

    if user_type != "admin":
        log.warning(f"Invalid token type for admin endpoint. Type: {user_type}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operation not allowed for this user type")
    if not email: # Should be caught by _decode, but double check
         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload (missing subject)")


    admin = db.query(models.AdminUser).filter(models.AdminUser.email == email).first()
    if admin is None:
        log.warning(f"Admin user '{email}' from token not found.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin user associated with token no longer exists")

    log.debug(f"Authenticated admin retrieved: {admin.id}")
    return admin