# backend/main.py

import random
import logging
import os
import requests
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict
otp_store = {}


from fastapi import FastAPI, HTTPException, Depends, status, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

# --- Project Imports ---
from database import get_db, engine # Engine needed for create_all
import models
from models import Farmer as FarmerDB # Alias for Farmer model
from models import AdminUser as AdminUserDB # Alias for Admin model
import schemas
import auth_utils # Contains hashing, JWT, dependencies

log = logging.getLogger(__name__)

# --- Create DB Tables ---
try:
    log.info("Attempting to create database tables based on models...")
    # This will create both 'farmers' and 'admin_users' if they don't exist
    models.Base.metadata.create_all(bind=engine)
    log.info("Database tables checked/created successfully.")
except Exception as e:
    log.critical(f"FATAL ERROR creating database tables: {e}", exc_info=True)
    raise SystemExit("Database table creation failed.")

# --- FastAPI Application Setup ---
app = FastAPI(
    title="Kisan Manch API",
    description="API for Kisan Manch Farmer (OTP Login) and Admin (Password Login).",
    version="1.3.1" # Consistent version
)

# --- CORS Middleware ---
allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,https://kisan-manch.vercel.app")
allowed_origins = [origin.strip() for origin in allowed_origins_str.split(',') if origin.strip()]
if not allowed_origins: allowed_origins = ["http://localhost:3000,https://kisan-manch.vercel.app"]
log.info(f"Configuring CORS for origins: {allowed_origins}")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Configuration & OTP Store ---
def send_otp(number, otp):
    if not TWOFACTOR_API_KEY:
        log.error("No API key provided — can't send OTP.")
        return

    url = f"https://2factor.in/API/V1/{TWOFACTOR_API_KEY}/SMS/{number}/{otp}/AUTOGEN"
    try:
        response = requests.get(url)
        response.raise_for_status()
        log.info(f"2Factor response: {response.text}")
    except Exception as e:
        log.error(f"Failed to send OTP via 2Factor: {e}")

# --- Helper Functions ---
def generate_farmer_id() -> str:
    """Generates a unique farmer ID (simple version)."""
    timestamp_part = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    random_part = random.randint(1000, 9999)
    return f"KM{timestamp_part}{random_part}"

# --- API Endpoints ---

# --- Health Check ---
@app.get("/health", tags=["System"], status_code=status.HTTP_200_OK)
async def health_check():
    # Add DB check here for better health indication
    try:
        db : Session = next(get_db())
        db.execute(models.text("SELECT 1")) # Use models.text or import text from sqlalchemy
        return {"status": "healthy", "db_connection": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
    except Exception as db_err:
         log.error(f"Health check DB connection failed: {db_err}")
         return {"status": "unhealthy", "db_connection": "failed", "timestamp": datetime.now(timezone.utc).isoformat()}
    finally:
         if 'db' in locals() and db: db.close()


# --- Shared OTP Endpoint ---
@app.post("/send-otp", response_model=schemas.SuccessResponse, tags=["OTP"], status_code=status.HTTP_200_OK)
async def send_otp_route(data: schemas.Phone):
    """Generates and attempts to send OTP via 2Factor for Registration OR Login."""
    mobile_number = data.mobile_number
    log.info(f"Received /send-otp request for number: {mobile_number[-4:]}")
    otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    otp_store[mobile_number] = otp # Store temporarily
    log.info(f"Stored OTP for {mobile_number[-4:]}: {otp}") # Log OTP only in dev/debug

    if not TWOFACTOR_API_KEY:
        log.warning(f"Simulating OTP send for {mobile_number[-4:]} (API Key missing).")
    else:
        try:
            # IMPORTANT: Replace 'YourAppNameTemplate' with your actual 2Factor template name if required
            url = f"https://2factor.in/API/V1/{TWOFACTOR_API_KEY}/SMS/{mobile_number}/{otp}/YourAppNameTemplate"
            log.info(f"Sending OTP via 2Factor to {mobile_number[-4:]}...")
            # --- UNCOMMENT FOR ACTUAL SENDING ---
            # response = requests.get(url, timeout=10);
            # response.raise_for_status()
            # response_json = response.json()
            # log.info(f"2Factor Response: {response_json}")
            # if response_json.get("Status") != "Success":
            #     log.error(f"2Factor Failure: {response_json.get('Details', 'Unknown error')}")
            # --- END UNCOMMENT ---
            log.info("Simulated successful 2Factor call (API key present).") # Remove/comment this line when uncommenting above
        except Exception as e:
            log.error(f"Error sending OTP via 2Factor: {e}", exc_info=True)

    # Return success as OTP is stored locally for testing/fallback
    return {"Status": "Success", "Details": f"OTP process initiated for {mobile_number[-4:]}"}


# --- Farmer Registration ---
@app.post(
    "/api/register",
    response_model=schemas.RegisterSuccessResponse,
    tags=["Farmer Auth & Registration"],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new farmer (passwordless)"
)
async def register_farmer_endpoint(data: schemas.FarmerCreate, db: Session = Depends(get_db)):
    mobile_number = data.mobile
    submitted_otp = data.otp
    log.info(f"Registration attempt for mobile: {mobile_number[-4:]}")

    # Verify OTP
    stored_otp = otp_store.get(mobile_number)
    if not stored_otp or stored_otp != submitted_otp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP.")

    # Check existing Farmer
    existing = db.query(FarmerDB).filter(FarmerDB.mobile_number == mobile_number).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Mobile number already registered.")

    # Generate ID
    farmer_id = generate_farmer_id()

    # Prepare and Store Data
    try:
        db_farmer_data = {
            "id": farmer_id,
            "full_name": data.fullName,
            "mobile_number": data.mobile,
            "aadhaar_number": data.aadhaarNumber,
            "crop_type": data.cropType,
            "village": data.village,
            "district": data.district,
            "state": data.state,
            "pin_code": data.pinCode,
            "cultivation_unit": data.cultivationUnit,
            "approximate_produce": data.approximateProduce,
            "geo_location": data.geoLocation,
            # status and role will use DB defaults
        }
        # Handle cultivation_area conversion
        if data.cultivationArea:
             try: db_farmer_data["cultivation_area"] = float(data.cultivationArea)
             except (ValueError, TypeError): db_farmer_data["cultivation_area"] = None
        else: db_farmer_data["cultivation_area"] = None

        db_farmer = FarmerDB(**db_farmer_data)
        db.add(db_farmer)
        db.commit()
        db.refresh(db_farmer)
        log.info(f"Successfully registered farmer: {farmer_id}")
        if mobile_number in otp_store: del otp_store[mobile_number] # Clean up OTP
        return {"success": True, "farmer_id": farmer_id}

    except IntegrityError:
         db.rollback()
         log.warning(f"Integrity error (likely duplicate mobile/aadhaar) for {mobile_number[-4:]}")
         raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A user with this mobile number or Aadhaar number already exists.")
    except Exception as e:
         db.rollback()
         log.error(f"Error during farmer registration for {mobile_number[-4:]}: {e}", exc_info=True)
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Registration failed due to a server error.")


# --- Farmer Login (OTP Verification) ---
@app.post(
    "/api/login/verify-otp",
    response_model=schemas.FarmerProfile,
    tags=["Farmer Auth & Registration"],
    summary="Verify OTP for farmer login and set auth cookie"
)
async def login_verify_otp(response: Response, login_data: schemas.FarmerOtpLogin, db: Session = Depends(get_db)):
    mobile_number = login_data.mobile
    submitted_otp = login_data.otp
    log.info(f"Farmer login OTP verification attempt for: {mobile_number[-4:]}")

    # Verify OTP
    stored_otp = otp_store.get(mobile_number)
    if not stored_otp or stored_otp != submitted_otp:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired OTP provided.")
    log.info(f"Login OTP verified for {mobile_number[-4:]}")

    # Find User
    user = db.query(FarmerDB).filter(FarmerDB.mobile_number == mobile_number).first()
    if not user:
        if mobile_number in otp_store: del otp_store[mobile_number] # Clean invalid OTP
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mobile number not registered.")

    # Create JWT & Cookie
    expires = timedelta(minutes=auth_utils.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = auth_utils.create_access_token(data={"sub": user.mobile_number, "type": "farmer"}, expires_delta=expires)
    response.set_cookie(
        key=auth_utils.AUTH_COOKIE_NAME, value=token,
        httponly=True, max_age=int(expires.total_seconds()),
        expires=int(expires.total_seconds()), path="/",
        samesite="lax", secure=False # TODO: Set secure=True in production HTTPS
    )

    # Clean up OTP
    if mobile_number in otp_store: del otp_store[mobile_number]

    log.info(f"Farmer login successful: {user.id}")
    return user # Return farmer profile


# --- Get Current Farmer Profile ---
@app.get(
    "/api/users/me",
    response_model=schemas.FarmerProfile,
    tags=["Farmer Profile"],
    summary="Get profile of the currently authenticated farmer"
)
async def read_users_me(current_user: models.Farmer = Depends(auth_utils.get_current_farmer_user)):
     # Dependency handles auth check and fetching
     log.info(f"Returning profile for farmer: {current_user.id}")
     return current_user


# --- Admin Login ---
@app.post(
    "/api/admin/login",
    response_model=schemas.AdminProfile,
    tags=["Admin Auth"],
    summary="Login admin user with email/password and set auth cookie"
)
async def admin_login(response: Response, form_data: schemas.AdminLogin, db: Session = Depends(get_db)):
    log.info(f"Admin login attempt for email: {form_data.email}")
    admin_user = db.query(AdminUserDB).filter(AdminUserDB.email == form_data.email).first()

    # Verify user exists and password is correct
    if not admin_user or not auth_utils.verify_password(form_data.password, admin_user.hashed_password):
        log.warning(f"Admin login failed for email: {form_data.email} - Invalid credentials.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    # Create JWT & Cookie
    expires = timedelta(minutes=auth_utils.ACCESS_TOKEN_EXPIRE_MINUTES) # Consider longer session for admins?
    token = auth_utils.create_access_token(data={"sub": admin_user.email, "type": "admin"}, expires_delta=expires)
    response.set_cookie(
        key=auth_utils.AUTH_COOKIE_NAME, value=token,
        httponly=True, max_age=int(expires.total_seconds()),
        expires=int(expires.total_seconds()), path="/",
        samesite="lax", secure=False # TODO: Set secure=True in production HTTPS
    )

    # Optional: Update last login timestamp
    try:
        admin_user.last_login_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as e:
        db.rollback()
        log.error(f"Failed to update last_login_at for admin {admin_user.email}: {e}")

    log.info(f"Admin login successful: {admin_user.email}")
    return admin_user # Return admin profile


# --- Get Current Admin Profile ---
@app.get(
    "/api/admin/me",
    response_model=schemas.AdminProfile,
    tags=["Admin Profile"],
    summary="Get profile of the currently authenticated admin"
)
async def read_admin_me(current_admin: models.AdminUser = Depends(auth_utils.get_current_admin_user)):
     # Dependency handles auth check and fetching admin
     log.info(f"Returning profile for admin: {current_admin.email}")
     return current_admin


# --- Generic Logout ---
@app.post(
    "/api/logout",
    status_code=status.HTTP_200_OK,
    tags=["Authentication"], # Changed tag slightly
    summary="Logout user/admin by clearing the auth cookie"
)
async def logout(response: Response):
    log.info("Logout request received, clearing auth cookie.")
    # Clear the cookie by setting its max_age to 0
    response.delete_cookie(
        key=auth_utils.AUTH_COOKIE_NAME,
        path="/",
        # domain="yourdomain.com" # Add domain if set during login
    )
    return {"message": "Logout successful"}


# --- Run Application ---
if __name__ == "__main__":
    import uvicorn
    # Load config from environment variables
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "0.0.0.0")
    reload_flag = os.getenv("UVICORN_RELOAD", "true").lower() == "true"
    log_level = os.getenv("UVICORN_LOG_LEVEL", "info").lower()

    log.info(f"Starting Uvicorn Server on http://{host}:{port}")
    log.info(f"Reloading enabled: {reload_flag}")
    log.info(f"Log level: {log_level}")

    uvicorn.run(
        "main:app", # Point to the FastAPI app instance in this file
        host=host,
        port=port,
        reload=reload_flag,
        log_level=log_level
    )
