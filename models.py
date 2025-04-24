# models.py
"""
SQLAlchemy ORM Models for the Kisan Manch application.

Defines the database table structures for Farmers and Admin Users.
"""

import logging
from datetime import datetime
from sqlalchemy import (
    Column, String, DateTime, func, JSON, Numeric,
    UniqueConstraint # Can be used for table args if needed
)
# If you decide to use Integer IDs for Admin later:
# from sqlalchemy import Integer
from sqlalchemy.dialects.postgresql import UUID # If using UUID IDs later

# Import the Base from the central database configuration file
from database import Base

# Get a logger for this module
log = logging.getLogger(__name__)

# --- Farmer Model (Passwordless, OTP Login) ---
class Farmer(Base):
    """Represents a farmer user in the database."""
    __tablename__ = 'farmers'

    # Core identifier and contact
    id = Column(String, primary_key=True, index=True, comment="Unique KM... generated ID")
    full_name = Column(String(100), index=True, nullable=False, comment="Farmer's full name")
    mobile_number = Column(String(15), unique=True, index=True, nullable=False, comment="Registered mobile number (used for OTP login)")

    # Optional identification and details
    aadhaar_number = Column(String(12), unique=True, index=True, nullable=True, comment="Aadhaar number (optional, unique if provided)")
    crop_type = Column(String(50), nullable=True, comment="Primary crop grown by the farmer")
    village = Column(String(100), nullable=True, comment="Farmer's village/town")
    district = Column(String(100), nullable=True, comment="Farmer's district")
    state = Column(String(50), nullable=True, comment="Farmer's state")
    pin_code = Column(String(10), nullable=True, comment="Farmer's postal code")

    # Cultivation details
    cultivation_area = Column(Numeric(10, 2), nullable=True, comment="Area under cultivation")
    cultivation_unit = Column(String(20), nullable=True, comment="Unit for cultivation area (e.g., acre, bigha, hectare)")
    approximate_produce = Column(String(100), nullable=True, comment="Estimated annual produce quantity")
    geo_location = Column(JSON, nullable=True, comment="Geo-coordinates (latitude, longitude) as JSON")

    # Application specific fields
    status = Column(String(20), nullable=True, default="Pending", comment="Account status (e.g., Pending, Active, Suspended)")
    role = Column(String(20), nullable=True, default="farmer", comment="User role (primarily 'farmer')")

    # Timestamps
    registered_at = Column(DateTime(timezone=True), server_default=func.now(), comment="Timestamp when the farmer registered")
    # Add updated_at if needed for tracking modifications
    # updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Optional: Define constraints explicitly if not relying solely on unique=True
    # __table_args__ = (
    #     UniqueConstraint('mobile_number', name='uq_farmer_mobile'),
    #     UniqueConstraint('aadhaar_number', name='uq_farmer_aadhaar'),
    # )

    def __repr__(self):
        """String representation for debugging."""
        return f"<Farmer(id={self.id}, name='{self.full_name}', mobile='{self.mobile_number}')>"

log.info("SQLAlchemy 'Farmer' model defined (Passwordless).")


# --- Admin User Model (Email/Password Login) ---
class AdminUser(Base):
    """Represents an administrative user in the database."""
    __tablename__ = 'admin_users'

    # Using String ID for consistency, but Integer primary key is also common for admins
    # id = Column(Integer, primary_key=True) # Example if using Integer ID
    id = Column(String, primary_key=True, index=True, comment="Unique ID for admin user (can be generated)")
    email = Column(String(255), unique=True, index=True, nullable=False, comment="Admin's login email address")
    hashed_password = Column(String, nullable=False, comment="Securely hashed password for the admin")
    full_name = Column(String(100), nullable=True, comment="Admin's full name (optional)")
    role = Column(String(50), nullable=False, default='admin', comment="Admin role identifier (e.g., 'admin', 'superadmin')")

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), comment="Timestamp when the admin was created")
    last_login_at = Column(DateTime(timezone=True), nullable=True, comment="Timestamp of the admin's last successful login")

    def __repr__(self):
        """String representation for debugging."""
        return f"<AdminUser(id={self.id}, email='{self.email}', role='{self.role}')>"

log.info("SQLAlchemy 'AdminUser' model defined.")

# --- End of models.py ---