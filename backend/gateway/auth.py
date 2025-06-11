"""
SecureFlow Authentication System

Handles JWT token generation, password hashing, and user authentication.
"""

import os
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Bearer token dependency
security = HTTPBearer()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Optional[str]:
    """Verify JWT token and return username."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except JWTError:
        return None

def get_user_by_username(db: Session, username: str):
    """Get user by username from database."""
    from .models import User
    return db.query(User).filter(User.username == username).first()

def get_user_by_id(db: Session, user_id: int):
    """Get user by ID from database."""
    from .models import User
    return db.query(User).filter(User.id == user_id).first()

def create_user(db: Session, username: str, password: str, email: str = ""):
    """Create a new user."""
    from .models import User
    
    hashed_password = get_password_hash(password)
    user = User(
        username=username,
        email=email,
        hashed_password=hashed_password,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get current authenticated user."""
    from ..scheduler.database import get_database_session
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token = credentials.credentials
    username = verify_token(token)
    if username is None:
        raise credentials_exception
    
    with get_database_session() as db:
        user = get_user_by_username(db, username)
        if user is None:
            raise credentials_exception
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )
    
    return user

def init_default_user(db: Session) -> None:
    """Initialize default admin user if no users exist."""
    from .models import User
    
    existing_user = db.query(User).first()
    if not existing_user:
        default_user = create_user(
            db=db,
            username="admin",
            password="admin123",  # Change this in production!
            email="admin@secureflow.dev"
        )
        print(f"Created default user: {default_user.username}")
        print("IMPORTANT: Change the default password in production!")
