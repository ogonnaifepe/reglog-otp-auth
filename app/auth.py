from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.config import Config
import logging
import hashlib
import uuid

logger = logging.getLogger(__name__)

# Use PBKDF2-SHA256
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)

class AuthService:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using PBKDF2-SHA256"""
        try:
            return pwd_context.hash(password)
        except Exception as e:
            logger.error(f"Password hashing error: {e}")
            salt = hashlib.sha256(b"salt").hexdigest()
            hashed = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            ).hex()
            return f"$pbkdf2-sha256$100000${salt}${hashed}"
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    @staticmethod
    def create_access_token(data: dict) -> str:
        """Create SHORT-LIVED access token (5-10 mins)"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({
            "exp": expire,
            "type": "access",
            "jti": str(uuid.uuid4())
        })
        encoded_jwt = jwt.encode(to_encode, Config.SECRET_KEY, algorithm=Config.ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def create_refresh_token(data: dict) -> str:
        """Create LONG-LIVED refresh token (7 days)"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=Config.REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({
            "exp": expire,
            "type": "refresh",
            "jti": str(uuid.uuid4())
        })
        encoded_jwt = jwt.encode(to_encode, Config.SECRET_KEY, algorithm=Config.ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def decode_token(token: str) -> dict:
        """Decode and verify a JWT token"""
        try:
            payload = jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.ALGORITHM])
            return payload
        except JWTError as e:
            logger.error(f"Token decode error: {e}")
            return None
    
    @staticmethod
    def is_token_blacklisted(token: str, token_type: str = "access") -> bool:
        """Check if a token is blacklisted"""
        from app.database import db
        
        table = "access_token_blacklist" if token_type == "access" else "refresh_token_blacklist"
        query = f"SELECT id FROM {table} WHERE token = :1"
        result = db.fetch_one(query, (token,))
        return result is not None
    
    @staticmethod
    def refresh_access_token(refresh_token: str) -> dict:
        """Generate a new short-lived access token from a valid refresh token"""
        # Decode refresh token
        payload = AuthService.decode_token(refresh_token)
        if not payload:
            return None
        
        # Check if it's a refresh token
        if payload.get("type") != "refresh":
            return None
        
        # Check if refresh token is blacklisted
        if AuthService.is_token_blacklisted(refresh_token, "refresh"):
            logger.warning(f"Attempted to use blacklisted refresh token")
            return None
        
        # Get user email
        email = payload.get("sub")
        if not email:
            return None
        
        # Create new access token
        new_access_token = AuthService.create_access_token({"sub": email})
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "email": email,
            "expires_in": Config.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }