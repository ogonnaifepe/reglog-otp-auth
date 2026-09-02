from fastapi import APIRouter, HTTPException, status, Depends, Header
from app.schemas import (
    RegistrationRequest, 
    LoginRequest, 
    OTPVerifyRequest,
    TokenResponse,
    MessageResponse,
    RefreshTokenRequest
)
from app.database import db
from app.auth import AuthService
from app.otp import OTPService
from app.config import Config
import oracledb
from datetime import datetime

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

# Helper function to get current user
def get_current_user(authorization: str = Header(None)):
    """
    Extract and validate user from short-lived access token
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required"
        )
    
    try:
        token = authorization.replace("Bearer ", "")
        
        payload = AuthService.decode_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired access token"
            )
        
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        if AuthService.is_token_blacklisted(token, "access"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )
        
        email = payload.get("sub")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )
        
        return email
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}"
        )

# 1. TOKEN GENERATION ENDPOINT - Get new access token
@router.post("/token", response_model=dict)
async def generate_token(request: LoginRequest):
    """
    Generate a SHORT-LIVED access token and LONG-LIVED refresh token
    """
    try:
        query = "SELECT id, email, password_hash, is_verified FROM users WHERE email = :1"
        user = db.fetch_one(query, (request.email,))
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        user_id, email, password_hash, is_verified = user
        
        if not AuthService.verify_password(request.password, password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        if is_verified == 'N':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email not verified. Please verify your email first."
            )
        
        access_token = AuthService.create_access_token({"sub": email})
        refresh_token = AuthService.create_refresh_token({"sub": email})
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": email,
            "expires_in": Config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_expires_in": Config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            "message": "Tokens generated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token generation failed: {str(e)}"
        )

# 2. REFRESH TOKEN ENDPOINT
@router.post("/refresh", response_model=dict)
async def refresh_token(request: RefreshTokenRequest):
    """
    Get a new short-lived access token using a refresh token
    """
    try:
        result = AuthService.refresh_access_token(request.refresh_token)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        return {
            "access_token": result["access_token"],
            "token_type": result["token_type"],
            "email": result["email"],
            "expires_in": result["expires_in"],
            "message": "Access token refreshed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token refresh failed: {str(e)}"
        )

# 3. REGISTER
@router.post("/register", response_model=MessageResponse)
async def register(request: RegistrationRequest):
    """
    Register a new user
    """
    try:
        check_query = "SELECT id FROM users WHERE email = :1"
        existing = db.fetch_one(check_query, (request.email,))
        
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        hashed_password = AuthService.hash_password(request.password)
        
        insert_query = """
            INSERT INTO users (email, password_hash, is_verified)
            VALUES (:1, :2, 'N')
            RETURNING id INTO :3
        """
        
        cursor = db.connection.cursor()
        id_var = cursor.var(oracledb.NUMBER)
        cursor.execute(insert_query, (request.email, hashed_password, id_var))
        db.connection.commit()
        cursor.close()
        
        otp_code = OTPService.generate_otp()
        OTPService.store_otp(request.email, otp_code, 'registration')
        email_sent = OTPService.send_email(request.email, otp_code, 'registration')
        
        if not email_sent:
            delete_query = "DELETE FROM users WHERE email = :1"
            db.execute_query(delete_query, (request.email,))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send OTP email. Registration cancelled."
            )
        
        return {
            "message": "Registration successful. Please verify your email with OTP to get access tokens.",
            "success": True,
            "data": {"email": request.email}
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

# 4. VERIFY OTP - Now returns tokens
@router.post("/verify-otp", response_model=dict)
async def verify_otp(request: OTPVerifyRequest):
    """
    Verify OTP for registration - returns tokens after verification
    """
    try:
        is_valid, message = OTPService.verify_otp(
            request.email, 
            request.otp_code, 
            'registration'
        )
        
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        check_query = "SELECT id, is_verified FROM users WHERE email = :1"
        result = db.fetch_one(check_query, (request.email,))
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user_id, is_verified = result
        
        if is_verified == 'N':
            update_query = "UPDATE users SET is_verified = 'Y' WHERE email = :1"
            db.execute_query(update_query, (request.email,))
        
        access_token = AuthService.create_access_token({"sub": request.email})
        refresh_token = AuthService.create_refresh_token({"sub": request.email})
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": request.email,
            "is_verified": True,
            "expires_in": Config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_expires_in": Config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            "message": "Email verified and tokens generated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OTP verification failed: {str(e)}"
        )

# 5. LOGIN
@router.post("/login", response_model=MessageResponse)
async def login(request: LoginRequest):
    """
    Login user - sends OTP for verification
    """
    try:
        query = "SELECT id, email, password_hash, is_verified FROM users WHERE email = :1"
        user = db.fetch_one(query, (request.email,))
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        user_id, email, password_hash, is_verified = user
        
        if not AuthService.verify_password(request.password, password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        if is_verified == 'N':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email not verified. Please verify your email first."
            )
        
        otp_code = OTPService.generate_otp()
        OTPService.store_otp(email, otp_code, 'login')
        email_sent = OTPService.send_email(email, otp_code, 'login')
        
        if not email_sent:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send OTP email"
            )
        
        return {
            "message": "Login successful. OTP sent to your email. Verify to get access tokens.",
            "success": True,
            "data": {"email": email}
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

# 6. VERIFY LOGIN OTP - Returns tokens
@router.post("/verify-login-otp", response_model=dict)
async def verify_login_otp(request: OTPVerifyRequest):
    """
    Verify OTP for login - returns tokens
    """
    try:
        is_valid, message = OTPService.verify_otp(
            request.email, 
            request.otp_code, 
            'login'
        )
        
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        query = "SELECT is_verified FROM users WHERE email = :1"
        result = db.fetch_one(query, (request.email,))
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        is_verified = result[0]
        
        access_token = AuthService.create_access_token({"sub": request.email})
        refresh_token = AuthService.create_refresh_token({"sub": request.email})
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": request.email,
            "is_verified": is_verified == 'Y',
            "expires_in": Config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_expires_in": Config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            "message": "Login verified and tokens generated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login OTP verification failed: {str(e)}"
        )

# 7. LOGOUT
@router.post("/logout", response_model=MessageResponse)
async def logout(
    authorization: str = Header(None),
    refresh_token: str = None
):
    """
    Logout by blacklisting both access and refresh tokens
    """
    try:
        email = None
        
        if authorization:
            token = authorization.replace("Bearer ", "")
            payload = AuthService.decode_token(token)
            
            if payload:
                email = payload.get("sub")
                expires_at = datetime.fromtimestamp(payload.get("exp"))
                
                query = """
                    INSERT INTO access_token_blacklist (token, email, expires_at)
                    VALUES (:1, :2, :3)
                """
                db.execute_query(query, (token, email, expires_at))
        
        if refresh_token:
            payload = AuthService.decode_token(refresh_token)
            if payload:
                email = payload.get("sub") or email
                expires_at = datetime.fromtimestamp(payload.get("exp"))
                
                query = """
                    INSERT INTO refresh_token_blacklist (token, email, expires_at)
                    VALUES (:1, :2, :3)
                """
                db.execute_query(query, (refresh_token, email, expires_at))
        
        return {
            "message": f"Logged out successfully",
            "success": True,
            "data": {"email": email or "unknown"}
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}"
        )

# 8. PROTECTED ROUTE EXAMPLE
@router.get("/profile", response_model=dict)
async def get_profile(current_user: str = Depends(get_current_user)):
    """
    Get user profile - requires valid access token
    """
    try:
        query = "SELECT id, email, is_verified, created_at FROM users WHERE email = :1"
        user = db.fetch_one(query, (current_user,))
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user_id, email, is_verified, created_at = user
        
        return {
            "id": user_id,
            "email": email,
            "is_verified": is_verified == 'Y',
            "created_at": str(created_at)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get profile: {str(e)}"
        )