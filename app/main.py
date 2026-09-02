from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth_router, otp_router
from app.config import Config
from app.database import db
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="OTP Authentication System",
    description="Complete authentication API with OTP verification",
    version="1.0.0",
    debug=Config.DEBUG
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(otp_router)

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "OTP Authentication System",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "auth": {
                "register": "POST /api/v1/auth/register",
                "verify_otp": "POST /api/v1/auth/verify-otp",
                "login": "POST /api/v1/auth/login",
                "verify_login_otp": "POST /api/v1/auth/verify-login-otp",
                "resend_otp": "POST /api/v1/auth/resend-otp"
            },
            "otp": {
                "generate": "POST /api/v1/otp/generate",
                "verify": "POST /api/v1/otp/verify",
                "resend": "POST /api/v1/otp/resend",
                "validate": "POST /api/v1/otp/validate",
                "check_verification": "GET /api/v1/otp/check-verification/{email}",
                "invalidate": "DELETE /api/v1/otp/invalidate/{email}?purpose={purpose}"
            }
        },
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc"
        }
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    try:
        # Test database connection
        cursor = db.connection.cursor()
        cursor.execute("SELECT 1 FROM DUAL")
        result = cursor.fetchone()
        cursor.close()
        db_status = "healthy"
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        db_status = "unhealthy"
    
    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "database": db_status,
        "timestamp": str(db.execute_query("SELECT CURRENT_TIMESTAMP FROM DUAL").fetchone()[0])
    }

# Shutdown event
@app.on_event("shutdown")
def shutdown_event():
    db.close()
    logger.info("Application shutdown complete")