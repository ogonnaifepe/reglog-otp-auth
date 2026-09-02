from app.routes.auth_routes import router as auth_router
from app.routes.otp_routes import router as otp_router

__all__ = ['auth_router', 'otp_router']