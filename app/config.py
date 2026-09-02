import os
from dotenv import load_dotenv
import re
import logging

load_dotenv()
logger = logging.getLogger(__name__)

class Config:
    # Database
    DATABASE_URL = os.getenv("DATABASE_URL")
    
    @classmethod
    def get_connection_params(cls):
        """
        Parse DATABASE_URL and return connection parameters
        """
        if not cls.DATABASE_URL:
            raise ValueError("DATABASE_URL not set in environment")
        
        # Remove oracle:// prefix if present
        url = cls.DATABASE_URL.replace('oracle://', '')
        
        # Try different patterns
        patterns = [
            r'^([^:]+):([^@]+)@([^:]+):(\d+)/(.+)$',
            r'^([^:]+):([^@]+)@([^:]+):(\d+)\?service_name=(.+)$',
            r'^([^:]+):([^@]+)@([^:]+):(\d+):(.+)$',
        ]
        
        for pattern in patterns:
            match = re.match(pattern, url)
            if match:
                groups = match.groups()
                if len(groups) == 5:
                    username, password, host, port, service = groups
                    logger.info(f"Parsed connection: user={username}, host={host}, port={port}, service={service}")
                    return {
                        'user': username,
                        'password': password,
                        'host': host,
                        'port': int(port),
                        'service_name': service
                    }
        
        logger.warning("Could not parse URL, using as DSN")
        return {'dsn': url}
    
    @classmethod
    def get_oracle_dsn(cls):
        params = cls.get_connection_params()
        if 'dsn' in params:
            return params['dsn']
        return f"{params['host']}:{params['port']}/{params['service_name']}"
    
    # JWT - Access Token
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 5))
    
    # JWT - Refresh Token (NEW)
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))
    
    # OTP
    OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", 5))
    
    # Email
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    
    # Application
    APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT = int(os.getenv("APP_PORT", 8000))
    DEBUG = os.getenv("DEBUG", "True").lower() == "true"