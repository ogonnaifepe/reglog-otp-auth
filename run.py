import uvicorn
from app.config import Config
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logger.info(f"Starting application on {Config.APP_HOST}:{Config.APP_PORT}")
    logger.info(f"Debug mode: {Config.DEBUG}")
    
    uvicorn.run(
        "app.main:app",
        host=Config.APP_HOST,
        port=Config.APP_PORT,
        reload=Config.DEBUG,
        log_level="info"
    )