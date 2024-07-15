import logging
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Log current working directory and Python path
logger.info(f"Current working directory: {os.getcwd()}")
logger.info(f"Python path: {sys.path}")

# Test import
try:
    from app.config import settings
    logger.info("Import successful!")
except ModuleNotFoundError as e:
    logger.error(f"Error importing module: {e}")
