"""
Module: config.py
Purpose: Load environment variables from .env file
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

ENV_LOADED = False


def load_env():
    """Load .env file if not already loaded."""
    global ENV_LOADED
    
    if ENV_LOADED:
        return
    
    if DOTENV_AVAILABLE:
        env_path = Path(__file__).parent.parent / '.env'
        load_dotenv(env_path)
    
    ENV_LOADED = True


def get_env(key: str, default: str = None) -> str:
    """
    Get environment variable.
    
    Priority:
    1. .env file (via env_manager - allows runtime updates)
    2. os.environ (loaded by dotenv)
    3. default value
    
    Args:
        key: Environment variable name
        default: Default value if not found
    
    Returns:
        Environment variable value or default
    """
    from utils.env_manager import read_env_file
    
    load_env()
    
    file_config = read_env_file()
    if key in file_config and file_config[key]:
        return file_config[key]
    
    return os.environ.get(key, default)


def reload_env():
    """Force reload of .env file."""
    global ENV_LOADED
    ENV_LOADED = False
    load_env()


load_env()