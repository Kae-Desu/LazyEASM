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
PROJECT_ROOT = Path(__file__).parent.parent


def get_log_dir() -> str:
    """
    Folder for the log files (created if missing): LAZYEASM_LOG_DIR, or
    logs/ in the project. The test suite points it at a temporary folder so
    test runs on a live install do not write into its logs.
    """
    path = os.environ.get('LAZYEASM_LOG_DIR') or str(PROJECT_ROOT / 'logs')
    os.makedirs(path, exist_ok=True)
    return path


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
    
    For EDITABLE_KEYS: Only reads from .env file (runtime updatable)
    For other keys: Falls back to os.environ
    
    Args:
        key: Environment variable name
        default: Default value if not found
    
    Returns:
        Environment variable value or default
    """
    from utils.env_manager import read_env_file, EDITABLE_KEYS
    
    load_env()
    
    file_config = read_env_file()
    
    if key in EDITABLE_KEYS:
        return file_config.get(key) or default
    
    if key in file_config and file_config[key]:
        return file_config[key]
    
    return os.environ.get(key, default)


def reload_env():
    """Force reload of .env file."""
    global ENV_LOADED
    ENV_LOADED = False
    load_env()


load_env()