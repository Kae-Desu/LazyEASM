"""
Module: env_manager.py
Purpose: Read/write .env file directly with validation
"""

import os
import re
from pathlib import Path
from typing import Dict, Tuple, Optional

ENV_FILE = Path(__file__).parent.parent / '.env'

EDITABLE_KEYS = [
    'DISCORD_WEBHOOK_URL',
    'DISCORD_USER_ID',
    'SECURITYTRAILS_API_KEY',
    'VULNERS_API_KEY',
    'GEMINI_API_KEY'
]

SENSITIVE_KEYS = [
    'SECURITYTRAILS_API_KEY',
    'VULNERS_API_KEY',
    'GEMINI_API_KEY'
]

KEY_DISPLAY_NAMES = {
    'DISCORD_WEBHOOK_URL': 'Discord Webhook URL',
    'DISCORD_USER_ID': 'Discord User ID',
    'SECURITYTRAILS_API_KEY': 'SecurityTrails API Key',
    'VULNERS_API_KEY': 'Vulners API Key',
    'GEMINI_API_KEY': 'Gemini API Key'
}

VALIDATION_RULES = {
    'DISCORD_WEBHOOK_URL': {
        'pattern': r'^(https://(ptb\.)?discord\.com/api/webhooks/\d+/[\w-]+)?$',
        'message': 'Invalid Discord webhook URL format (must be https://discord.com/api/webhooks/... or https://ptb.discord.com/api/webhooks/...)'
    },
    'DISCORD_USER_ID': {
        'pattern': r'^(\d+)?$',
        'message': 'Discord User ID must be numeric'
    }
}


def mask_value(value: str, visible: int = 2) -> str:
    """
    Mask sensitive value showing first and last N chars.
    
    Args:
        value: String to mask
        visible: Number of chars to show at start and end
    
    Returns:
        Masked string like "ab...yz" or "***" for short values
    """
    if not value:
        return ''
    
    if len(value) <= visible * 2:
        return '*' * len(value)
    
    return f"{value[:visible]}...{value[-visible:]}"


def mask_discord_webhook(webhook_url: str) -> str:
    """
    Mask Discord webhook URL for privacy.
    
    Input:  https://discord.com/api/webhooks/123456789/abc123...
    Output: discord.com/.../1449...4307/...mTXG
    
    Returns empty string if input is empty or invalid format.
    """
    if not webhook_url:
        return ''
    
    pattern = r'https?://(?:ptb\.)?discord\.com/api/webhooks/(\d+)/([A-Za-z0-9_-]+)'
    match = re.match(pattern, webhook_url)
    
    if match:
        webhook_id = match.group(1)
        token = match.group(2)
        
        masked_id = f"{webhook_id[:4]}...{webhook_id[-4:]}" if len(webhook_id) > 8 else webhook_id
        masked_token = f"...{token[-4:]}" if len(token) > 4 else token
        
        return f"discord.com/.../{masked_id}/{masked_token}"
    
    return mask_value(webhook_url)


def mask_discord_user_id(user_id: str) -> str:
    """
    Mask Discord user ID.
    
    Input:  1093465261627162664
    Output: 1093...6664
    """
    if not user_id:
        return ''
    
    if len(user_id) <= 8:
        return '*' * len(user_id)
    
    return f"{user_id[:4]}...{user_id[-4:]}"


def read_env_file() -> Dict[str, str]:
    """
    Parse .env file into dictionary.
    
    Returns:
        Dict of key-value pairs
    """
    config = {}
    
    if not ENV_FILE.exists():
        return config
    
    try:
        with open(ENV_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                if '=' in line:
                    key, _, value = line.partition('=')
                    config[key.strip()] = value.strip()
    except Exception as e:
        print(f"Error reading .env file: {e}")
    
    return config


def write_env_file(config: Dict[str, str]) -> bool:
    """
    Write config dictionary to .env file.
    Preserves comments and file structure.
    
    Args:
        config: Dictionary of key-value pairs (keys not in dict will be removed)
    
    Returns:
        True on success, False on failure
    """
    try:
        lines = []
        existing_keys = set(config.keys())
        
        if ENV_FILE.exists():
            with open(ENV_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    stripped = line.strip()
                    
                    if not stripped or stripped.startswith('#'):
                        lines.append(line.rstrip())
                    elif '=' in stripped:
                        key = stripped.split('=')[0].strip()
                        if key in config:
                            lines.append(f"{key}={config[key]}")
                            existing_keys.discard(key)
        
        for key in existing_keys:
            if config.get(key):
                lines.append(f"{key}={config[key]}")
        
        with open(ENV_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
            if lines:
                f.write('\n')
        
        return True
    
    except Exception as e:
        print(f"Error writing .env file: {e}")
        return False


def validate_config(key: str, value: str) -> Tuple[bool, str]:
    """
    Validate config key-value pair.
    
    Args:
        key: Config key name
        value: Config value
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not value or not value.strip():
        return True, ''
    
    if key in VALIDATION_RULES:
        rule = VALIDATION_RULES[key]
        if not re.match(rule['pattern'], value.strip()):
            return False, rule['message']
    
    return True, ''


def set_env_key(key: str, value: str) -> Tuple[bool, str]:
    """
    Set single key in .env file with validation.
    
    Args:
        key: Config key name
        value: Config value
    
    Returns:
        Tuple of (success, error_message)
    """
    is_valid, error = validate_config(key, value)
    if not is_valid:
        return False, error
    
    if not value or not value.strip():
        return True, ''
    
    config = read_env_file()
    config[key] = value.strip()
    
    if write_env_file(config):
        return True, ''
    
    return False, 'Failed to write configuration file'


def delete_env_key(key: str) -> bool:
    """
    Delete a key from .env file.
    
    Args:
        key: Config key name to delete
    
    Returns:
        True on success, False on failure
    """
    config = read_env_file()
    
    if key not in config:
        return True
    
    del config[key]
    
    return write_env_file(config)


def get_env_key(key: str) -> Optional[str]:
    """
    Get single key value from .env file.
    
    Args:
        key: Config key name
    
    Returns:
        Value string or None if not found
    """
    config = read_env_file()
    return config.get(key)


def get_config_for_ui() -> Dict[str, Dict]:
    """
    Get config dictionary formatted for dashboard display.
    
    Returns:
        Dict with value, masked, type, and display name for each key
    """
    config = read_env_file()
    result = {}
    
    for key in EDITABLE_KEYS:
        value = config.get(key, '')
        
        if key == 'DISCORD_WEBHOOK_URL':
            masked = mask_discord_webhook(value)
        elif key == 'DISCORD_USER_ID':
            masked = mask_discord_user_id(value)
        elif key in SENSITIVE_KEYS:
            masked = mask_value(value)
        else:
            masked = value
        
        result[key] = {
            'value': value,
            'masked': masked,
            'type': 'password' if key in SENSITIVE_KEYS else 'text',
            'display': KEY_DISPLAY_NAMES.get(key, key)
        }
    
    return result


if __name__ == '__main__':
    print("Testing env_manager...")
    print(f"\n.env file path: {ENV_FILE}")
    print(f".env exists: {ENV_FILE.exists()}")
    
    print("\n[1] Testing read_env_file:")
    config = read_env_file()
    for key, value in config.items():
        print(f"  {key}: {'*' * 8 if 'KEY' in key or 'SECRET' in key else value}")
    
    print("\n[2] Testing mask_value:")
    test_values = ['abcdefghij', 'ab', '', 'sk-1234567890abcdef']
    for v in test_values:
        print(f"  '{v}' -> '{mask_value(v)}'")
    
    print("\n[3] Testing validate_config:")
    test_cases = [
        ('DISCORD_WEBHOOK_URL', 'https://discord.com/api/webhooks/123456789/abc123'),
        ('DISCORD_WEBHOOK_URL', 'https://ptb.discord.com/api/webhooks/123/xyz'),
        ('DISCORD_WEBHOOK_URL', 'https://invalid.com/webhook'),
        ('DISCORD_USER_ID', '123456789012345678'),
        ('DISCORD_USER_ID', 'abc123'),
        ('VULNERS_API_KEY', 'any-value-here'),
    ]
    for key, val in test_cases:
        valid, err = validate_config(key, val)
        print(f"  {key}='{val[:20]}...': {'✓' if valid else '✗ ' + err}")
    
    print("\n[4] Testing get_config_for_ui:")
    ui_config = get_config_for_ui()
    for key, data in ui_config.items():
        print(f"  {key}: {data['masked']} ({data['type']})")
    
    print("\nDone.")