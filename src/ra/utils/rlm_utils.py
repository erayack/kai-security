from typing import Any
import secrets

def filter_sensitive_keys(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Filter out sensitive keys like API keys from kwargs."""
    filtered = {}
    for key, value in kwargs.items():
        key_lower = key.lower()
        if "api" in key_lower and "key" in key_lower:
            continue
        filtered[key] = value
    return filtered


def generate_id() -> str:
    """Generate a random 24-character hex ID"""
    return secrets.token_hex(12)
