"""Kai — exploit agent built on the ra framework."""

import os as _os

from dotenv import load_dotenv as _load_dotenv

_load_dotenv()  # Ensure .env is loaded before config modules read os.environ


def generate_id() -> str:
    """Return a 24-character hex ID (MongoDB ObjectId-compatible)."""
    return _os.urandom(12).hex()
