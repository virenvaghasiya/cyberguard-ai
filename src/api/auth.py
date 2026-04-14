"""
JWT Authentication for CyberGuard AI API.

Single-user auth designed for personal use.
Credentials are read from environment variables:

    CYBERGUARD_USER     — username (default: "admin")
    CYBERGUARD_PASSWORD — plaintext password (default: "cyberguard")
    CYBERGUARD_SECRET   — JWT signing secret (change this in production!)

Tokens expire after 24 hours. Auth is optional on all endpoints by default
and can be enforced per-route using the `require_auth` dependency.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import hashlib
import hmac

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

# ---------------------------------------------------------------------------
# Configuration — all from environment, safe defaults for dev
# ---------------------------------------------------------------------------

SECRET_KEY = os.getenv(
    "CYBERGUARD_SECRET",
    "cyberguard-dev-secret-change-in-production",
)
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

DEFAULT_USERNAME = os.getenv("CYBERGUARD_USER", "admin")
DEFAULT_PASSWORD = os.getenv("CYBERGUARD_PASSWORD", "cyberguard")

# ---------------------------------------------------------------------------
# Password hashing — PBKDF2-SHA256 via stdlib (no external deps)
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    """Derive a secure hash using PBKDF2-HMAC-SHA256."""
    salt = SECRET_KEY[:16].encode("utf-8")
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return h.hex()

# Hash the default password once at import time
_hashed_password = _hash_password(DEFAULT_PASSWORD)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)


def authenticate_user(username: str, password: str) -> bool:
    """Return True if credentials are valid."""
    if username != DEFAULT_USERNAME:
        return False
    return hmac.compare_digest(_hash_password(password), _hashed_password)


def create_access_token(username: str) -> str:
    """Create a signed JWT token for the given username."""
    expire = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

async def get_current_user(token: str | None = Depends(oauth2_scheme)) -> str | None:
    """
    Decode a JWT token and return the username, or None if invalid/missing.
    Use this for optional auth (endpoints accessible without login but
    can return extra info when logged in).
    """
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub", "")
        return username or None
    except JWTError:
        return None


async def require_auth(token: str | None = Depends(oauth2_scheme)) -> str:
    """
    Strict auth dependency — raises 401 if token is missing or invalid.
    Use this on endpoints that must be protected.
    """
    user = await get_current_user(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication token. POST /auth/token to login.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
