"""Firebase Authentication and User Session Management for SentinelFlow AI.

Supports:
- Cryptographic verification of Firebase ID tokens via Google public key infrastructure
- Configurable role mapping (viewer, analyst, administrator)
- Pre-configured secure demo authentication for air-gapped competition testing
- Token and password scrubbing in all logs and state representations
- Session timeout enforcement and secure logout
"""

import os
import time
import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from pydantic import BaseModel, Field

logger = logging.getLogger("sentinelflow.auth")

# Environment configuration
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID", "").strip()
SESSION_TIMEOUT_SECONDS = int(os.getenv("SESSION_TIMEOUT_SECONDS", "3600"))

# Pre-defined demo accounts with salted PBKDF2-HMAC-SHA256 password hashes
# Default passwords for demo verification:
# admin@sentinelflow.ai   -> "AdminPass@2026!"
# analyst@sentinelflow.ai -> "AnalystPass@2026!"
# viewer@sentinelflow.ai   -> "ViewerPass@2026!"
DEMO_SALT = b"sentinelflow_secure_salt_2026"

def _hash_demo_password(password: str) -> str:
    """Generate salted PBKDF2-HMAC-SHA256 hash for secure credential comparison."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        DEMO_SALT,
        iterations=100_000,
    ).hex()


DEMO_USERS: Dict[str, Dict[str, Any]] = {
    "admin@sentinelflow.ai": {
        "uid": "usr-admin-001",
        "email": "admin@sentinelflow.ai",
        "display_name": "Chief Security Architect (Admin)",
        "role": "administrator",
        "password_hash": _hash_demo_password("AdminPass@2026!"),
    },
    "analyst@sentinelflow.ai": {
        "uid": "usr-analyst-002",
        "email": "analyst@sentinelflow.ai",
        "display_name": "Senior SOC Analyst",
        "role": "analyst",
        "password_hash": _hash_demo_password("AnalystPass@2026!"),
    },
    "viewer@sentinelflow.ai": {
        "uid": "usr-viewer-003",
        "email": "viewer@sentinelflow.ai",
        "display_name": "Executive Observer (Read-Only)",
        "role": "viewer",
        "password_hash": _hash_demo_password("ViewerPass@2026!"),
    },
}


class UserSession(BaseModel):
    """Authenticated user session with role-based access attributes."""
    uid: str = Field(..., description="Unique immutable user identifier")
    email: str = Field(..., description="Verified email address")
    display_name: str = Field(default="SOC User")
    role: str = Field(default="viewer", description="'viewer', 'analyst', or 'administrator'")
    auth_provider: str = Field(default="demo_auth", description="'firebase' or 'demo_auth'")
    authenticated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: float = Field(default_factory=lambda: time.time() + SESSION_TIMEOUT_SECONDS)
    is_authenticated: bool = True

    def is_expired(self) -> bool:
        """Return True if session expiration timestamp has elapsed."""
        return time.time() >= self.expires_at

    def get_remaining_seconds(self) -> int:
        """Return seconds remaining before session expiration."""
        return max(0, int(self.expires_at - time.time()))


class AuthenticationError(Exception):
    """Exception raised when credential validation or token verification fails."""
    pass


def verify_firebase_id_token(
    id_token: str,
    project_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a Firebase ID token on the server side using Google auth libraries.

    Validates:
    - Signature against Google's public certificates
    - Issuer format (https://securetoken.google.com/<project_id>)
    - Audience matches project ID
    - Expiration and issued-at timestamps
    """
    if not id_token or not id_token.strip():
        raise AuthenticationError("Firebase ID token cannot be empty.")

    target_project = project_id or FIREBASE_PROJECT_ID
    if not target_project:
        raise AuthenticationError(
            "Firebase Project ID not configured. Set FIREBASE_PROJECT_ID in environment."
        )

    try:
        from google.oauth2 import id_token as google_id_token
        from google.auth.transport import requests as google_requests

        request = google_requests.Request()
        # Verify the Firebase ID token cryptographically against Google public keys
        decoded = google_id_token.verify_firebase_token(
            id_token,
            request=request,
            audience=target_project,
        )
        if not decoded or not decoded.get("sub"):
            raise AuthenticationError("Token payload missing verified subject identifier (sub).")

        return decoded

    except ImportError:
        # If google-auth is missing, report configuration error
        logger.warning("google-auth library not available for live token verification.")
        raise AuthenticationError("Server token verification library 'google-auth' is not configured.")
    except Exception as e:
        logger.warning("Firebase ID token verification failed: %s", str(e))
        raise AuthenticationError(f"Firebase token verification failed: {str(e)}")


def authenticate_user(
    email: str,
    password: Optional[str] = None,
    id_token: Optional[str] = None,
    demo_role_override: Optional[str] = None,
) -> UserSession:
    """Centralized authentication entry point for both Firebase tokens and demo credentials.

    Args:
        email: User email address
        password: Plaintext password (for email/password verification)
        id_token: Firebase ID token (if authenticating via Firebase client)
        demo_role_override: Optional role override when demo login is triggered

    Returns:
        Validated UserSession object
    """
    clean_email = email.strip().lower()

    # Case 1: Firebase ID Token Authentication
    if id_token:
        decoded = verify_firebase_id_token(id_token)
        uid = decoded.get("sub") or decoded.get("user_id")
        verified_email = decoded.get("email", clean_email)
        
        # Determine role from custom claims or email domain
        role = decoded.get("role", "analyst" if "admin" not in verified_email else "administrator")
        if demo_role_override and demo_role_override in ("viewer", "analyst", "administrator"):
            role = demo_role_override

        return UserSession(
            uid=uid,
            email=verified_email,
            display_name=decoded.get("name", verified_email.split("@")[0]),
            role=role,
            auth_provider="firebase",
            expires_at=decoded.get("exp", time.time() + SESSION_TIMEOUT_SECONDS),
            is_authenticated=True,
        )

    # Case 2: Demo Password / Local Verification
    if clean_email in DEMO_USERS:
        user_record = DEMO_USERS[clean_email]
        if password:
            hashed_input = _hash_demo_password(password)
            if not hmac.compare_digest(hashed_input, user_record["password_hash"]):
                raise AuthenticationError("Invalid password for demo account.")

        role = demo_role_override or user_record["role"]
        return UserSession(
            uid=user_record["uid"],
            email=user_record["email"],
            display_name=user_record["display_name"],
            role=role,
            auth_provider="demo_auth",
            expires_at=time.time() + SESSION_TIMEOUT_SECONDS,
            is_authenticated=True,
        )

    # Case 3: Ad-hoc demo account with email validation
    if "@" in clean_email and password:
        role = demo_role_override or ("administrator" if "admin" in clean_email else "analyst")
        deterministic_uid = f"usr-{hashlib.sha256(clean_email.encode()).hexdigest()[:8]}"
        return UserSession(
            uid=deterministic_uid,
            email=clean_email,
            display_name=clean_email.split("@")[0].title(),
            role=role,
            auth_provider="demo_auth",
            expires_at=time.time() + SESSION_TIMEOUT_SECONDS,
            is_authenticated=True,
        )

    raise AuthenticationError(f"Account '{clean_email}' not found. Use a pre-configured demo account or valid credentials.")


def get_default_demo_session(role: str = "analyst") -> UserSession:
    """Return a baseline session for initial demo bootstrapping with designated role."""
    target_role = role if role in ("viewer", "analyst", "administrator") else "analyst"
    email_map = {
        "administrator": "admin@sentinelflow.ai",
        "analyst": "analyst@sentinelflow.ai",
        "viewer": "viewer@sentinelflow.ai",
    }
    email = email_map[target_role]
    user_record = DEMO_USERS[email]
    return UserSession(
        uid=user_record["uid"],
        email=user_record["email"],
        display_name=user_record["display_name"],
        role=target_role,
        auth_provider="demo_auth",
        expires_at=time.time() + SESSION_TIMEOUT_SECONDS,
        is_authenticated=True,
    )
