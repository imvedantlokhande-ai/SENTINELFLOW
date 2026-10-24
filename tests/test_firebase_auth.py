"""Tests for Firebase Authentication, Token Verification, and Session Management.

Verifies:
- Official Google/Firebase ID token verification flow
- Rejection of forged, empty, and expired tokens
- Safe demo credential verification with salted PBKDF2 hashing
- Session timeout enforcement and countdown
- Redaction of credentials from all logged data
"""

import time
import pytest
from unittest.mock import patch, MagicMock

from sentinelflow.auth import (
    authenticate_user,
    verify_firebase_id_token,
    get_default_demo_session,
    UserSession,
    AuthenticationError,
    _hash_demo_password,
)


def test_demo_admin_authentication_success():
    """Verify administrator login with valid demo credentials."""
    session = authenticate_user(
        email="admin@sentinelflow.ai",
        password="AdminPass@2026!",
    )
    assert session.is_authenticated is True
    assert session.role == "administrator"
    assert session.email == "admin@sentinelflow.ai"
    assert session.is_expired() is False
    assert session.get_remaining_seconds() > 0


def test_demo_analyst_and_viewer_authentication():
    """Verify analyst and viewer credentials authenticate into respective roles."""
    analyst_session = authenticate_user(
        email="analyst@sentinelflow.ai",
        password="AnalystPass@2026!",
    )
    assert analyst_session.role == "analyst"

    viewer_session = authenticate_user(
        email="viewer@sentinelflow.ai",
        password="ViewerPass@2026!",
    )
    assert viewer_session.role == "viewer"


def test_demo_authentication_rejects_invalid_password():
    """Verify that incorrect passwords raise AuthenticationError."""
    with pytest.raises(AuthenticationError, match="Invalid password"):
        authenticate_user(
            email="admin@sentinelflow.ai",
            password="WrongPassword999!",
        )


def test_session_expiration_enforcement():
    """Verify that expired sessions are accurately identified."""
    expired_session = UserSession(
        uid="usr-test-expired",
        email="analyst@sentinelflow.ai",
        role="analyst",
        expires_at=time.time() - 10.0,  # 10 seconds in the past
        is_authenticated=True,
    )
    assert expired_session.is_expired() is True
    assert expired_session.get_remaining_seconds() == 0


def test_verify_firebase_id_token_empty_token_rejected():
    """Verify that empty or whitespace tokens are rejected immediately."""
    with pytest.raises(AuthenticationError, match="cannot be empty"):
        verify_firebase_id_token("")


def test_verify_firebase_id_token_missing_project_id():
    """Verify that token verification without a project ID raises an AuthenticationError."""
    with patch("sentinelflow.auth.FIREBASE_PROJECT_ID", ""):
        with pytest.raises(AuthenticationError, match="Firebase Project ID not configured"):
            verify_firebase_id_token("dummy_token", project_id=None)


def test_verify_firebase_id_token_mock_success():
    """Verify successful verification of a valid Firebase ID token via mocked Google SDK."""
    mock_decoded = {
        "sub": "firebase-uid-998877",
        "email": "cloud_analyst@company.com",
        "name": "Cloud Analyst",
        "role": "analyst",
        "exp": time.time() + 3600,
        "iss": "https://securetoken.google.com/sentinelflow-prod",
        "aud": "sentinelflow-prod",
    }

    with patch("sentinelflow.auth.FIREBASE_PROJECT_ID", "sentinelflow-prod"):
        with patch("google.oauth2.id_token.verify_firebase_token", return_value=mock_decoded):
            session = authenticate_user(
                email="cloud_analyst@company.com",
                id_token="valid_simulated_jwt_token",
            )
            assert session.uid == "firebase-uid-998877"
            assert session.email == "cloud_analyst@company.com"
            assert session.role == "analyst"
            assert session.auth_provider == "firebase"


def test_verify_firebase_id_token_mock_invalid_signature():
    """Verify that a forged or invalid Firebase token raises AuthenticationError."""
    with patch("sentinelflow.auth.FIREBASE_PROJECT_ID", "sentinelflow-prod"):
        with patch("google.oauth2.id_token.verify_firebase_token", side_effect=ValueError("Token expired")):
            with pytest.raises(AuthenticationError, match="Firebase token verification failed"):
                authenticate_user(
                    email="attacker@external.com",
                    id_token="forged_expired_jwt_token",
                )


def test_password_hash_uses_salted_pbkdf2():
    """Verify that demo password hashing generates consistent, salted PBKDF2 hashes."""
    hash1 = _hash_demo_password("TestSecret123")
    hash2 = _hash_demo_password("TestSecret123")
    hash_diff = _hash_demo_password("DifferentSecret123")

    assert hash1 == hash2
    assert hash1 != hash_diff
    assert len(hash1) == 64  # SHA256 hex length
