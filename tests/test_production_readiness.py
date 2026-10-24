"""Tests for Production Readiness, Security Hardening, Privacy, and Rate Limiting.

Verifies the 20 checklist requirements:
- In-memory rate limiting and bot spam defense
- Ephemeral session privacy & token scrubbing in audit logs
- Consent-aware operational telemetry
- Static SEO files (robots.txt, sitemap.xml, favicon, Open Graph preview)
- Deployment configs (HSTS, reverse proxy headers)
"""

import os
import time
import pytest
from unittest.mock import MagicMock

from sentinelflow.state import check_rate_limit, record_telemetry_event
from sentinelflow.audit import AuditTrail, sanitize_text


def test_sanitize_text_redacts_api_keys_and_passwords():
    """Verify that sensitive API key patterns and passwords are redacted from log text."""
    leak_text = "Encountered error with key AIzaSyDUMMYKEY1234567890abcdefghijklm and password: SecretPassword123!"
    cleaned = sanitize_text(leak_text)
    assert "AIzaSyDUMMYKEY" not in cleaned
    assert "[REDACTED_API_KEY]" in cleaned
    assert "SecretPassword123!" not in cleaned
    assert "[REDACTED]" in cleaned


def test_audit_trail_redacts_keys_in_details_and_metadata():
    """Verify audit log entries never store sensitive secrets."""
    audit = AuditTrail()
    entry = audit.log(
        event_type="API_CALL_FAILED",
        status="FAILED",
        details="Error contacting Gemini API with key AIzaSyABCDEF1234567890abcdefghijklm",
        metadata={
            "api_key": "AIzaSySECRETKEY999",
            "session_token": "token-12345",
            "safe_param": "SCENARIO_1",
        },
    )
    assert "AIzaSy" not in entry.details
    assert "[REDACTED_API_KEY]" in entry.details
    assert entry.metadata["api_key"] == "[REDACTED_SECRET]"
    assert entry.metadata["session_token"] == "[REDACTED_SECRET]"
    assert entry.metadata["safe_param"] == "SCENARIO_1"


def test_rate_limiter_allows_normal_usage_and_blocks_burst():
    """Verify in-memory rate limiting enforces thresholds."""
    mock_st = MagicMock()
    mock_st.session_state = {"rate_limits": {}}

    # 5 allowed calls with limit of 5
    for i in range(5):
        assert check_rate_limit(mock_st, "test_action", max_calls=5, period_seconds=10) is True

    # 6th call exceeds limit within the 10-second period
    assert check_rate_limit(mock_st, "test_action", max_calls=5, period_seconds=10) is False


def test_consent_aware_telemetry_respects_user_choice():
    """Verify telemetry events are strictly recorded only when analytics consent is granted."""
    mock_st = MagicMock()

    # Case 1: No consent decided yet
    mock_st.session_state = {"cookie_consent": None, "analytics_events": []}
    record_telemetry_event(mock_st, "PAGE_VIEW", {"route": "/Incidents"})
    assert len(mock_st.session_state["analytics_events"]) == 0

    # Case 2: User rejected optional cookies
    mock_st.session_state["cookie_consent"] = {"necessary": True, "analytics": False}
    record_telemetry_event(mock_st, "SCENARIO_SWITCHED", {"scenario": "INC-2026-001"})
    assert len(mock_st.session_state["analytics_events"]) == 0

    # Case 3: User accepted analytics cookies
    mock_st.session_state["cookie_consent"] = {"necessary": True, "analytics": True}
    record_telemetry_event(mock_st, "SCENARIO_SWITCHED", {"scenario": "INC-2026-001"})
    assert len(mock_st.session_state["analytics_events"]) == 1
    assert mock_st.session_state["analytics_events"][0]["event"] == "SCENARIO_SWITCHED"


def test_static_seo_and_security_files_exist():
    """Verify that robots.txt, sitemap.xml, favicon.svg, and og_preview.svg exist."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    static_dir = os.path.join(base_dir, "static")

    robots_path = os.path.join(static_dir, "robots.txt")
    sitemap_path = os.path.join(static_dir, "sitemap.xml")
    favicon_path = os.path.join(static_dir, "favicon.svg")
    og_preview_path = os.path.join(static_dir, "og_preview.svg")

    assert os.path.exists(robots_path), "robots.txt must exist"
    assert os.path.exists(sitemap_path), "sitemap.xml must exist"
    assert os.path.exists(favicon_path), "favicon.svg must exist"
    assert os.path.exists(og_preview_path), "og_preview.svg must exist"

    with open(robots_path, "r", encoding="utf-8") as f:
        robots_content = f.read()
        assert "Sitemap: https://sentinelflow.ai/sitemap.xml" in robots_content

    with open(sitemap_path, "r", encoding="utf-8") as f:
        sitemap_content = f.read()
        assert "<loc>https://sentinelflow.ai/</loc>" in sitemap_content
        assert "<loc>https://sentinelflow.ai/Privacy_Policy</loc>" in sitemap_content
        assert "<loc>https://sentinelflow.ai/Terms</loc>" in sitemap_content


def test_all_pages_exist():
    """Verify all 9 multipage routes exist in the pages/ directory."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pages_dir = os.path.join(base_dir, "pages")

    expected_pages = [
        "1_Incidents.py",
        "2_Threat_Intelligence.py",
        "3_Response_Center.py",
        "4_Audit_Timeline.py",
        "5_Analytics.py",
        "6_Settings.py",
        "7_Privacy_Policy.py",
        "8_Terms.py",
        "9_Not_Found.py",
    ]

    for page_name in expected_pages:
        page_path = os.path.join(pages_dir, page_name)
        assert os.path.exists(page_path), f"Page {page_name} must exist"


def test_production_deployment_configs_contain_hsts_and_security_headers():
    """Verify Caddyfile and nginx.conf contain Strict-Transport-Security and security headers."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    caddy_path = os.path.join(base_dir, "deploy", "Caddyfile")
    nginx_path = os.path.join(base_dir, "deploy", "nginx.conf")

    assert os.path.exists(caddy_path), "deploy/Caddyfile must exist"
    assert os.path.exists(nginx_path), "deploy/nginx.conf must exist"

    with open(caddy_path, "r", encoding="utf-8") as f:
        caddy_content = f.read()
        assert "Strict-Transport-Security" in caddy_content
        assert "X-Content-Type-Options" in caddy_content
        assert "X-Frame-Options" in caddy_content
        assert "robots.txt" in caddy_content
        assert "sitemap.xml" in caddy_content

    with open(nginx_path, "r", encoding="utf-8") as f:
        nginx_content = f.read()
        assert "Strict-Transport-Security" in nginx_content
        assert "proxy_pass http://127.0.0.1:8501" in nginx_content
        assert "robots.txt" in nginx_content
        assert "sitemap.xml" in nginx_content


def test_pwa_manifest_and_service_worker_configuration():
    """Verify W3C PWA Manifest, Service Worker, and static file serving."""
    import json
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    static_dir = os.path.join(base_dir, "static")

    manifest_path = os.path.join(static_dir, "manifest.json")
    sw_path = os.path.join(static_dir, "service-worker.js")
    icon192_path = os.path.join(static_dir, "icon-192.svg")
    icon512_path = os.path.join(static_dir, "icon-512.svg")
    icon192_png = os.path.join(static_dir, "icon-192.png")
    icon512_png = os.path.join(static_dir, "icon-512.png")
    offline_path = os.path.join(static_dir, "offline.html")
    config_path = os.path.join(base_dir, ".streamlit", "config.toml")

    assert os.path.exists(manifest_path), "manifest.json must exist"
    assert os.path.exists(sw_path), "service-worker.js must exist"
    assert os.path.exists(icon192_path), "icon-192.svg must exist"
    assert os.path.exists(icon512_path), "icon-512.svg must exist"
    assert os.path.exists(icon192_png), "icon-192.png must exist"
    assert os.path.exists(icon512_png), "icon-512.png must exist"
    assert os.path.exists(offline_path), "offline.html must exist"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)
        assert manifest_data["id"] == "/"
        assert manifest_data["display"] == "standalone"
        assert manifest_data["theme_color"] == "#00f0ff"
        assert len(manifest_data["icons"]) >= 2
        assert len(manifest_data.get("screenshots", [])) >= 2
        assert "display_override" in manifest_data

    with open(sw_path, "r", encoding="utf-8") as f:
        sw_content = f.read()
        assert "caches.open" in sw_content
        assert "offline.html" in sw_content
        assert "Promise.allSettled" in sw_content

    with open(config_path, "r", encoding="utf-8") as f:
        config_content = f.read()
        assert "enableStaticServing = true" in config_content


def test_cross_device_responsive_css_rules_present():
    """Verify UI components contain device breakpoints for PC, laptop, tablet, and mobile."""
    from sentinelflow.ui_components import inject_custom_css
    import inspect
    css_source = inspect.getsource(inject_custom_css)

    assert "min-width: 1200px" in css_source, "Desktop/PC breakpoint required"
    assert "min-width: 768px" in css_source and "max-width: 1024px" in css_source, "Tablet breakpoint required"
    assert "max-width: 767px" in css_source, "Mobile phone breakpoint required"
    assert "max-width: 375px" in css_source, "Small screen mobile breakpoint required"
    assert "safe-area-inset-bottom" in css_source, "Safe area insets required"
    assert "safe-area-inset-top" in css_source, "Top safe area insets required"
    assert "min-height: 48px" in css_source, "Touch target sizing required"
    assert "font-size: 16px" in css_source, "16px input font size to prevent iOS auto-zoom required"
    assert "prefers-reduced-motion" in css_source, "Accessibility reduced motion required"
    assert "soc-mobile-dock" in css_source, "Mobile bottom dock styling required"
    assert "data-testid=\"stSidebar\"" in css_source, "Cyber sidebar styling required"
    assert "data-testid=\"stHorizontalBlock\"" in css_source, "Horizontal block wrap styling required"
    assert "display-mode: standalone" in css_source, "Standalone PWA media query required"
    assert "display-mode: window-controls-overlay" in css_source, "Window controls overlay media query required"


