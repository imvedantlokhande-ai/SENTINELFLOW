# SentinelFlow AI — Production Deployment Guide

This document provides deployment blueprints for hosting SentinelFlow AI securely in production.

---

## 1. Hosting Options

### Option A: Streamlit Community Cloud (Zero-Config HTTPS)
Streamlit Community Cloud automatically manages:
- Valid Let's Encrypt TLS/SSL certificates
- Automatic HTTP-to-HTTPS redirection
- Continuous integration directly from GitHub (`main` branch)

**Steps:**
1. Log in to [share.streamlit.io](https://share.streamlit.io/).
2. Select repository: `imvedantlokhande-ai/SENTINELFLOW`.
3. Branch: `main`.
4. Main file path: `app.py`.
5. Under **Advanced settings**, set Python version to `3.11` (or 3.12).
6. Under **Secrets**, optionally provide `GEMINI_API_KEY = "your-api-key"`.
7. Click **Deploy**.

---

### Option B: Cloud VM with Caddy (Recommended for Custom Domains)
Caddy automatically provisions and renews Let's Encrypt TLS certificates with zero manual intervention.

1. Install Caddy on Ubuntu/Debian:
   ```bash
   sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
   sudo apt update && sudo apt install caddy
   ```

2. Copy [`deploy/Caddyfile`](file:///c:/Users/imved/Downloads/projrct/deploy/Caddyfile) to `/etc/caddy/Caddyfile`.
3. Start the Streamlit application using a systemd service or background manager:
   ```bash
   streamlit run app.py --server.port 8501 --server.address 127.0.0.1
   ```
4. Reload Caddy:
   ```bash
   sudo systemctl reload caddy
   ```

---

### Option C: Nginx Reverse Proxy with Certbot
1. Install Nginx and Certbot:
   ```bash
   sudo apt install -y nginx certbot python3-certbot-nginx
   ```
2. Copy [`deploy/nginx.conf`](file:///c:/Users/imved/Downloads/projrct/deploy/nginx.conf) to `/etc/nginx/sites-available/sentinelflow.ai`.
3. Link to sites-enabled:
   ```bash
   sudo ln -s /etc/nginx/sites-available/sentinelflow.ai /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   ```
4. Obtain certificates:
   ```bash
   sudo certbot --nginx -d sentinelflow.ai -d www.sentinelflow.ai
   ```

---

## 2. HTTPS & Security Headers Checklist
- [x] **HSTS (Strict-Transport-Security):** Configured with `max-age=31536000; includeSubDomains; preload`
- [x] **Anti-MIME Sniffing:** `X-Content-Type-Options: nosniff`
- [x] **Anti-Clickjacking:** `X-Frame-Options: SAMEORIGIN`
- [x] **Referrer Policy:** `strict-origin-when-cross-origin`
- [x] **XSRF Protection:** Configured in `.streamlit/config.toml` (`enableXsrfProtection = true`)
- [x] **Stack Trace Suppression:** Configured in `.streamlit/config.toml` (`showErrorDetails = false`)
