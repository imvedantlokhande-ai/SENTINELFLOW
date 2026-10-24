# SentinelFlow AI — Autonomous Cybersecurity Incident Investigation & Response Simulation

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Framework: Streamlit](https://img.shields.io/badge/framework-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Google GenAI SDK](https://img.shields.io/badge/google--genai-v2.0+-4285F4.svg)](https://ai.google.dev/)
[![Tests: Pytest Passed](https://img.shields.io/badge/tests-44%20passed-success.svg)](https://pytest.org/)
[![Status: Simulated SOC](https://img.shields.io/badge/simulation-air--gapped-00f0ff.svg)](#synthetic-data-disclaimer)

---

## 1. Product Overview

**SentinelFlow AI** is an AI-assisted cybersecurity operations center (SOC) and incident investigation platform. Designed for security analysts, it demonstrates how state-of-the-art AI (powered by Google's official `google-genai` SDK) can correlate fragmented synthetic telemetry, investigate complex cyber incidents, validate supporting evidence, calculate transparent risk scores, propose human-in-the-loop containment actions, and independently verify state transitions within an air-gapped simulation.

### The Operational Workflow

```
Synthetic Security Events
       │
       ▼
Deterministic Event Correlation Engine
       │
       ▼
AI / Rule-Based Investigation Engine (Gemini 3.8 Flash / Deterministic Fallback)
       │
       ▼
Evidence Validation & Transparent Risk Scoring
       │
       ▼
Human-in-the-Loop Analyst Authorization Gate
       │
       ▼
Simulated Response Execution (Strict Allowlist)
       │
       ▼
Independent State Verification Engine
       │
       ▼
Append-Only Application Audit Trail
```

---

## 2. Problem Statement

Modern SOC analysts face alert fatigue, processing hundreds of disjointed signals across endpoints, clouds, and networks. Manual correlation takes an average of **18 to 25 minutes per incident**, risking dwell time and lateral adversary movement. Conversely, fully autonomous containment without human oversight poses catastrophic operational risks (e.g., unintended lockout of domain controllers or critical customer service accounts).

**SentinelFlow AI solves this dilemma** by providing high-speed AI investigation and deterministic correlation while enforcing a strict **human authorization gate** and **independent state verification** before any simulated containment is applied.

---

## 3. System Architecture

```
sentinelflow-ai/
├── app.py                      # Main SOC Dashboard (3-column layout & workspace)
├── requirements.txt            # Python dependencies (Streamlit, Plotly, GenAI, Pydantic, Pytest)
├── README.md                   # Comprehensive platform documentation
├── .gitignore                  # Git exclusions (credentials, caches, venv)
├── .env.example                # Safe environment variable template (placeholders only)
├── .streamlit/
│   └── config.toml             # Futuristic SOC theme & security configuration
├── pages/
│   ├── 1_Incidents.py          # Incident queue, filter table & relationship inspector
│   ├── 2_Threat_Intelligence.py # Global geo threat map & adversary tracking
│   ├── 3_Response_Center.py    # Human authorization center & simulation registries
│   ├── 4_Audit_Timeline.py     # Append-only chronological audit ledger
│   ├── 5_Analytics.py          # Operational metrics, charts & efficiency benchmarks
│   └── 6_Settings.py           # Gemini API key management & demo reset controls
├── sentinelflow/
│   ├── __init__.py             # Package initialization & version metadata
│   ├── config.py               # Theme colors, allowlists & environment settings
│   ├── models.py               # Strict Pydantic models for events, findings & responses
│   ├── sample_data.py          # 6 deterministic synthetic scenarios & geo markers
│   ├── event_correlation.py    # Multi-rule deterministic correlation engine
│   ├── risk_engine.py          # Transparent mathematical risk attribution engine
│   ├── investigation.py        # Orchestrator for Gemini AI and deterministic fallback
│   ├── gemini_client.py        # Official google-genai client with Pydantic validation
│   ├── response_engine.py      # Safe human-supervised response execution
│   ├── verification.py         # Independent post-action state verification engine
│   ├── audit.py                # Append-only audit logger with secret redaction
│   ├── analytics.py            # Real SOC metrics & Plotly visualization builders
│   ├── state.py                # Streamlit session state management & data reset
│   └── ui_components.py        # Glassmorphic SOC cards, badges & header bar
└── tests/
    ├── __init__.py
    ├── test_models.py          # Validation bounds, missing fields, invalid IDs
    ├── test_correlation.py     # Deterministic multi-rule correlation tests
    ├── test_risk_engine.py     # Risk scoring, mitigating vs escalating factors
    ├── test_investigation.py   # Gemini mocking, hallucinated ID rejection, fallback
    ├── test_response_engine.py # Allowlist enforcement, approval gates, duplicate block
    ├── test_verification.py    # Independent verification passes & intentional failures
    ├── test_audit.py           # Audit append-only integrity & secret redaction
    ├── test_analytics.py       # Metrics calculation accuracy & Plotly generation
    └── test_workflow.py        # Complete end-to-end integration lifecycle test
```

---

## 4. Key Features

- **Futuristic SOC Design System:** Near-black navy palette (`#0a0e17`), glassmorphic panels with cyan-blue borders (`#00f0ff`), glowing status badges, and compact high-density layout.
- **6 Seeded Synthetic Scenarios:**
  1. *Scenario 1:* Anomalous Administrator Login from Eastern Europe IP.
  2. *Scenario 2:* Credential Stuffing & Password Spraying culminating in Payroll Access.
  3. *Scenario 3:* Service Account Compromise via Tor Exit Node with S3 Invoice Exfiltration.
  4. *Scenario 4:* Suspicious Bulk Export with Sanctioned Disaster Recovery Ticket (Benign).
  5. *Scenario 5:* Compliant Corporate SSO Login with Hardware Posture (Benign).
  6. *Scenario 6:* High-Volume C2 Beaconing & 4.2 GB Exfiltration via Encrypted TLS Port 8443.
- **Dual Investigation Modes:**
  - *Gemini AI Mode:* Calls Google's official `google-genai` SDK using `gemini-3.8-flash` with strict Pydantic JSON schema validation and evidence filtering.
  - *Deterministic Demo Mode:* Works completely offline with zero API keys required, applying transparent rule heuristics and scenario findings.
- **Strict Response Allowlist:**
  - `revoke_session`: Invalidates active session tokens.
  - `lock_account`: Temporarily disables synthetic account credentials.
  - `escalate_incident`: Routes incident to senior SOC tiers for forensic investigation.
  - `mark_monitoring`: Retains incident in telemetry watchlist without disruptive containment.
- **Independent State Verification:** Validates that the requested state mutation genuinely occurred in the simulation registries before reporting success.
- **Append-Only Audit Ledger:** Automatically records all analyst approvals, model findings, and verification outcomes with automated credential/secret redaction.

---

## 5. Installation & Setup

### Prerequisites

- Python 3.11 or higher (Python 3.11, 3.12, 3.13, 3.14 supported).
- Windows PowerShell, macOS Terminal, or Linux Bash.
- Git.

### Windows PowerShell Setup

```powershell
# 1. Clone the repository
git clone https://github.com/imvedantlokhande-ai/SENTINELFLOW.git
cd SENTINELFLOW

# 2. Create and activate a Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Upgrade pip and install dependencies
pip install -r requirements.txt
```

### Linux / macOS Setup

```bash
# 1. Clone the repository
git clone https://github.com/imvedantlokhande-ai/SENTINELFLOW.git
cd SENTINELFLOW

# 2. Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Upgrade pip and install dependencies
pip install -r requirements.txt
```

---

## 6. Environment Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` to configure your settings:

```ini
# Optional: Google Gemini API Key from Google AI Studio (https://aistudio.google.com/)
# If left empty, SentinelFlow AI automatically runs in full Deterministic Demo Mode!
GEMINI_API_KEY=your_gemini_api_key_here

# Configurable Gemini Model (Default: gemini-3.8-flash)
GEMINI_MODEL=gemini-3.8-flash

# Operational Mode: 'auto', 'deterministic', or 'gemini_only'
SENTINELFLOW_MODE=auto

# Server Port
PORT=8501
```

> **Security Guarantee:** API keys are read server-side only. Keys are never logged, displayed in the web UI, or exported in client-side bundles.

---

## 7. How to Run the Application

Launch the Streamlit web application:

```bash
python -m streamlit run app.py
```

The application will start and be available at:
`http://localhost:8501`

---

## 8. How to Run Automated Tests

Run the full pytest automated test suite:

```bash
python -m pytest -q
```

Expected output:
```
............................................                             [100%]
44 passed in 0.84s
```

All 44 automated unit and integration tests run offline without requiring external network access or live Gemini API keys.

---

## 9. Deployment Guide (Streamlit Community Cloud)

SentinelFlow AI is engineered for zero-configuration deployment to **Streamlit Community Cloud**:

1. **Push Code to GitHub:**
   ```bash
   git add .
   git commit -m "feat: complete SentinelFlow AI SOC platform"
   git push origin main
   ```
2. **Connect to Streamlit Cloud:**
   - Navigate to [share.streamlit.io](https://share.streamlit.io).
   - Select your repository (`imvedantlokhande-ai/SENTINELFLOW`) and branch (`main`).
   - Set the Main file path to `app.py`.
3. **Configure Secrets (Optional):**
   - In the Streamlit Cloud App Settings under **Secrets**, add your optional Gemini API key:
     ```toml
     GEMINI_API_KEY = "your_actual_gemini_api_key"
     GEMINI_MODEL = "gemini-3.8-flash"
     ```
   - If no secret is configured, the app seamlessly runs in Deterministic Demo Mode.
4. **Deploy & Verify:**
   - Click **Deploy**. The platform will install `requirements.txt` and launch the live application.

---

## 10. Security Engineering & Safeguards

- **Strict Isolation:** Zero network calls to corporate endpoints or active directory systems.
- **Allowlisted Actions Only:** The application rejects arbitrary code execution, raw shell commands, or unauthorized parameters.
- **Pydantic Validation:** All incoming telemetry and Gemini model JSON outputs are strictly validated against Pydantic schemas. Hallucinated evidence IDs are automatically filtered out.
- **Human Authorization Gate:** AI recommendations are purely advisory; containment actions require explicit human confirmation.
- **Append-Only In-Memory Audit Trail:** Every action, actor, timestamp, and status transition is recorded with secret redaction.

---

## 11. Known Limitations

- **In-Memory State Persistence:** Current demo state is stored in memory. Refreshing the browser or redeploying restarts the simulation from baseline.
- **Simulated Infrastructure:** Threat maps, endpoint counts, and cloud statuses reflect seeded demonstration metrics.
- **Rate Limits on Live AI:** When using free-tier Gemini API keys, provider quotas may trigger rate limits; in this case, the system gracefully falls back to deterministic rule analysis.

---

## 12. Synthetic Data Disclaimer

> **IMPORTANT NOTICE:** All events, timestamps, IP addresses (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), hostnames, employee identities, and threat telemetry within SentinelFlow AI are **strictly synthetic and fictional**. They are generated for demonstration and competition testing purposes only. No real personal data or corporate systems are accessed or affected.

---

## 13. License

This project is licensed under the MIT License.
