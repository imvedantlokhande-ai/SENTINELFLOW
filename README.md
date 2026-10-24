# SentinelFlow AI 🛡️

### Intelligent Cybersecurity Incident Investigation & Autonomous Response Platform

[![Next.js 16](https://img.shields.io/badge/Next.js-16.4.2-black?logo=next.js)](https://nextjs.org/)
[![Google Gemini](https://img.shields.io/badge/Google%20Gen%20AI-Gemini%202.5%20Flash-4285F4?logo=google)](https://aistudio.google.com/)
[![Zod](https://img.shields.io/badge/Validation-Zod%20Schema-3E67B1)](https://zod.dev/)
[![Security Guardrails](https://img.shields.io/badge/Security-Human--in--the--Loop-emerald)](https://github.com/imvedantlokhande-ai/SENTINELFLOW)

SentinelFlow AI is an AI-enabled cybersecurity incident investigation and response platform designed to help security teams analyze suspicious activity, correlate evidence, assess risk, and execute controlled response workflows.

Built for the *PromptWars — Build Beyond AI* challenge, SentinelFlow demonstrates how AI reasoning can be combined with secure software engineering, human oversight, automated verification, and measurable efficiency.

> *Project status:* Competition prototype  
> *Deployment target:* Vercel  
> *AI integration:* Google Gemini  
> *Primary focus:* Security, reliability, efficiency, accessibility, and responsible automation

---

## ⚡ Fastest Way to Demonstrate to a Judge (10-Minute Walkthrough)

1. *Open the Dashboard*: Navigate to http://localhost:3000 (or deployed Vercel URL).
2. *Launch Demo Scenario: Click the *"DEMO SCENARIO"* button in the top navigation or *"Launch Demo Workflow"** on the hero banner.
   - Automatically loads *Incident INC-2026-8812: *Possible Account Compromise — Unusual Login and Session Activity.
3. *Inspect AI Investigation*:
   - Synthesizes 5 correlated events: geographic anomaly (Bulgaria Tor exit node), credential stuffing burst, session token hijack, bulk PII download, and non-standard egress stream.
   - Computes *Risk Score: 92/100 (Critical)* and *Confidence: 88/100*.
   - Displays *Evidence-Backed Findings* with clickable [EV-101], [EV-103] tags. Click any tag to open the *Raw Telemetry Inspector* showing MITRE ATT&CK mappings.
4. *Authorize Containment Action*:
   - Click *"Containment Center"* (or top tab).
   - Review proposed action: SIMULATE_LOCK_ACCOUNT or SIMULATE_REVOKE_SESSION.
   - Click *"Authorize & Execute"*. The modal requires explicit human operator confirmation.
   - Check the authorization box and submit.
5. *Verify Independent Target State*:
   - Observe the *Simulated Target State* card:
     - Target: sarah.chen@fintech-enterprise.internal
     - Status changes from ACTIVE to *LOCKED*.
     - Active sessions change from 3 to *0*.
     - Verification Badge: *INDEPENDENTLY VERIFIED BY SEPARATE STATE QUERY*.
6. *Inspect Immutable Audit Trail*:
   - Navigate to the *"Audit Trail"* tab to verify that the approval, action result, and verification status were appended.
7. *Negative Controls Sandbox*:
   - In the Response Center, click *"1. Test Missing Approval"* or *"2. Test Non-Allowlisted Action"* to demonstrate that unauthorized/unapproved attempts are strictly rejected with HTTP 400/403.
8. *Efficiency Benchmark*:
   - Navigate to *"Efficiency & ROI"* to see the 99.4% MTTR acceleration comparison (2.4s AI vs 40m manual SOC baseline).

---

## 🚀 Overview

Traditional security investigations often require analysts to manually inspect logs, correlate events, determine incident severity, and decide how to respond.

SentinelFlow AI aims to simplify this process through an integrated workflow that turns structured security events into explainable investigations and controlled response actions.

Instead of stopping at threat detection, SentinelFlow connects investigation, decision support, response approval, execution, and verification in a single interface.

---

## ✨ Key Features

### 1. Security Operations Dashboard
- Overview of incidents, severity levels, and response status.
- Recent security activity and incident summaries.
- Risk indicators and investigation metrics.
- A guided demonstration workflow.

### 2. AI-Powered Investigation
- Analyze structured security event data using Google Gemini.
- Correlate related events and entities.
- Generate incident summaries and risk assessments.
- Identify suspicious patterns and alternative explanations.
- Link findings to supporting evidence IDs.
- Distinguish observed evidence from AI-generated inferences.

### 3. Controlled Response Automation
- Generate predefined incident response recommendations.
- Require explicit approval before consequential simulated actions.
- Execute only allowlisted response actions.
- Verify simulated state changes after execution.
- Handle rejected, failed, or unsupported actions safely.

### 4. Incident Timeline and Audit Trail
- Track investigation events and response decisions.
- Record approval and execution outcomes.
- Display verification status.
- Make the incident lifecycle easier to understand and review.

### 5. Reliability and Fallbacks
- Validate incoming requests and AI-generated outputs.
- Handle malformed responses and provider errors.
- Support a deterministic fallback when configured AI services are unavailable.
- Clearly distinguish fallback analysis from Gemini-generated results.

### 6. Efficiency Analytics
- Track investigation execution time where implemented.
- Count evidence items processed and findings linked to evidence.
- Report verified response actions.
- Compare AI-assisted investigation time with an explicitly labelled manual baseline.

---

## 🧠 How It Works

mermaid
graph TD
    A[Telemetry Event Stream<br/>EV-101 to EV-105] --> B[Incident Correlation Engine]
    B --> C[SentinelFlow Core API<br/>POST /api/investigate]
    
    C -->|If Key Present| D[Google Gemini 2.5 Flash<br/>Low-Temp Structured Output]
    C -->|If Key Missing or Failure| E[Deterministic Heuristic<br/>SOC Rule Engine]
    
    D --> F[Strict Zod Schema Validation<br/>& Evidence ID Grounding Check]
    E --> F
    
    F --> G[Investigation Workspace<br/>Timeline, MITRE Mapping, Findings]
    G --> H[Response Center<br/>Containment Proposal]
    
    H --> I{Human Operator<br/>Explicit Approval?}
    I -->|Rejected| J[HTTP 403 / Audit Logged]
    I -->|Approved| K[Allowlisted Action Engine<br/>POST /api/respond]
    
    K --> L[Simulated Target Entity State<br/>In-Memory Isolation / Token Invalidation]
    L --> M[Independent State Verification Query]
    M --> N[Append-Only Audit Trail<br/>GET /api/audit]


The core workflow follows these steps:

1. *Detect:* Select a predefined simulated security incident.
2. *Collect:* Gather related security events and evidence.
3. *Investigate:* Analyze the evidence using Gemini or the clearly identified fallback.
4. *Assess:* Generate findings, severity, risk score, confidence, and alternative explanations.
5. *Recommend:* Propose a predefined response action with its rationale and expected effect.
6. *Approve:* Require human authorization for the simulated response.
7. *Execute:* Run the approved action against the demo environment.
8. *Verify:* Independently check whether the simulated state changed as expected.
9. *Audit:* Record the outcome and verification status.

---

## 🏗️ Technology Stack

| Technology | Purpose |
|---|---|
| Next.js 16 (App Router) | Application framework and server-side routes |
| TypeScript | Type safety and maintainable development |
| Vanilla CSS / Tailwind | Responsive SOC interface, dark theme, and high-contrast accessibility |
| Google Gemini (2.5 Flash) | AI-powered security investigation and structured synthesis |
| Zod | Strict request and model-output schema validation |
| Node Test Runner | 13 automated unit, integration, and security resilience tests |
| Vercel | Instant serverless deployment target |

---

## 🔐 Security Design

Security is a core design consideration.

- *Server-side secrets:* AI provider credentials (GEMINI_API_KEY) remain strictly on the server.
- *Input validation:* API requests are validated with Zod before processing.
- *Output validation:* Model responses are strictly validated against the expected schema.
- *Evidence validation:* Findings must reference evidence associated with the investigation. Unknown or hallucinated IDs trigger safe fallback.
- *Action allowlisting:* Only predefined response actions (SIMULATE_LOCK_ACCOUNT, SIMULATE_REVOKE_SESSION, SIMULATE_ISOLATE_HOST, SIMULATE_ESCALATE_INCIDENT) are accepted.
- *Human approval:* Consequential actions fail with HTTP 403 without explicit operator authorization.
- *Safe execution:* Model-generated text is never executed as arbitrary code or commands.
- *Idempotency protection:* Response executions are guarded by unique idempotency tokens, preventing accidental duplicate execution.
- *Error handling:* Failures are reported without exposing secrets or internal stack traces.
- *Auditability:* Investigation and response outcomes are recorded in an append-only audit trail.

### Prototype Limitations

The demonstration uses simulated security events and simulated containment actions. It does not connect to real enterprise security infrastructure or perform real account lockouts.

Target entity states and audit trails operate in a controlled server-side memory layer for portable, zero-dependency deployment. State resets across cold-start serverless instances.

---

## 📊 Efficiency and Evaluation

| Evaluation Area | Demonstration in SentinelFlow |
|---|---|
| *Code Quality* | TypeScript, modular architecture, validated API contracts, and clean design |
| *Security* | Server-side secrets, mandatory human approval, allowlisted actions, and safe failures |
| *Efficiency* | Real-time investigation timing, evidence-processing count, and MTTR comparison |
| *Testing* | 13 automated tests covering happy path, failure injection, and resilience |
| *Accessibility* | Semantic HTML, ARIA states, visible focus rings, and high-contrast color scheme |
| *Alignment* | AI reasoning, controlled automation, independent verification, and audit trail |

---

## 📡 API Endpoint Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | /api/health | Readiness health check, Gemini provider status, and environment stats |
| GET | /api/incidents | List all open incidents and high-level SOC summary statistics |
| GET | /api/incidents/[id] | Fetch single incident case with all synthetic telemetry events |
| POST | /api/investigate | Trigger Gemini AI or Heuristic investigation for an incident case |
| POST | /api/respond | Execute allowlisted containment action with human approval check |
| POST | /api/reset | Reset simulated environment to pristine baseline for repeated demos |
| GET | /api/audit | Fetch append-only audit trail and verification records |

---

## ⚙️ Getting Started

### Prerequisites

- Node.js v20.x or v24.x
- npm v10+
- Git

### 1. Clone the repository

bash
git clone https://github.com/imvedantlokhande-ai/SENTINELFLOW.git
cd SENTINELFLOW


### 2. Install dependencies

bash
npm install


### 3. Configure environment variables (Optional)

Create a .env.local file in the project root:

env
# Optional: If omitted, SentinelFlow runs cleanly in Deterministic Fallback Mode
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.5-flash


> *Note on Demo Mode: If GEMINI_API_KEY is not provided, SentinelFlow runs in **High-Fidelity Deterministic Fallback Mode*. The UI transparently identifies when the deterministic engine is active.

### 4. Start the development server

bash
npm run dev


Open [http://localhost:3000](http://localhost:3000) in your browser.

### 5. Run automated test suite

bash
npm test


Tests cover 13 comprehensive scenarios:
- Request schema validation (valid & invalid)
- Malformed AI response handling & Zod rejection
- Hallucinated / unknown evidence ID rejection
- Out-of-range risk score detection
- Unauthorized action rejection (missing human approval)
- Non-allowlisted action rejection
- Idempotency guard execution (duplicate prevention)
- Independent target state verification
- Deterministic fallback execution
- Full end-to-end incident lifecycle
- Provider outage resilience (missing key / API error fallback)
- Non-existent incident verification guard

---

## ☁️ Deployment on Vercel

SentinelFlow AI is engineered specifically for instantaneous, zero-configuration Vercel deployment.

1. Push the project to GitHub:
   bash
   git push origin main
   
2. Import the repository in [Vercel](https://vercel.com/new).
3. (Optional) In *Project Settings → Environment Variables*, add:
   - GEMINI_API_KEY: Your Google Gemini API Key from [Google AI Studio](https://aistudio.google.com/).
   - GEMINI_MODEL: gemini-2.5-flash
4. Click *Deploy*. The Next.js App Router build completes in ~30 seconds.

*Deployment Checklist:*
- [x] Production build succeeds.
- [x] Dashboard loads responsively.
- [x] Investigation works with Gemini or the clearly labelled fallback.
- [x] Invalid requests and unsupported actions are rejected.
- [x] Response approval is strictly enforced server-side.
- [x] Independent state verification and audit history work as intended.
- [x] No secrets are exposed to the browser.
- [x] Keyboard navigation and accessibility contrast validated.

---

## 🎬 Suggested Demo

For a concise competition demonstration:

1. Open the security dashboard.
2. Select the simulated suspicious-login incident (INC-2026-8812).
3. Run an investigation.
4. Review the findings and supporting evidence tags.
5. Inspect the proposed containment action.
6. Approve the simulated action.
7. Show the independent verification result and audit timeline.
8. Attempt an unsupported or unapproved action in the negative sandbox to demonstrate safe rejection.
9. Explain the efficiency metrics and the prototype boundaries.

---

## 🔮 Future Improvements

- Persistent incident storage with Firestore.
- Firebase Authentication and role-based access control.
- Integration with real security event sources in a controlled staging environment.
- Evaluation datasets for measuring investigation accuracy.
- Human feedback loop for improving investigation quality.
- Advanced correlation and anomaly detection across enterprise tenants.

---

## 👨‍💻 Project Information

*Project:* SentinelFlow AI  
*Challenge:* PromptWars — Build Beyond AI  
*Category:* AI-enabled cybersecurity and autonomous systems  
*Repository:* [imvedantlokhande-ai/SENTINELFLOW](https://github.com/imvedantlokhande-ai/SENTINELFLOW)  
*Deployment platform:* Vercel

### Responsible AI Statement

SentinelFlow AI is a prototype for demonstrating AI-assisted security investigations and controlled response automation. AI findings may be incomplete or incorrect and should be reviewed before consequential decisions. All competition scenarios use simulated security data and simulated response actions.

---

Built to demonstrate that effective AI systems need more than intelligence: they need security, reliability, accountability, and verifiable outcomes.# SENTINELFLOW
