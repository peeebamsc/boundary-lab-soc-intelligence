# BOUNDARY//LAB
### SOC Intelligence Platform | AI-Assisted Security Event Analysis

BOUNDARY//LAB is a Python-based Security Operations Center (SOC) intelligence prototype designed to demonstrate how deterministic threat detection and local large language models can work together to support security investigations.

The platform processes synthetic authentication events, assigns risk scores, generates structured security assessments, and provides a dashboard for monitoring security activity.

Its primary architectural principle is separating security decision-making from AI-generated explanations.

## Project Objectives

BOUNDARY//LAB explores several important challenges in modern security operations:

- Automating security event classification and triage.
- Maintaining deterministic risk scoring independent of generative AI.
- Generating AI-assisted security investigation summaries.
- Preserving security event history for analysis.
- Evaluating the reliability and limitations of AI-generated security conclusions.
- Establishing a foundation for prompt-injection and evidence-contamination testing.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.11 | Core application development |
| FastAPI | Security analysis API |
| Pydantic | Data validation and structured models |
| SQLite | Persistent security event storage |
| Streamlit | SOC monitoring dashboard |
| Pandas | Event history visualization |
| Ollama | Local LLM inference |
| Llama 3.2 3B | AI-generated security assessments |
| Pytest | Automated testing |
| Git / GitHub | Version control |

## Architecture

```text
Synthetic Authentication Events
              |
              v
       FastAPI Backend
              |
              v
       Event Validation
              |
              v
    Deterministic Log Analysis
              |
              v
       Alert Classification
              |
              v
       Risk Score Generation
              |
       +------+------+
       |             |
       v             v
 SQLite Storage   SOC Explanation
       |             |
       v             v
 Streamlit UI    Local LLM Analysis
                     |
                     v
              Analyst Guidance
```

The deterministic authentication pipeline and the AI analysis endpoint are currently separate workflows.

The AI model generates advisory explanations without directly modifying the risk score returned by the deterministic triage system.

## Core Features

### 1. Security Event Analysis

Processes structured authentication events and normalizes security information.

Demonstration severity thresholds:

| Failed Attempts | Severity |
|---|---|
| 0 | Low |
| 1–4 | Medium |
| 5–9 | High |
| 10+ | Critical |

These thresholds are demonstration heuristics, not production-calibrated detection rules.

### 2. Automated Alert Triage

Assigns deterministic classifications and risk scores.

| Severity | Risk Score | Classification |
|---|---|---|
| Low | 10 | Benign |
| Medium | 40 | Needs Review |
| High | 70 | Suspicious |
| Critical | 95 | Suspicious |

Risk scores represent illustrative values rather than statistically calibrated probabilities.

### 3. SOC Copilot

Generates structured explanations that include:

- Security event classification.
- Supporting evidence.
- Recommended investigation actions.
- Limitations of available information.

The baseline SOC Copilot uses deterministic logic rather than a language model.

### 4. Local AI Security Analyst

Integrates Ollama with Llama 3.2 3B to generate additional security assessments.

The AI analyst provides:

- Threat assessments.
- Supporting evidence summaries.
- Investigation recommendations.
- Evidence limitations.

The model operates locally without requiring a paid cloud inference API.

AI-generated conclusions are advisory and may contain unsupported assumptions.

### 5. Security Event Persistence

Uses SQLite to store processed security events, classifications, risk scores, and supporting analysis.

### 6. SOC Monitoring Dashboard

The Streamlit dashboard provides:

- Authentication event submission.
- Security analysis results.
- Historical event records.
- Risk score visualization.
- Deterministic SOC Copilot explanations.

AI-generated explanations are currently available through a separate API endpoint.

## API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Application information |
| `/health` | GET | API health status |
| `/events/analyze` | POST | Analyze a structured security event |
| `/logs/authentication` | POST | Process an authentication log |
| `/events/history` | GET | Retrieve stored event history |
| `/ai/analyze` | POST | Generate a local AI-assisted assessment |

## Installation

### Prerequisites

- Python 3.11
- Git
- Ollama
- Llama 3.2 3B

### Clone the Repository

```powershell
git clone https://github.com/peeebamsc/boundary-lab-soc-intelligence.git
cd boundary-lab-soc-intelligence
```

### Create a Virtual Environment

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Install Dependencies

```powershell
pip install -r requirements.txt
```

### Install the Local AI Model

Install Ollama, then run:

```powershell
ollama pull llama3.2:3b
```

### Start the FastAPI Backend

```powershell
python -m uvicorn app.main:app --port 8000
```

### Start the Streamlit Dashboard

Open another terminal:

```powershell
.\.venv\Scripts\Activate.ps1
python -m streamlit run dashboard/app.py
```

Access the dashboard at the local URL displayed by Streamlit.

## Automated Testing

Run:

```powershell
python -m pytest -q
```

Latest verified local result:

**49 tests passed — November 9, 2026.**

The tests cover event processing, validation, triage, structured explanations, persistence functions, API behavior, and mocked AI integration behavior.

A successful mocked AI test does not establish the reliability or security of the underlying language model.

## Security Considerations

BOUNDARY//LAB is currently a local development prototype.

Important limitations include:

- Authentication events use synthetic data.
- Detection rules are simplified demonstration heuristics.
- The AI model can generate unsupported security conclusions.
- Prompt-injection resistance has not been comprehensively evaluated.
- The AI endpoint currently accepts a supplied event severity.
- The application does not yet implement production authentication, authorization, or deployment hardening.
- The platform is not intended for unsupervised security response decisions.

## Development Roadmap

- [x] Security event normalization
- [x] Deterministic alert triage
- [x] Structured SOC explanations
- [x] SQLite event persistence
- [x] Streamlit dashboard
- [x] Local LLM integration
- [x] Automated regression testing
- [ ] AI hallucination evaluation framework
- [ ] Prompt-injection testing
- [ ] Evidence-contamination evaluations
- [ ] AI explanation integration into dashboard
- [ ] Docker deployment
- [ ] GitHub Actions CI/CD
- [ ] Expanded security controls

## Engineering Focus

BOUNDARY//LAB demonstrates practical work involving:

**Cybersecurity Engineering | Security Automation | Python Development | REST APIs | AI Integration | Security Testing | Event Analysis | Local LLM Deployment**

The project is intended for continued experimentation with trustworthy AI-assisted security workflows.

## Repository

GitHub: https://github.com/peeebamsc/boundary-lab-soc-intelligence