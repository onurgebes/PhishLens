# PhishLens

PhishLens is a local email security analyzer with a framework-independent domain layer. It parses `.eml` files, extracts indicators of compromise (IOCs), applies rule-based phishing heuristics, and produces a transparent risk score — all without sending email content to external services.

**Current milestone:** Phase 5 complete (domain pipeline + FastAPI HTTP layer)

---

## Project overview

PhishLens helps analysts answer three questions about a suspicious email:

1. **What is in the message?** (headers, body, attachments)
2. **What IOCs are present?** (URLs, domains, IPs, emails, file hashes)
3. **How risky is it?** (findings + weighted 0–100 score)

The design separates each concern into its own phase so every layer can be tested and understood independently.

---

## Architecture (Phases 1–5)

```
.eml / raw bytes
       │
       ▼
┌──────────────────┐  Phase 1   EmailParser        → ParsedEmail
└────────┬─────────┘
         ▼
┌──────────────────┐  Phase 2   IOCExtractor       → list[IOC]
└────────┬─────────┘
         ▼
┌──────────────────┐  Phase 3   Analyzers          → list[Finding]
│ HeaderAnalyzer   │            (header, URL, domain,
│ URLAnalyzer      │             attachment, auth)
│ DomainAnalyzer   │
│ AttachmentAnalyzer│
│ SecurityAnalyzer │
└────────┬─────────┘
         ▼
┌──────────────────┐  Phase 4   RiskScoringEngine  → RiskScore
└────────┬─────────┘
         ▼
┌──────────────────┐  Integration PhishLensAnalyzer → AnalysisResult
└────────┬─────────┘
         ▼
┌──────────────────┐  Phase 5   FastAPI            → JSON over HTTP
└──────────────────┘
```

| Phase | Module | Responsibility |
|-------|--------|----------------|
| 1 | `app/domain/parser.py` | Parse raw email bytes into `ParsedEmail` |
| 2 | `app/domain/ioc_extractor.py` | Extract and deduplicate IOCs |
| 3 | `app/domain/analyzers/` | Rule-based findings (22 rules) |
| 4 | `app/domain/scoring/` | Weighted risk score (0–100) |
| Integration | `app/domain/pipeline.py` | `PhishLensAnalyzer` orchestrates Phases 1–4 |
| 5 | `app/api/` | HTTP API wrapping the pipeline |

**Design principles**

- The **domain layer** (`app/domain/`) has zero FastAPI/Pydantic dependencies.
- The **API layer** (`app/api/`) only imports from the domain — never the reverse.
- Attachment **content bytes are never exposed** in API responses (metadata only).
- No network calls, threat intelligence, or machine learning in the current milestone.

---

## Project structure

```
PhishLens/
├── app/
│   ├── domain/           # Phases 1–4 (framework-free)
│   │   ├── parser.py
│   │   ├── ioc_extractor.py
│   │   ├── pipeline.py
│   │   ├── analyzers/
│   │   └── scoring/
│   └── api/              # Phase 5 (FastAPI)
│       ├── main.py
│       ├── routes/
│       ├── schemas/
│       └── serializers/
├── tests/
│   ├── unit/             # Phase 1–4 unit tests
│   ├── integration/      # End-to-end pipeline tests
│   ├── api/              # HTTP API tests
│   └── fixtures/         # Sample .eml files
└── pyproject.toml
```

---

## Installation

Requires **Python 3.11+**.

```powershell
# Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install the package with API and dev/test dependencies
pip install -e ".[api,dev]"
```

| Extra | Packages | Purpose |
|-------|----------|---------|
| *(core)* | stdlib only | Domain layer (Phases 1–4) |
| `api` | FastAPI, uvicorn, python-multipart | Run the HTTP server |
| `dev` | pytest, httpx, FastAPI, python-multipart | Run tests |

---

## Running the API

Start the development server:

```powershell
python -m uvicorn app.api.main:app --reload --host 127.0.0.1 --port 8000
```

Interactive documentation:

- Swagger UI: http://127.0.0.1:8000/docs
- OpenAPI schema: http://127.0.0.1:8000/openapi.json

---

## Available endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check |
| `POST` | `/api/analyze` | Upload a `.eml` file for analysis |
| `POST` | `/api/analyze/raw` | Submit raw RFC 822 email text (UTF-8) |

### Upload limits

- **Accepted file type:** `.eml` only (case-insensitive)
- **Maximum size:** 25 MB (reuses `MAX_EMAIL_SIZE_BYTES` from the domain parser)
- **Empty file:** HTTP 400
- **Wrong extension:** HTTP 400
- **Oversized file:** HTTP 413

---

## Example API usage

### Health check

```powershell
curl http://127.0.0.1:8000/health
```

```json
{"status":"ok","version":"0.1.0"}
```

### Upload an .eml file

```powershell
curl -X POST http://127.0.0.1:8000/api/analyze `
  -F "file=@tests/fixtures/phishing_duplicate_iocs.eml"
```

**Example response (abbreviated):**

```json
{
  "parsed_email": {
    "from_address": "PayPal Security <security@paypa1-secure.com>",
    "subject": "Unusual activity on your account",
    "attachments": [],
    "parse_warnings": []
  },
  "iocs": [ "... 10 IOCs ..." ],
  "findings": [
    {
      "rule_id": "header_display_name_brand_spoofing",
      "severity": "high",
      "title": "Display name references a brand but sender domain is unrelated"
    }
  ],
  "risk_score": {
    "score": 100,
    "level": "critical",
    "raw_points": 118.5,
    "summary": "Risk score: 100/100 (CRITICAL). 5 finding(s) contributed. ...",
    "recommendation": "Emaili silin ve IT guvenlik ekibine iletin. ...",
    "contributions": [ "... score breakdown ..." ]
  }
}
```

### Submit raw email text

```powershell
curl -X POST http://127.0.0.1:8000/api/analyze/raw `
  -H "Content-Type: application/json" `
  -d "{\"raw_email\": \"From: test@example.com\r\nTo: victim@example.com\r\nSubject: Hi\r\n\r\nHello.\"}"
```

---

## Phase 5: FastAPI layer

Phase 5 adds a thin HTTP transport layer around the existing `PhishLensAnalyzer` pipeline:

- **`app/api/routes/`** — endpoint handlers (`/health`, `/api/analyze`, `/api/analyze/raw`)
- **`app/api/schemas/`** — Pydantic request/response models (API-only, not domain models)
- **`app/api/serializers/`** — converts domain `AnalysisResult` to JSON-safe dictionaries
- **`app/api/dependencies.py`** — injects `PhishLensAnalyzer` (overridable in tests)
- **`app/api/errors.py`** — maps domain errors (e.g. `EmailTooLargeError`) to HTTP status codes

The API never re-implements analysis logic. It validates transport concerns (file type, size, empty uploads), calls `PhishLensAnalyzer.analyze(bytes)`, and serializes the result. Attachment `content` bytes are stripped during serialization — only `filename`, `content_type`, and `size_bytes` are returned.

---

## Running tests

```powershell
python -m pytest tests/ -v
```

Quick summary:

```powershell
python -m pytest tests/ -q
```

### Test results (Phase 5 milestone)

```
178 passed
```

| Suite | Tests | Scope |
|-------|-------|-------|
| `tests/unit/` | 156 | Phases 1–4 (parser, IOC, analyzers, scoring) |
| `tests/integration/` | 6 | `PhishLensAnalyzer` pipeline |
| `tests/api/` | 16 | FastAPI HTTP endpoints |

---

## Using the pipeline directly (no HTTP)

```python
from pathlib import Path
from app.domain.pipeline import PhishLensAnalyzer

raw = Path("tests/fixtures/phishing_duplicate_iocs.eml").read_bytes()
result = PhishLensAnalyzer().analyze(raw)

print(result.risk_score.score)   # 100
print(result.risk_score.level)   # RiskLevel.CRITICAL
print(len(result.findings))      # 5
```

---

## What is not included yet

- Database / analysis history (Phase 6+)
- Authentication
- Frontend dashboard
- OSINT / threat intelligence enrichment
- Bulk upload
- Rate limiting

---

## License

University project — see course requirements for usage terms.
