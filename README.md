# PhishLens

PhishLens is an email security analysis system that parses `.eml` files, extracts indicators of compromise (IOCs), applies rule-based phishing heuristics, and produces a transparent risk score - all without sending email content to external services.

## Live Demo

[https://phish-lens-pearl.vercel.app](https://phish-lens-pearl.vercel.app)

## GitHub Repository

[https://github.com/onurgebes/PhishLens](https://github.com/onurgebes/PhishLens)

## Project Overview

PhishLens helps security analysts answer three critical questions about a suspicious email:

1. **What is in the message?** - Parses headers, body content, and attachment metadata
2. **What IOCs are present?** - Extracts URLs, domains, IP addresses, email addresses, and file hashes
3. **How risky is it?** - Applies rule-based detection and produces a weighted 0-100 risk score

The system is designed with a clean separation of concerns, making each layer independently testable and maintainable.

## Current Status

PhishLens is a deployed full-stack MVP with both frontend and backend available online:

- **Frontend:** React + TypeScript + Vite + Tailwind CSS dashboard
- **Backend:** FastAPI REST API with comprehensive test coverage
- **Deployment:** Both services deployed on Vercel

## Architecture

The system follows a layered architecture with clear separation between domain logic and API concerns:

```
.eml / raw bytes
       |
       v
+------------------+  EmailParser        -> ParsedEmail
+------------------+
         |
         v
+------------------+  IOCExtractor       -> list[IOC]
+------------------+
         |
         v
+------------------+  Analyzers          -> list[Finding]
| HeaderAnalyzer   |            (header, URL, domain,
| URLAnalyzer      |             attachment, auth)
| DomainAnalyzer   |
| AttachmentAnalyzer|
| SecurityAnalyzer |
+------------------+
         |
         v
+------------------+  RiskScoringEngine  -> RiskScore
+------------------+
         |
         v
+------------------+  PhishLensAnalyzer -> AnalysisResult
+------------------+
         |
         v
+------------------+  FastAPI            -> JSON over HTTP
+------------------+
```

### Analysis Pipeline

| Component | Responsibility |
|-----------|----------------|
| **EmailParser** | Parses raw RFC 822 email bytes into structured `ParsedEmail` object |
| **IOCExtractor** | Extracts and deduplicates IOCs (URLs, domains, IPs, emails, file hashes) |
| **Analyzers** | Rule-based detection (header, URL, domain, attachment, authentication) |
| **RiskScoringEngine** | Calculates weighted risk score (0-100) with transparent contributions |
| **PhishLensAnalyzer** | Orchestrates the entire pipeline |
| **FastAPI Layer** | HTTP API wrapping the domain pipeline |

## Design Principles

- **Domain Independence:** The domain layer (`app/domain/`) has zero FastAPI/Pydantic dependencies
- **Unidirectional Dependencies:** The API layer only imports from the domain - never the reverse
- **Security by Design:** Attachment content bytes are never exposed in API responses (metadata only)
- **Rule-Based Detection:** No machine learning or external threat intelligence - transparent, explainable analysis
- **Privacy:** No network calls or external service integrations

## Tech Stack

### Backend
- **Language:** Python 3.11+
- **Framework:** FastAPI
- **Validation:** Pydantic
- **Testing:** pytest
- **ASGI Server:** uvicorn

### Frontend
- **Framework:** React 18
- **Language:** TypeScript
- **Build Tool:** Vite
- **Styling:** Tailwind CSS
- **Deployment:** Vercel

## Project Structure

```
PhishLens/
├── app/
│   ├── domain/           # Core business logic (framework-independent)
│   │   ├── parser.py
│   │   ├── ioc_extractor.py
│   │   ├── pipeline.py
│   │   ├── analyzers/
│   │   └── scoring/
│   └── api/              # FastAPI HTTP layer
│       ├── main.py
│       ├── routes/
│       ├── schemas/
│       └── serializers/
├── frontend/             # React + TypeScript frontend
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── types/
│   ├── package.json
│   └── vite.config.ts
├── tests/
│   ├── unit/             # Domain layer unit tests
│   ├── integration/      # Pipeline integration tests
│   ├── api/              # HTTP API tests
│   └── fixtures/         # Sample .eml files
└── pyproject.toml
```

## Installation

### Backend

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
| *(core)* | stdlib only | Domain layer only |
| `api` | FastAPI, uvicorn, python-multipart | Run the HTTP server |
| `dev` | pytest, httpx, FastAPI, python-multipart | Run tests |

### Frontend

Requires **Node.js 18+**.

```powershell
cd frontend
npm install
```

## Running the Application

### Backend API

Start the development server:

```powershell
python -m uvicorn app.api.main:app --reload --host 127.0.0.1 --port 8000
```

Interactive documentation:
- Swagger UI: http://127.0.0.1:8000/docs
- OpenAPI schema: http://127.0.0.1:8000/openapi.json

### Frontend

Start the development server:

```powershell
cd frontend
npm run dev
```

The frontend will be available at http://localhost:5173

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check |
| `POST` | `/api/analyze` | Upload a `.eml` file for analysis |
| `POST` | `/api/analyze/raw` | Submit raw RFC 822 email text (UTF-8) |

### Upload Limits

- **Accepted file type:** `.eml` only (case-insensitive)
- **Maximum size:** 25 MB
- **Empty file:** HTTP 400
- **Wrong extension:** HTTP 400
- **Oversized file:** HTTP 413

## Example API Usage

### Health Check

```powershell
curl http://127.0.0.1:8000/health
```

```json
{"status":"ok","version":"0.1.0"}
```

### Upload an .eml File

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
  "iocs": [
    {
      "type": "url",
      "value": "http://paypa1-secure.com/login",
      "source": "body"
    }
  ],
  "findings": [
    {
      "rule_id": "header_display_name_brand_spoofing",
      "severity": "high",
      "title": "Display name references a brand but sender domain is unrelated",
      "evidence": "Display name: 'PayPal Security', Sender domain: 'paypa1-secure.com'"
    }
  ],
  "risk_score": {
    "score": 100,
    "level": "critical",
    "raw_points": 118.5,
    "summary": "Risk score: 100/100 (CRITICAL). 5 finding(s) contributed.",
    "recommendation": "Delete the email and report to IT security team.",
    "contributions": [
      {
        "rule_id": "header_display_name_brand_spoofing",
        "points": 35.0,
        "severity": "high"
      }
    ]
  }
}
```

### Submit Raw Email Text

```powershell
curl -X POST http://127.0.0.1:8000/api/analyze/raw `
  -H "Content-Type: application/json" `
  -d "{\"raw_email\": \"From: test@example.com\r\nTo: victim@example.com\r\nSubject: Hi\r\n\r\nHello.\"}"
```

## Risk Scoring

The risk scoring engine produces a transparent 0-100 score based on weighted contributions from detected findings:

- **0-24:** LOW
- **25-49:** MEDIUM
- **50-74:** HIGH
- **75-100:** CRITICAL

Each finding contributes points based on its severity:
- **LOW:** 10 points
- **MEDIUM:** 20 points
- **HIGH:** 35 points
- **CRITICAL:** 50 points

The final score is clamped to 100, and a summary explains which findings contributed to the score.

## Security Analysis

PhishLens applies rule-based detection across multiple vectors:

### Header Analysis
- Brand spoofing detection (display name vs. sender domain)
- Missing authentication headers (SPF, DKIM, DMARC)
- Reply-to mismatches
- Suspicious subject lines

### URL Analysis
- IP address URLs
- URL shortener detection
- Suspicious TLDs
- Lookalike domains

### Domain Analysis
- Suspicious TLDs
- Lookalike domain detection

### Attachment Analysis
- Executable file types
- Suspicious extensions
- Double extensions

### Security Analysis
- Missing TLS indicators
- HTML form submissions to external domains

## Testing

Run the full test suite:

```powershell
python -m pytest tests/ -v
```

Quick summary:

```powershell
python -m pytest tests/ -q
```

### Test Coverage

| Suite | Scope |
|-------|-------|
| `tests/unit/` | Domain layer (parser, IOC extractor, analyzers, scoring) |
| `tests/integration/` | End-to-end pipeline tests |
| `tests/api/` | FastAPI HTTP endpoint tests |

## Using the Pipeline Directly

The domain layer can be used independently without HTTP:

```python
from pathlib import Path
from app.domain.pipeline import PhishLensAnalyzer

raw = Path("tests/fixtures/phishing_duplicate_iocs.eml").read_bytes()
result = PhishLensAnalyzer().analyze(raw)

print(result.risk_score.score)   # 100
print(result.risk_score.level)   # RiskLevel.CRITICAL
print(len(result.findings))      # 5
print(len(result.iocs))          # 10
```

## Limitations & Future Improvements

### Current Limitations
- No analysis history or database persistence
- No user authentication
- No OSINT or threat intelligence enrichment
- No bulk analysis capabilities
- No rate limiting
- No real-time domain reputation checks

### Potential Future Enhancements
- Database integration for analysis history
- User authentication and authorization
- Integration with threat intelligence APIs
- Machine learning-based detection
- Bulk upload and analysis
- Rate limiting and API quotas
- Real-time IOC enrichment
- Integration with SIEM platforms

## Project Goals

PhishLens was designed to demonstrate:

- Clean architecture with separation of concerns
- Framework-independent domain modeling
- Comprehensive test coverage
- Transparent, explainable security analysis
- Well-structured API design
- Modern frontend development practices

## Deployment

The project is deployed on Vercel:

- **Frontend:** https://phish-lens-pearl.vercel.app
- **Backend API:** https://phishlens-eight.vercel.app

Both services are configured with CORS to allow cross-origin requests from the frontend.

## License

University project - see course requirements for usage terms.
