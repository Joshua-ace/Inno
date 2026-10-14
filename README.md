# DaddyDefender - Digital Threat Detection

DaddyDefender is a real-time threat detection application designed to identify phishing attempts, fraudulent messages, and malicious links. It combines rule-based heuristic scoring, cryptographic entropy calculations, domain reputation verification, and optional AI-assisted threat summaries.

## Features

- **URL Analysis**: Scans for IP-based hosts, punycode/IDN spoofing, typosquatting, deceptive brand impersonation, high-entropy paths, and URLhaus threat feeds.
- **Message Analysis**: Inspects SMS, email, and chat messages for artificial urgency, financial requests, credential theft, and suspicious links.
- **Scoring Engine**: Normalizes risk into clear categories (Safe, Low, Suspicious, Dangerous) with confidence ratings and specific indicator breakdowns.
- **Scan History**: Stores scans locally in SQLite for easy auditing and review.
- **Clean Interface**: Fast, responsive dark UI built with vanilla HTML5, CSS3, and JavaScript.

## Architecture

- **Frontend**: Single-page application served via static files (`index.html`, `style.css`, `app.js`).
- **Backend API**: Python FastAPI service (`backend/main.py`) running on port 8000.
- **Database**: SQLite database for scan storage and lookup (`backend/daddydefender.db`).
- **External Providers**: Optional integrations for VirusTotal and Google Gemini. The engine runs completely offline with local heuristics if no external API keys are configured.

## Quick Start

### 1. Backend Setup

Prerequisites: Python 3.10 or higher.

```bash
# Navigate to backend directory
cd backend

# Create and activate a virtual environment (optional but recommended)
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
# source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Configure environment variables
copy .env.example .env

# Start the FastAPI server
python main.py
```

The backend server starts at `http://127.0.0.1:8000`. You can verify API health at `http://127.0.0.1:8000/api/health`.

### 2. Frontend Setup

Serve the root directory with any static file server:

```bash
# Example with Python's built-in HTTP server:
python -m http.server 5500
```

Open `http://localhost:5500` in your web browser.

## Running Tests

Pytest test suite covers API routing, message heuristics, URL structure parsing, and composite scoring:

```bash
python -m pytest backend/tests
```

## Project Structure

```
Inno/
├── index.html              # Main application page
├── style.css               # Application stylesheet
├── app.js                  # Frontend client logic and API integration
├── favicon.svg             # Application icon
├── privacy-policy.html     # Privacy Policy
├── terms.html              # Terms and Conditions
├── legal.css               # Legal pages styling
└── backend/
    ├── main.py             # FastAPI entrypoint
    ├── config.py           # Configuration and environment settings
    ├── database.py         # SQLite connection and session management
    ├── models.py           # Database models and Pydantic schemas
    ├── requirements.txt    # Python dependencies
    ├── providers/          # Gemini, VirusTotal, and URLhaus integrations
    ├── routers/            # FastAPI route handlers (analyze, scans, health)
    ├── scoring/            # Core heuristic engines (URL, message, composite)
    └── tests/              # Test suite (31 unit and integration tests)
```

## Security and Privacy

DaddyDefender performs local heuristics on the backend instance. Submissions are stored strictly for scan history lookup and are not sold or transmitted to third parties without configured external API providers.
