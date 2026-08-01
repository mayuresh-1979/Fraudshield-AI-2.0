# FraudShield AI 2.0 — Unified Fraud Intelligence Platform

A single Flask app that brings together transaction fraud detection, phishing URL scanning, SMS scam detection, QR code analysis, and a live fraud-intelligence dashboard — all in one interface.

![Status](https://img.shields.io/badge/status-active-brightgreen) ![Python](https://img.shields.io/badge/python-3.10+-blue) ![Flask](https://img.shields.io/badge/flask-backend-black)

---

## Features

### 1. Transaction Fraud Detection
Ensemble of a **Random Forest** and **XGBoost** classifier, trained on transaction data, scores each transaction and blends the ML output with rule-based risk boosts (odd hours, high velocity, unusual distance from home, new device, card-not-present, high-risk merchant). Returns a 0–100 risk score and a `CLEARED` / `REVIEW` / `BLOCKED` decision.

### 2. Phishing URL Detection
A transparent, weighted heuristic engine — no black-box model, no dependency on a labeled phishing dataset. Flags raw-IP hosts, punycode/homograph domains, `@` host-spoofing tricks, excessive subdomains, brand-impersonation lookalikes, high-risk TLDs (`.tk`, `.ml`, `.xyz`, `.top`...), known URL shorteners, and high-entropy auto-generated domains. Every flag that fires is surfaced to the user, not just a score.

### 3. SMS Scam Detection
Same heuristic philosophy applied to SMS text: urgency/pressure language, prize-and-lottery bait, credential/OTP harvesting phrases, authority impersonation (banks, tax offices, couriers), call-to-action pressure, and embedded links — which are automatically re-scanned through the URL engine.

### 4. QR Code Scanner
Upload a QR image → decoded with OpenCV's built-in `QRCodeDetector` (no system-level `libzbar` dependency, so it deploys cleanly on minimal hosting environments) → if the payload is a URL, it's piped straight into the phishing engine for a Safe / Suspicious / Dangerous verdict.

### 5. Live Dashboard
Real-time fraud intelligence view combining a deterministic daily baseline with actual session activity:
- Fraud attempts today, genuine transactions, blocked / under-review counts
- Risk distribution (Chart.js doughnut)
- Fraud categories breakdown (Chart.js bar)
- Hourly attack volume (ApexCharts)
- Day × hour attack heatmap (Plotly)

### 6. Downloadable Report
One-click PDF export (via ReportLab) summarizing the dashboard snapshot and the full session activity log — every transaction, URL, SMS, and QR check run during the session.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Flask (Python) |
| ML models | scikit-learn (Random Forest), XGBoost |
| URL / SMS detection | Custom rule-based heuristic engines |
| QR decoding | OpenCV (`opencv-python-headless`) |
| PDF reports | ReportLab |
| Charts | Chart.js, ApexCharts, Plotly.js |
| Frontend | Vanilla HTML/CSS/JS (no build step) |
| Deployment | Render (Gunicorn WSGI) |

---

## Project Structure

```
fraudshield-ai/
├── app.py                     # Flask app — all routes
├── requirements.txt
├── render.yaml                 # Render Blueprint config
├── models/
│   ├── rf_model.pkl            # Random Forest classifier
│   ├── xgb_model.pkl           # XGBoost classifier
│   └── scaler.pkl              # StandardScaler for transaction amount
├── detectors/
│   ├── url_detector.py         # Phishing URL heuristic engine
│   ├── sms_detector.py         # SMS scam heuristic engine
│   ├── qr_detector.py          # QR decode + URL analysis
│   ├── dashboard_data.py       # Live dashboard data feed
│   └── report.py               # PDF report generator
├── templates/
│   └── index.html              # Single-page app, all 5 tabs
└── static/                     # (reserved — currently unused)
```

---

## Getting Started (Local)

**Requirements:** Python 3.10+

```bash
git clone https://github.com/<your-username>/fraudshield-ai.git
cd fraudshield-ai

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
python app.py
```

The app runs at `http://localhost:5000`.

---

## API Reference

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/` | Serves the single-page dashboard |
| `POST` | `/predict` | Transaction fraud score (JSON body: amount, hour, distance, velocity, merchant_risk, new_device, card_present) |
| `POST` | `/predict_url` | Phishing URL scan (JSON body: `{ "url": "..." }`) |
| `POST` | `/predict_sms` | SMS scam scan (JSON body: `{ "message": "..." }`) |
| `POST` | `/scan_qr` | QR code decode + analysis (multipart form, field name `qr_image`) |
| `GET` | `/dashboard_data` | Live dashboard JSON feed |
| `GET` | `/generate_report` | Downloads a PDF activity report |

---

## Deployment

This repo ships with a `render.yaml` Blueprint for one-click deployment on [Render](https://render.com):

1. Push this repo to GitHub
2. On Render: **New +** → **Blueprint** → connect the repo
3. Render reads `render.yaml` and deploys automatically with Gunicorn

Also deployable on Google Cloud Run, Hugging Face Spaces (Docker), or Fly.io with a Dockerfile.

---

## Known Limitations

- **In-memory activity log** — the data behind the Live Dashboard and PDF report is stored in a plain Python list, not a database. It resets on every server restart and assumes a single running instance. Fine for a demo; swap in SQLite/Postgres for anything persistent.
- **Heuristic, not ML-trained, URL/SMS/QR detection** — no labeled phishing/scam dataset shipped with this project, so those three modules use transparent weighted rule engines rather than trained classifiers. They're tuned against known scam patterns but won't catch novel attack styles a trained model might.
- **Dashboard numbers are partly simulated** — a deterministic daily baseline is blended with real session activity so the dashboard looks populated immediately, rather than starting empty.

---

## Test Data

A companion test dataset (sample URLs, SMS messages, transactions, and pre-generated QR code images with known-good/known-bad labels) is available separately for exercising every module end-to-end.

---
