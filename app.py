from flask import Flask, request, jsonify, render_template, send_file
import pickle
import io
from datetime import datetime
import numpy as np

from detectors.url_detector import analyze_url
from detectors.sms_detector import analyze_sms
from detectors.qr_detector import decode_qr_from_bytes
from detectors.dashboard_data import build_dashboard
from detectors.report import generate_report_pdf

app = Flask(__name__)

# ── Load models once at startup ──────────────────────────
with open('models/rf_model.pkl', 'rb') as f:
    rf_model = pickle.load(f)

with open('models/xgb_model.pkl', 'rb') as f:
    xgb_model = pickle.load(f)

with open('models/scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

print("✅ All models loaded — server ready!")

# ── In-memory session activity log (feeds dashboard + report) ────
# Resets on server restart — this is a demo/single-instance store,
# not a database.
ACTIVITY_LOG = []
MAX_LOG = 500


def log_event(event_type, summary, score, verdict, severity, category=None):
    ACTIVITY_LOG.append({
        'ts': datetime.utcnow(),
        'type': event_type,
        'summary': summary,
        'score': score,
        'verdict': verdict,
        'severity': severity,   # 'danger' | 'warning' | 'safe'
        'category': category or 'Card-Not-Present Fraud',
    })
    if len(ACTIVITY_LOG) > MAX_LOG:
        del ACTIVITY_LOG[: len(ACTIVITY_LOG) - MAX_LOG]


# ── Routes ───────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')


# 1) Transaction fraud detection (original ML ensemble) ───────────
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()

        amount = float(data['amount'])
        hour = float(data['hour'])
        distance = float(data['distance'])
        velocity = float(data['velocity'])
        merchant_risk = float(data['merchant_risk'])
        new_device = float(data['new_device'])
        card_present = float(data['card_present'])

        amount_scaled = scaler.transform([[amount]])[0][0]

        v_features = [0.0] * 28
        features = np.array([[*v_features, amount_scaled]])

        rf_prob = rf_model.predict_proba(features)[0][1]
        xgb_prob = xgb_model.predict_proba(features)[0][1]

        risk_score = round((rf_prob + xgb_prob) / 2 * 100, 1)

        if hour < 5 or hour > 23:
            risk_score = min(100, risk_score + 15)
        if distance > 5000:
            risk_score = min(100, risk_score + 20)
        if velocity >= 5:
            risk_score = min(100, risk_score + 25)
        if merchant_risk > 0.7:
            risk_score = min(100, risk_score + 15)
        if new_device == 1:
            risk_score = min(100, risk_score + 10)
        if card_present == 0:
            risk_score = min(100, risk_score + 5)

        if risk_score >= 75:
            decision, color = 'BLOCKED', 'danger'
        elif risk_score >= 45:
            decision, color = 'REVIEW', 'warning'
        else:
            decision, color = 'CLEARED', 'safe'

        log_event('Transaction', f'${amount:,.2f} transaction', risk_score,
                   decision, color, category='Card-Not-Present Fraud')

        return jsonify({
            'risk_score': risk_score,
            'decision': decision,
            'color': color,
            'rf_score': round(rf_prob * 100, 1),
            'xgb_score': round(xgb_prob * 100, 1)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 2) Phishing URL detection ────────────────────────────────────────
@app.route('/predict_url', methods=['POST'])
def predict_url():
    try:
        data = request.get_json()
        url = (data.get('url') or '').strip()
        if not url:
            return jsonify({'error': 'Please provide a URL.'}), 400

        result = analyze_url(url)
        log_event('Phishing URL', result['url'], result['risk_score'],
                   result['verdict'], result['color'], category='Phishing URL')
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 3) SMS scam detection ─────────────────────────────────────────────
@app.route('/predict_sms', methods=['POST'])
def predict_sms():
    try:
        data = request.get_json()
        message = data.get('message') or ''
        if not message.strip():
            return jsonify({'error': 'Please provide an SMS message.'}), 400

        result = analyze_sms(message)
        summary = message[:60] + ('…' if len(message) > 60 else '')
        log_event('SMS Scam', summary, result['risk_score'],
                   result['verdict'], result['color'], category='SMS Smishing')
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 4) QR code scanner ────────────────────────────────────────────────
@app.route('/scan_qr', methods=['POST'])
def scan_qr():
    try:
        if 'qr_image' not in request.files:
            return jsonify({'error': 'No image uploaded.'}), 400

        file = request.files['qr_image']
        image_bytes = file.read()
        if not image_bytes:
            return jsonify({'error': 'Empty image file.'}), 400

        result = decode_qr_from_bytes(image_bytes)
        if not result.get('success'):
            return jsonify(result), 200

        if result.get('is_url'):
            ua = result['url_analysis']
            log_event('QR Code', ua['url'], ua['risk_score'], ua['verdict'],
                       ua['color'], category='QR Code Scam')
        else:
            log_event('QR Code', result['decoded_text'][:60], '—',
                       'DECODED (not a URL)', 'safe', category='QR Code Scam')

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# 5) Live dashboard data feed ───────────────────────────────────────
@app.route('/dashboard_data', methods=['GET'])
def dashboard_data():
    return jsonify(build_dashboard(ACTIVITY_LOG))


# 6) Downloadable report ─────────────────────────────────────────────
@app.route('/generate_report', methods=['GET'])
def generate_report():
    dashboard = build_dashboard(ACTIVITY_LOG)
    pdf_bytes = generate_report_pdf(ACTIVITY_LOG, dashboard)
    filename = f"fraudshield-report-{datetime.utcnow().strftime('%Y%m%d-%H%M')}.pdf"
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename,
    )


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
