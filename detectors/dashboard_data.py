"""
Live Dashboard data feed.

There is no production data warehouse behind this demo, so we generate a
realistic, internally-consistent "today" baseline (deterministically seeded
by the calendar date, so it doesn't jump around on every refresh) and then
layer the *actual* activity that has happened in this server session
(real transaction / URL / SMS / QR checks run by the user) on top of it.
That keeps the dashboard honest about anything the user actually did while
still looking like a live production feed rather than an empty shell.
"""
import random
from datetime import datetime, timedelta

CATEGORIES = [
    'Card-Not-Present Fraud', 'Phishing URL', 'SMS Smishing',
    'Account Takeover', 'QR Code Scam', 'Fake Merchant', 'Velocity Abuse',
]


def _seeded_rng():
    seed = int(datetime.utcnow().strftime('%Y%m%d'))
    return random.Random(seed)


def _hourly_baseline(rng):
    """24 values, shaped like a realistic attack curve (higher at night)."""
    hours = []
    now_hour = datetime.utcnow().hour
    for h in range(24):
        base = 4 if 9 <= h <= 21 else 10  # more fraud attempts overnight
        val = base + rng.randint(-2, 6)
        if h > now_hour:
            val = 0  # hasn't happened yet "today"
        hours.append(max(0, val))
    return hours


def build_dashboard(activity_log: list) -> dict:
    rng = _seeded_rng()

    baseline_hourly = _hourly_baseline(rng)
    baseline_blocked = sum(int(v * 0.4) for v in baseline_hourly)
    baseline_review = sum(int(v * 0.25) for v in baseline_hourly)
    baseline_genuine = rng.randint(180, 260)

    baseline_categories = {c: rng.randint(3, 40) for c in CATEGORIES}

    # ── layer real session activity on top ──────────────────────────
    live_blocked = live_review = live_cleared = 0
    live_hourly = [0] * 24
    live_categories = {c: 0 for c in CATEGORIES}
    heat = [[0] * 24 for _ in range(7)]  # 7 "days" x 24 hours, demo heatmap

    for ev in activity_log:
        ts = ev['ts']
        hour = ts.hour
        weekday = ts.weekday()
        sev = ev['severity']  # 'danger' | 'warning' | 'safe'
        cat = ev.get('category', 'Card-Not-Present Fraud')

        if sev == 'danger':
            live_blocked += 1
            heat[weekday][hour] += 2
        elif sev == 'warning':
            live_review += 1
            heat[weekday][hour] += 1
        else:
            live_cleared += 1

        live_hourly[hour] += 1
        live_categories[cat] = live_categories.get(cat, 0) + 1

    hourly = [b + l for b, l in zip(baseline_hourly, live_hourly)]
    blocked = baseline_blocked + live_blocked
    review = baseline_review + live_review
    genuine = baseline_genuine + live_cleared
    total_attacks = blocked + review

    categories = {c: baseline_categories[c] + live_categories.get(c, 0)
                  for c in CATEGORIES}

    # simple demo heatmap: baseline shape + live overlay
    heatmap = []
    for d in range(7):
        row = []
        for h in range(24):
            base = rng.randint(0, 5) if (9 <= h <= 23) else rng.randint(0, 2)
            row.append(base + heat[d][h])
        heatmap.append(row)

    risk_distribution = {
        'Blocked (High Risk)': blocked,
        'Under Review (Medium Risk)': review,
        'Cleared (Low Risk)': genuine,
    }

    return {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'fraud_attempts_today': total_attacks,
        'genuine_transactions': genuine,
        'blocked': blocked,
        'under_review': review,
        'risk_distribution': risk_distribution,
        'hourly_attacks': {
            'labels': [f'{h:02d}:00' for h in range(24)],
            'values': hourly,
        },
        'fraud_categories': categories,
        'heatmap': {
            'days': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            'hours': [f'{h:02d}' for h in range(24)],
            'matrix': heatmap,
        },
        'live_events_this_session': len(activity_log),
    }
