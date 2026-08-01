"""
SMS Scam Detection — weighted keyword / pattern heuristic engine.

Same rationale as the URL detector: no labeled SMS corpus ships with this
project, so we score against known scam-SMS patterns (urgency & threats,
prize/lottery bait, credential/OTP harvesting, impersonation of banks or
delivery companies, embedded links, excessive urgency punctuation) and
surface exactly which patterns fired.
"""
import re
from .url_detector import analyze_url

URGENCY = [
    'urgent', 'immediately', 'act now', 'act fast', 'expire', 'expires',
    'expiring', 'within 24 hours', 'last chance', 'final notice',
    'account suspended', 'account will be blocked', 'action required',
    'limited time'
]

PRIZE_BAIT = [
    'won', 'winner', 'lottery', 'prize', 'jackpot', 'claim your',
    'free gift', 'cash reward', 'congratulations', 'lucky draw',
    'you have been selected', 'gift card'
]

CREDENTIAL_HARVEST = [
    'otp', 'one time password', 'pin number', 'cvv', 'card number',
    'password', 'verify your account', 'confirm your identity',
    'update your kyc', 'bank details', 'ssn', 'social security',
    'login credentials', 'security code'
]

IMPERSONATION = [
    'your bank', 'income tax', 'irs', 'customs', 'courier', 'delivery',
    'parcel', 'package could not be delivered', 'electricity board',
    'your account', 'refund', 'tax refund', 'unpaid toll', 'court',
    'arrest warrant', 'police'
]

CTA = [
    'click here', 'click the link', 'call now', 'call this number',
    'reply yes', 'text back', 'download the app', 'install app'
]

URL_RE = re.compile(
    r'((?:https?://|www\.)[^\s]+|\b[a-zA-Z0-9-]+\.(?:com|net|org|xyz|tk|'
    r'top|club|info|biz|ru|cn)(?:/[^\s]*)?)', re.IGNORECASE
)
PHONE_RE = re.compile(r'\b(\+?\d[\d\s-]{7,}\d)\b')


def _count_hits(text: str, terms: list) -> list:
    return [t for t in terms if t in text]


def analyze_sms(message: str) -> dict:
    text = message.lower()
    score = 0
    flags = []

    urgency_hits = _count_hits(text, URGENCY)
    if urgency_hits:
        score += min(20, 7 * len(urgency_hits))
        flags.append(f"Urgency/pressure language: {', '.join(urgency_hits[:3])}")

    prize_hits = _count_hits(text, PRIZE_BAIT)
    if prize_hits:
        score += min(25, 9 * len(prize_hits))
        flags.append(f"Prize/lottery bait: {', '.join(prize_hits[:3])}")

    cred_hits = _count_hits(text, CREDENTIAL_HARVEST)
    if cred_hits:
        score += min(30, 10 * len(cred_hits))
        flags.append(f"Requests sensitive info: {', '.join(cred_hits[:3])}")

    imp_hits = _count_hits(text, IMPERSONATION)
    if imp_hits:
        score += min(18, 6 * len(imp_hits))
        flags.append(f"Impersonation cues: {', '.join(imp_hits[:3])}")

    cta_hits = _count_hits(text, CTA)
    if cta_hits:
        score += min(15, 8 * len(cta_hits))
        flags.append(f"Call-to-action pressure: {', '.join(cta_hits[:3])}")

    urls_found = URL_RE.findall(message)
    url_analysis = None
    if urls_found:
        score += 12
        flags.append(f'Contains embedded link ({len(urls_found)} found)')
        # score the first URL found through the phishing engine too
        url_analysis = analyze_url(urls_found[0])
        if url_analysis['risk_score'] >= 60:
            score += 15
            flags.append('Embedded link itself scores as a phishing URL')

    if PHONE_RE.search(message):
        score += 5
        flags.append('Contains a callback phone number')

    caps_ratio = sum(1 for c in message if c.isupper()) / max(1, len(message))
    if caps_ratio > 0.3 and len(message) > 15:
        score += 8
        flags.append('Excessive capitalization')

    if message.count('!') >= 3:
        score += 5
        flags.append('Excessive exclamation marks')

    score = min(100, score)

    if score >= 48:
        verdict, color = 'SCAM', 'danger'
    elif score >= 24:
        verdict, color = 'SUSPICIOUS', 'warning'
    else:
        verdict, color = 'SAFE', 'safe'

    if not flags:
        flags.append('No known scam patterns detected')

    return {
        'risk_score': score,
        'verdict': verdict,
        'color': color,
        'flags': flags,
        'urls_found': urls_found,
        'url_analysis': url_analysis,
    }
