"""
Phishing URL Detection — rule/heuristic based feature scorer.

No labeled phishing-URL training set ships with this project, so instead of a
black-box model this module uses a transparent, weighted heuristic engine —
the same category of signals (lexical + host based) used in published
phishing-URL feature sets (URL length, IP-literal host, '@' tricks, punycode,
suspicious TLDs, shortener services, brand-impersonation keywords, etc).
Every flag that fires is returned to the caller so the UI can explain *why*
a URL was scored the way it was, not just spit out a number.
"""
import re
import math
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'click',
    'link', 'zip', 'mov', 'country', 'stream', 'gdn', 'kim', 'loan',
    'racing', 'accountant', 'science', 'party', 'bid', 'win'
}

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'rebrand.ly', 'cutt.ly', 'shorte.st', 'tiny.cc', 'rb.gy',
    'shorturl.at', 'v.gd'
}

BRAND_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm',
    'password', 'banking', 'webscr', 'suspend', 'urgent', 'billing',
    'security', 'alert', 'authenticate', 'wallet', 'unlock', 'recover',
    'support', 'invoice', 'payment', 'refund', 'gift', 'reward', 'bonus'
]

BRAND_NAMES = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 'bank',
    'facebook', 'instagram', 'whatsapp', 'irs', 'dhl', 'fedex', 'ups'
]

IP_RE = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def analyze_url(raw_url: str) -> dict:
    url = raw_url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = 'http://' + url

    flags = []
    score = 0

    try:
        parsed = urlparse(url)
    except Exception:
        return {
            'url': raw_url, 'risk_score': 100, 'verdict': 'DANGEROUS',
            'color': 'danger', 'flags': ['Malformed / unparsable URL'],
        }

    host = (parsed.hostname or '').lower()
    path = parsed.path or ''
    full = url.lower()

    # 1. IP address as host
    if host and IP_RE.match(host):
        score += 25
        flags.append('Uses raw IP address instead of a domain name')

    # 2. Length
    if len(url) > 100:
        score += 15
        flags.append('Unusually long URL (>100 chars)')
    elif len(url) > 60:
        score += 8
        flags.append('Long URL (>60 chars)')

    # 3. '@' trick — everything before '@' is ignored by browsers
    if '@' in url:
        score += 20
        flags.append("Contains '@' — classic host-spoofing trick")

    # 4. Punycode / IDN homograph
    if 'xn--' in host:
        score += 20
        flags.append('Punycode host — possible homograph attack')

    # 5. Excess subdomains (skip for raw-IP hosts, already flagged above)
    if host and not IP_RE.match(host):
        labels = host.split('.')
        if len(labels) > 4:
            score += 15
            flags.append(f'Excessive subdomains ({len(labels)} labels)')
        elif len(labels) > 3:
            score += 8
            flags.append('Multiple subdomains')

    # 6. Hyphens in domain (brand lookalikes: paypal-secure-login.com)
    if host.count('-') >= 2:
        score += 10
        flags.append('Multiple hyphens in domain (lookalike pattern)')

    # 7. No HTTPS
    if parsed.scheme != 'https':
        score += 12
        flags.append('Not using HTTPS')

    # 8. Suspicious / free TLD
    tld = host.split('.')[-1] if '.' in host else ''
    if tld in SUSPICIOUS_TLDS:
        score += 15
        flags.append(f'High-risk TLD (.{tld})')

    # 9. URL shortener
    if host in SHORTENERS:
        score += 20
        flags.append('Known URL shortener — real destination is hidden')

    # 10. Brand name + non-official domain (impersonation)
    for brand in BRAND_NAMES:
        if brand in host and not host.endswith(f'{brand}.com'):
            score += 22
            flags.append(f"Impersonates brand '{brand}' on a lookalike domain")
            break

    # 11. Suspicious keywords in path/host
    kw_hits = [k for k in BRAND_KEYWORDS if k in full]
    if kw_hits:
        add = min(20, 5 * len(kw_hits))
        score += add
        flags.append(f"Suspicious keywords: {', '.join(kw_hits[:5])}")

    # 12. Port explicitly specified
    if parsed.port and parsed.port not in (80, 443):
        score += 10
        flags.append(f'Non-standard port specified ({parsed.port})')

    # 13. Double-slash redirect trick in path
    if '//' in path:
        score += 10
        flags.append("'//' redirect pattern found in path")

    # 14. Excess special characters
    special_count = sum(url.count(c) for c in ['%', '=', '&', '?'])
    if special_count > 6:
        score += 10
        flags.append('High density of special/encoded characters')

    # 15. High entropy host (randomly generated domains)
    if host and _shannon_entropy(host.replace('.', '')) > 4.0 and len(host) > 12:
        score += 10
        flags.append('High-entropy / auto-generated-looking domain')

    score = min(100, score)

    if score >= 60:
        verdict, color = 'DANGEROUS', 'danger'
    elif score >= 30:
        verdict, color = 'SUSPICIOUS', 'warning'
    else:
        verdict, color = 'SAFE', 'safe'

    if not flags:
        flags.append('No known phishing signals detected')

    return {
        'url': raw_url,
        'host': host,
        'risk_score': score,
        'verdict': verdict,
        'color': color,
        'flags': flags,
    }
