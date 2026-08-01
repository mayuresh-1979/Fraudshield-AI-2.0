"""
QR Code Scanner — decode an uploaded image with OpenCV's built-in QR
detector (no external system libraries needed, unlike pyzbar/libzbar,
which keeps this deployable on plain Render/Heroku-style buildpacks) and
run the decoded payload through the phishing URL heuristic when it looks
like a URL.
"""
import re
import numpy as np
import cv2

from .url_detector import analyze_url

_detector = cv2.QRCodeDetector()

URL_LIKE = re.compile(r'^(https?://|www\.)', re.IGNORECASE)


def decode_qr_from_bytes(image_bytes: bytes) -> dict:
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)

    if img is None:
        return {'success': False, 'error': 'Could not read image file.'}

    data, points, _ = _detector.detectAndDecode(img)

    if not data:
        # try multi-detect as a fallback (handles some tricky scans)
        ok, decoded_info, pts, _ = _detector.detectAndDecodeMulti(img)
        if ok and decoded_info and decoded_info[0]:
            data = decoded_info[0]

    if not data:
        return {
            'success': False,
            'error': 'No QR code detected in this image. Try a clearer photo.',
        }

    result = {'success': True, 'decoded_text': data}

    if URL_LIKE.match(data.strip()):
        result['is_url'] = True
        result['url_analysis'] = analyze_url(data.strip())
    else:
        result['is_url'] = False

    return result
