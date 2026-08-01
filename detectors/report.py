"""
Downloadable Report — builds a PDF summary of the current session's
activity (transaction / URL / SMS / QR checks) plus the live dashboard
snapshot, using reportlab (pure-Python, no system deps → safe on Render).
"""
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

INK = colors.HexColor('#1A1612')
ACCENT = colors.HexColor('#C8460A')
DIM = colors.HexColor('#7A7268')
SAFE = colors.HexColor('#2A7A4A')
WARN = colors.HexColor('#D4860A')
DANGER = colors.HexColor('#C8460A')

SEVERITY_COLOR = {'danger': DANGER, 'warning': WARN, 'safe': SAFE}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle('TitleBig', parent=ss['Title'], fontSize=24,
                           textColor=INK, spaceAfter=2))
    ss.add(ParagraphStyle('SubTitle', parent=ss['Normal'], fontSize=10,
                           textColor=DIM, spaceAfter=14))
    ss.add(ParagraphStyle('Section', parent=ss['Heading2'], fontSize=13,
                           textColor=INK, spaceBefore=16, spaceAfter=8))
    ss.add(ParagraphStyle('Body', parent=ss['Normal'], fontSize=9.5,
                           textColor=INK, leading=13))
    return ss


def generate_report_pdf(activity_log: list, dashboard: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=22 * mm, bottomMargin=18 * mm,
        leftMargin=18 * mm, rightMargin=18 * mm,
    )
    ss = _styles()
    story = []

    story.append(Paragraph('FRAUDSHIELD AI — INTELLIGENCE REPORT', ss['TitleBig']))
    story.append(Paragraph(
        f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · "
        f"Unified Fraud Intelligence Platform", ss['SubTitle']))

    # ── summary stats ────────────────────────────────────────────
    story.append(Paragraph('Today at a Glance', ss['Section']))
    summary_rows = [
        ['Metric', 'Value'],
        ['Fraud attempts today', str(dashboard['fraud_attempts_today'])],
        ['Genuine transactions', str(dashboard['genuine_transactions'])],
        ['Blocked (high risk)', str(dashboard['blocked'])],
        ['Under review (medium risk)', str(dashboard['under_review'])],
        ['Events analyzed this session', str(dashboard['live_events_this_session'])],
    ]
    t = Table(summary_rows, colWidths=[90 * mm, 60 * mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), INK),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, -1), 9.5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D8D2C8')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F4F1EC')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # ── fraud categories ─────────────────────────────────────────
    story.append(Paragraph('Fraud Categories (Today)', ss['Section']))
    cat_rows = [['Category', 'Count']] + [
        [k, str(v)] for k, v in dashboard['fraud_categories'].items()
    ]
    t2 = Table(cat_rows, colWidths=[110 * mm, 40 * mm])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EDE9E2')),
        ('FONTSIZE', (0, 0), (-1, -1), 9.5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D8D2C8')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t2)

    # ── session activity log ────────────────────────────────────
    story.append(Paragraph('Session Activity Log', ss['Section']))
    if not activity_log:
        story.append(Paragraph('No checks were run in this session.', ss['Body']))
    else:
        rows = [['Time', 'Type', 'Summary', 'Risk', 'Verdict']]
        for ev in activity_log[-100:]:
            rows.append([
                ev['ts'].strftime('%H:%M:%S'),
                ev['type'],
                Paragraph(ev['summary'][:70], ss['Body']),
                str(ev.get('score', '—')),
                ev.get('verdict', '—'),
            ])
        t3 = Table(rows, colWidths=[20 * mm, 28 * mm, 72 * mm, 15 * mm, 25 * mm], repeatRows=1)
        style_cmds = [
            ('BACKGROUND', (0, 0), (-1, 0), INK),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#D8D2C8')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]
        for i, ev in enumerate(activity_log[-100:], start=1):
            c = SEVERITY_COLOR.get(ev.get('severity'), DIM)
            style_cmds.append(('TEXTCOLOR', (4, i), (4, i), c))
        t3.setStyle(TableStyle(style_cmds))
        story.append(t3)

    story.append(Spacer(1, 14))
    story.append(Paragraph(
        'FraudShield AI — Random Forest + XGBoost ensemble for transactions; '
        'rule-based heuristic engines for URL / SMS / QR analysis. '
        'Dashboard figures blend a simulated daily baseline with real activity '
        'from this session.', ss['SubTitle']))

    doc.build(story)
    return buf.getvalue()
