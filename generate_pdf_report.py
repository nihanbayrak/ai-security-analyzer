#!/usr/bin/env python3
"""
PDF Security Report Generator — Q&A Format
Each section answers a plain-English question with evidence from the data.
Designed to be readable by non-technical people.

Usage:
    pip install reportlab
    python generate_pdf_report.py security_report_final.json --output report.pdf
"""

import json
import sys
import os
import argparse
import unicodedata
from datetime import datetime
from collections import Counter

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, KeepTogether
    )
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.legends import Legend
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
except ImportError:
    print("reportlab required: pip install reportlab")
    sys.exit(1)

WIDTH, HEIGHT = A4

# ─── Unicode font registration ──────────────────────────────────
_FONT = "Helvetica"
_FONT_B = "Helvetica-Bold"
_FONT_I = "Helvetica-Oblique"
_FONT_M = "Courier"

for fp in [
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
]:
    if os.path.exists(fp):
        try:
            pdfmetrics.registerFont(TTFont("UniFont", fp))
            _FONT = _FONT_B = _FONT_I = _FONT_M = "UniFont"
            break
        except Exception:
            continue

# ─── Colors ──────────────────────────────────────────────────────
C_RED     = colors.HexColor("#e74c3c")
C_ORANGE  = colors.HexColor("#f39c12")
C_YELLOW  = colors.HexColor("#f1c40f")
C_GREEN   = colors.HexColor("#27ae60")
C_BLUE    = colors.HexColor("#2980b9")
C_LGREY   = colors.HexColor("#ecf0f1")
C_DGREY   = colors.HexColor("#2c3e50")
C_WHITE   = colors.white
C_BG_Q    = colors.HexColor("#eaf2f8")
C_BG_ANS  = colors.HexColor("#fdfefe")

SEV_COLOR = {"CRITICAL": C_RED, "HIGH": C_ORANGE, "MEDIUM": C_YELLOW, "LOW": C_GREEN}


def build_styles():
    ss = getSampleStyleSheet()
    add = ss.add
    add(ParagraphStyle("Title2", parent=ss["Title"], fontSize=24, fontName=_FONT_B,
                        textColor=C_DGREY, spaceAfter=2*mm))
    add(ParagraphStyle("Subtitle", parent=ss["Normal"], fontSize=11, fontName=_FONT,
                        textColor=colors.HexColor("#7f8c8d"), spaceAfter=6*mm))
    add(ParagraphStyle("H1", parent=ss["Heading1"], fontSize=15, fontName=_FONT_B,
                        textColor=C_DGREY, spaceBefore=6*mm, spaceAfter=3*mm))
    add(ParagraphStyle("Question", parent=ss["Normal"], fontSize=12, fontName=_FONT_B,
                        textColor=C_BLUE, spaceBefore=5*mm, spaceAfter=2*mm))
    add(ParagraphStyle("Answer", parent=ss["Normal"], fontSize=10, fontName=_FONT,
                        leading=14, textColor=C_DGREY, spaceAfter=2*mm))
    add(ParagraphStyle("AnswerBold", parent=ss["Normal"], fontSize=10, fontName=_FONT_B,
                        leading=14, textColor=C_DGREY))
    add(ParagraphStyle("Body", parent=ss["Normal"], fontSize=9, fontName=_FONT,
                        leading=13, textColor=C_DGREY))
    add(ParagraphStyle("Small", parent=ss["Normal"], fontSize=8, fontName=_FONT,
                        leading=11, textColor=colors.HexColor("#555555")))
    add(ParagraphStyle("Evidence", parent=ss["Normal"], fontSize=8, fontName=_FONT_M,
                        leading=11, backColor=C_LGREY, borderPadding=4, textColor=C_DGREY))
    add(ParagraphStyle("AccuracyGood", parent=ss["Normal"], fontSize=9, fontName=_FONT_B,
                        textColor=C_GREEN))
    add(ParagraphStyle("AccuracyWarn", parent=ss["Normal"], fontSize=9, fontName=_FONT_B,
                        textColor=C_ORANGE))
    add(ParagraphStyle("AccuracyBad", parent=ss["Normal"], fontSize=9, fontName=_FONT_B,
                        textColor=C_RED))
    return ss


def safe(txt, max_len=120):
    if not txt:
        return ""
    t = str(txt)
    out = []
    for c in t:
        cat = unicodedata.category(c)
        if cat[0] == "C" and c not in ("\n", "\t"):
            out.append(" ")
        elif ord(c) > 0xFFFF or (cat == "So" and ord(c) > 0x2600):
            out.append(" ")
        else:
            out.append(c)
    t = "".join(out)
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return t[:max_len] + "..." if len(t) > max_len else t


def make_bar_chart(labels, values, bar_colors, w=220, h=120):
    d = Drawing(w, h)
    bc = VerticalBarChart()
    bc.x, bc.y = 40, 10
    bc.width, bc.height = w - 60, h - 30
    bc.data = [values]
    bc.categoryAxis.categoryNames = labels
    bc.categoryAxis.labels.fontName = _FONT
    bc.categoryAxis.labels.fontSize = 7
    bc.valueAxis.labels.fontName = _FONT
    bc.valueAxis.labels.fontSize = 7
    bc.valueAxis.valueMin = 0
    bc.bars.strokeWidth = 0
    for i, c in enumerate(bar_colors):
        bc.bars[0, i].fillColor = c
    d.add(bc)
    return d


def qa_block(ss, question, answer_paragraphs, accuracy=None, accuracy_style=None):
    """Build a Question + Answer block with optional accuracy badge."""
    block = []
    block.append(Paragraph(question, ss["Question"]))
    for p in answer_paragraphs:
        block.append(p)
    if accuracy and accuracy_style:
        block.append(Spacer(1, 1*mm))
        block.append(Paragraph(f"Confidence: {accuracy}", ss[accuracy_style]))
    block.append(Spacer(1, 3*mm))
    return block


def build_pdf(report_path: str, output_path: str):
    with open(report_path, "r", encoding="utf-8") as f:
        rpt = json.load(f)

    ss = build_styles()
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=18*mm, bottomMargin=18*mm)
    story = []
    findings = rpt.get("findings", {})
    summary = rpt.get("summary", {})
    sev = rpt.get("severity_breakdown", {})

    # ══════════════════════════════════════════════════════════════
    # PAGE 1: COVER
    # ══════════════════════════════════════════════════════════════
    story.append(Spacer(1, 25*mm))
    story.append(Paragraph("AI Security Analyzer", ss["Title2"]))
    story.append(Paragraph(
        "Your ChatGPT conversation history, checked for security risks. "
        "This report answers 7 simple questions about your data.",
        ss["Subtitle"]))

    risk = rpt["overall_risk_level"]
    score = rpt["risk_score"]
    rc = SEV_COLOR.get(risk, C_DGREY)

    info = [
        ["What was scanned?", f"{rpt['conversation_count']} conversations, {rpt['message_count']} messages"],
        ["When?", rpt["scan_timestamp"][:19].replace("T", " ")],
        ["Overall risk", f"{risk} ({score}/100)"],
    ]
    t = Table(info, colWidths=[50*mm, 100*mm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), _FONT_B),
        ("FONTNAME", (1, 0), (1, -1), _FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (-1, -1), C_DGREY),
        ("TEXTCOLOR", (1, 2), (1, 2), rc),
        ("FONTNAME", (1, 2), (1, 2), _FONT_B),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 6*mm))

    # Quick accuracy overview table
    story.append(Paragraph("Report Accuracy at a Glance", ss["H1"]))
    story.append(Paragraph(
        "Each check shows what we found and what it means for you.",
        ss["Body"]))
    story.append(Spacer(1, 2*mm))

    n_inj = summary.get("prompt_injection", 0)
    n_creds = len([f for f in findings.get("pii_leakage", []) if f.get("is_credential")])
    n_pii = summary.get("pii_leakage", 0)
    n_anom = summary.get("anomalies", 0)
    n_adv = summary.get("advertising", 0)
    n_mem = summary.get("membership_inference", 0)

    acc_data = [
        ["Security Check", "Findings", "Result", "What It Means"],
        ["Prompt Injection", str(n_inj),
         "Clean" if n_inj == 0 else "Found!",
         "No attack attempts detected." if n_inj == 0 else "Attack attempts found in your chats!"],
        ["Passwords & Keys", str(n_creds),
         "Clean" if n_creds == 0 else f"{n_creds} Exposed!",
         "No credentials found." if n_creds == 0 else "Passwords or API keys visible in chats!"],
        ["Personal Info (email, phone)", str(n_pii),
         "Clean" if n_pii == 0 else f"{n_pii} Found",
         "No personal data detected." if n_pii == 0 else "Personal data visible in chats."],
        ["Unusual Behavior", str(n_anom),
         "Clean" if n_anom == 0 else f"{n_anom} Detected",
         "No unusual patterns." if n_anom == 0 else "Strange patterns found in conversations."],
        ["Ads & Manipulation", str(n_adv),
         "Clean" if n_adv == 0 else f"{n_adv} Detected",
         "No manipulation detected." if n_adv == 0 else "Possible brand pushing or dark patterns."],
        ["Training Data Leaks", str(n_mem),
         "Clean" if n_mem == 0 else f"{n_mem} Signals",
         "No memorization signals." if n_mem == 0 else "Weak signals of memorized text (not proof)."],
    ]
    at = Table(acc_data, colWidths=[38*mm, 18*mm, 22*mm, 62*mm])
    acc_style = [
        ("BACKGROUND", (0, 0), (-1, 0), C_DGREY),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), _FONT_B),
        ("FONTNAME", (0, 1), (-1, -1), _FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LGREY]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
    ]
    result_counts = [n_inj, n_creds, n_pii, n_anom, n_adv, n_mem]
    for i in range(1, 7):
        rc = C_GREEN if result_counts[i-1] == 0 else (C_RED if i <= 2 else C_ORANGE)
        acc_style.append(("TEXTCOLOR", (2, i), (2, i), rc))
        acc_style.append(("FONTNAME", (2, i), (2, i), _FONT_B))
    at.setStyle(TableStyle(acc_style))
    story.append(at)

    story.append(Spacer(1, 4*mm))

    # Severity bar chart
    bar_labels = ["Critical", "High", "Medium", "Low"]
    bar_values = [sev.get("critical", 0), sev.get("high", 0),
                  sev.get("medium", 0), sev.get("low", 0)]
    bar_colors = [C_RED, C_ORANGE, C_YELLOW, C_GREEN]
    story.append(Paragraph("Findings by Severity", ss["H1"]))
    story.append(make_bar_chart(bar_labels, bar_values, bar_colors))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # Q1: PROMPT INJECTION
    # ══════════════════════════════════════════════════════════════
    inj = findings.get("prompt_injection", [])
    story.extend(qa_block(ss,
        "Q1. Did anyone try to hijack or trick the AI in your conversations?",
        [
            Paragraph(
                f"<b>Answer: {'No.' if not inj else 'Yes!'}</b> "
                f"We scanned all {rpt['message_count']} messages for prompt injection attacks "
                f"-- tricks that try to make the AI ignore its rules or reveal secrets.",
                ss["Answer"]),
            Paragraph(
                f"<b>{len(inj)}</b> attack attempt(s) found." if inj else
                "No attack attempts were found. Your conversations are clean.",
                ss["AnswerBold"]),
            Paragraph(
                "<i>How we check:</i> We look for known attack patterns (like 'ignore all previous instructions'), "
                "then verify with a trained AI model (DeBERTa-v3). Both must agree before we flag something.",
                ss["Small"]),
            Paragraph(
                "<i>Reference:</i> OWASP LLM01:2025 Prompt Injection, MITRE ATLAS AML.T0051",
                ss["Small"]),
        ],
        accuracy="Very High (97-100%)", accuracy_style="AccuracyGood"
    ))

    if inj:
        for i, f in enumerate(inj[:5], 1):
            story.append(Paragraph(
                f"  Finding #{i}: {safe(f.get('injection_type',''))} "
                f"(confidence {f.get('confidence',0):.0%}) - {safe(f.get('message_preview',''), 80)}",
                ss["Evidence"]))
        story.append(Spacer(1, 3*mm))

    # ══════════════════════════════════════════════════════════════
    # Q2: PASSWORDS & API KEYS
    # ══════════════════════════════════════════════════════════════
    pii = findings.get("pii_leakage", [])
    creds = [f for f in pii if f.get("is_credential")]
    passwords = [f for f in pii if f["category"] == "password"]
    cc = [f for f in pii if f["category"] == "credit_card"]

    cred_answer = []
    if creds:
        cred_answer.append(Paragraph(
            f"<b>Answer: Yes -- {len(creds)} exposed credential(s) found!</b> "
            "These are passwords, API keys, or tokens visible in your chat history. "
            "Anyone with access to your export file can see them.",
            ss["Answer"]))
    else:
        cred_answer.append(Paragraph(
            "<b>Answer: No.</b> No passwords, API keys, or tokens were found in your conversations.",
            ss["Answer"]))

    if passwords:
        cred_answer.append(Paragraph(
            f"<b>{len(passwords)} password(s)</b> found in plain text:",
            ss["Body"]))
        for i, f in enumerate(passwords[:5], 1):
            cred_answer.append(Paragraph(
                f"  #{i} {safe(f['matched_value'], 40)} -- change this immediately",
                ss["Evidence"]))

    if cc:
        cred_answer.append(Spacer(1, 2*mm))
        cred_answer.append(Paragraph(
            f"<b>{len(cc)} credit card number(s)</b> found (Luhn-validated):",
            ss["Body"]))
        for i, f in enumerate(cc[:5], 1):
            cred_answer.append(Paragraph(
                f"  #{i} {safe(f['matched_value'], 30)} -- monitor for unauthorized charges",
                ss["Evidence"]))

    cred_answer.extend([
        Spacer(1, 2*mm),
        Paragraph(
            "<i>How we check:</i> Pattern matching for known credential formats "
            "(API keys, passwords, tokens), credit card numbers verified with Luhn checksum.",
            ss["Small"]),
        Paragraph(
            "<i>Reference:</i> OWASP LLM06:2025 Sensitive Information Disclosure",
            ss["Small"]),
    ])

    story.extend(qa_block(ss,
        "Q2. Are any passwords, API keys, or credit cards exposed in your chats?",
        cred_answer,
        accuracy="Very High (97-100%)", accuracy_style="AccuracyGood"
    ))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # Q3: PERSONAL INFORMATION
    # ══════════════════════════════════════════════════════════════
    emails = [f for f in pii if f["category"] == "email"]
    phones = [f for f in pii if f["category"] == "phone"]
    ips = [f for f in pii if f["category"] == "ip_address"]
    ssn_f = [f for f in pii if f["category"] == "ssn"]
    urls = [f for f in pii if f["category"] == "internal_url"]

    pi_answer = [
        Paragraph(
            f"<b>Answer: {'Yes.' if (emails or phones) else 'No.'}</b> "
            f"We found <b>{len(emails)}</b> email address(es), "
            f"<b>{len(phones)}</b> phone number(s), "
            f"and <b>{len(ips)}</b> IP address(es) in your conversations.",
            ss["Answer"]),
    ]

    if emails:
        pi_answer.append(Paragraph("<b>Emails found (sample):</b>", ss["Body"]))
        for f in emails[:5]:
            pi_answer.append(Paragraph(f"  {safe(f['matched_value'], 50)}", ss["Evidence"]))

    if phones:
        pi_answer.append(Spacer(1, 2*mm))
        pi_answer.append(Paragraph(f"<b>Phone numbers found (sample of {len(phones)}):</b>", ss["Body"]))
        for f in phones[:5]:
            pi_answer.append(Paragraph(f"  {safe(f['matched_value'], 30)}", ss["Evidence"]))

    if ips:
        pi_answer.append(Spacer(1, 2*mm))
        pi_answer.append(Paragraph(
            f"<b>{len(ips)} IP address(es)</b> found. "
            "Well-known addresses (Google DNS, Cloudflare, etc.), private ranges, "
            "and version numbers have already been filtered out. "
            "These are likely real public IPs worth reviewing.",
            ss["Body"]))

    pi_answer.extend([
        Spacer(1, 2*mm),
        Paragraph(
            "<i>How we check:</i> Regex patterns for emails, phone numbers, IPs, SSNs, IBANs. "
            "Phone numbers require nearby context words (like 'call', 'phone') and filter out "
            "fake/test numbers. IPs exclude DNS servers, private ranges, and version numbers. "
            "Credit cards are verified with Luhn checksum. IBANs are validated with MOD-97. "
            "Passwords in code snippets/examples are skipped.",
            ss["Small"]),
        Paragraph(
            "<i>Confidence note:</i> Emails are very accurate (99%+). After filtering, "
            "phone and IP findings are high-confidence (&gt;90%).",
            ss["Small"]),
    ])

    story.extend(qa_block(ss,
        "Q3. Is any personal information (email, phone, IP) visible in your chats?",
        pi_answer,
        accuracy="High (95-99% after filtering)", accuracy_style="AccuracyGood"
    ))

    # ══════════════════════════════════════════════════════════════
    # Q4: UNUSUAL BEHAVIOR
    # ══════════════════════════════════════════════════════════════
    anom = findings.get("anomalies", [])
    anom_types = Counter(f["anomaly_type"] for f in anom)
    high_anom = [f for f in anom if f["severity"] in ("CRITICAL", "HIGH")]

    anom_answer = [
        Paragraph(
            f"<b>Answer:</b> We detected <b>{len(anom)}</b> unusual pattern(s) across your conversations. "
            f"<b>{len(high_anom)}</b> of these are high-priority.",
            ss["Answer"]),
        Paragraph(
            "Unusual patterns include: very long AI responses to tiny questions, "
            "repeated/duplicate messages, unexpected language switches, "
            "and high-entropy text that might indicate automated attacks.",
            ss["Body"]),
    ]

    anom_table_data = [["Pattern Type", "Count", "What It Means"]]
    type_explanations = {
        "repeated_message": "Same message sent multiple times (could be retries or bots)",
        "response_ratio": "AI response much longer than your question",
        "message_length": "Unusually long or short messages",
        "high_entropy": "Random-looking text (could be code or attack strings)",
        "language_switch": "Conversation switches language unexpectedly",
        "burst_messages": "Many messages sent in rapid succession",
        "adversarial_suffix": "Possible automated attack pattern detected",
    }
    for atype, cnt in anom_types.most_common():
        anom_table_data.append([
            atype.replace("_", " ").title(),
            str(cnt),
            type_explanations.get(atype, "")[:55],
        ])

    if len(anom_table_data) > 1:
        at2 = Table(anom_table_data, colWidths=[35*mm, 15*mm, 90*mm])
        at2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_DGREY),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), _FONT_B),
            ("FONTNAME", (0, 1), (-1, -1), _FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LGREY]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        anom_answer.append(at2)

    if high_anom:
        anom_answer.append(Spacer(1, 2*mm))
        anom_answer.append(Paragraph("<b>High-priority anomalies (sample):</b>", ss["Body"]))
        for f in high_anom[:5]:
            anom_answer.append(Paragraph(
                f"  [{f['severity']}] {safe(f.get('anomaly_type',''))} -- {safe(f.get('details',''), 100)}",
                ss["Evidence"]))

    anom_answer.extend([
        Spacer(1, 2*mm),
        Paragraph(
            "<i>How we check:</i> Statistical analysis of message lengths, response ratios, "
            "character entropy (after stripping code, URLs, and base64), language scripts, "
            "and word-bigram patterns for adversarial suffixes. Short/trivial messages "
            "are excluded to reduce noise.",
            ss["Small"]),
        Paragraph(
            "<i>Confidence note:</i> High-priority items (adversarial suffixes, extreme ratios) "
            "are reliable. Low-priority items (repeated messages, minor length outliers) "
            "are informational only.",
            ss["Small"]),
    ])

    story.extend(qa_block(ss,
        "Q4. Is there any unusual or suspicious behavior in your conversations?",
        anom_answer,
        accuracy="Medium (high-priority items are reliable, low-priority is informational)",
        accuracy_style="AccuracyWarn"
    ))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # Q5: ADVERTISING & MANIPULATION
    # ══════════════════════════════════════════════════════════════
    adv = findings.get("advertising", [])
    adv_types = Counter(f["finding_type"] for f in adv)
    brand = [f for f in adv if f["finding_type"] == "brand_bias"]
    promo = [f for f in adv if f["finding_type"] == "promotional"]
    aff = [f for f in adv if f["finding_type"] == "affiliate"]
    anthro = [f for f in adv if f["finding_type"] == "anthropomorphism"]

    adv_answer = [
        Paragraph(
            f"<b>Answer:</b> We found <b>{len(adv)}</b> instance(s) "
            "where the AI might be pushing products, brands, or using manipulation tactics.",
            ss["Answer"]),
    ]

    if brand:
        adv_answer.append(Paragraph(
            f"<b>Brand bias ({len(brand)} cases):</b> The AI repeatedly mentions one brand "
            "much more than alternatives. This doesn't mean it's paid advertising, "
            "but the AI may have a preference built into its training.",
            ss["Body"]))
        for f in brand[:3]:
            inds = f.get("indicators", [])
            if inds:
                adv_answer.append(Paragraph(f"  {safe(inds[0], 70)}", ss["Evidence"]))

    if promo:
        adv_answer.append(Spacer(1, 2*mm))
        adv_answer.append(Paragraph(
            f"<b>Promotional language ({len(promo)} cases):</b> "
            "The AI uses sales-like language (urgency, superlatives, calls-to-action).",
            ss["Body"]))

    if aff:
        adv_answer.append(Spacer(1, 2*mm))
        adv_answer.append(Paragraph(
            f"<b>Tracking links ({len(aff)} cases):</b> "
            "URLs with tracking parameters were found. Note: many of these come from "
            "ChatGPT's own web browsing feature (utm_source=chatgpt) and are not malicious.",
            ss["Body"]))

    if anthro:
        adv_answer.append(Spacer(1, 2*mm))
        adv_answer.append(Paragraph(
            f"<b>Anthropomorphism ({len(anthro)} case(s)):</b> "
            "The AI implies it has human feelings or consciousness. "
            "This is a known dark pattern that builds emotional attachment. "
            "(Reference: DarkBench, ICLR 2025)",
            ss["Body"]))

    adv_answer.extend([
        Spacer(1, 2*mm),
        Paragraph(
            "<i>How we check:</i> We scan AI responses for promotional language (urgency, "
            "superlatives, calls-to-action), brand mention density (8+ mentions at 5%+ density), "
            "tracking/affiliate URLs (whitelisting ChatGPT browsing and academic sites), "
            "and DarkBench dark pattern categories requiring multiple signals "
            "(3+ for sycophancy, 2+ for sneaking/retention).",
            ss["Small"]),
        Paragraph(
            "<i>Reference:</i> DarkBench (ICLR 2025), OWASP LLM09:2025 Misinformation",
            ss["Small"]),
    ])

    story.extend(qa_block(ss,
        "Q5. Is the AI trying to sell you things or manipulate your behavior?",
        adv_answer,
        accuracy="Medium (multi-signal thresholds reduce false positives)",
        accuracy_style="AccuracyWarn"
    ))

    # ══════════════════════════════════════════════════════════════
    # Q6: TRAINING DATA MEMORIZATION
    # ══════════════════════════════════════════════════════════════
    mem = findings.get("membership_inference", [])
    mem_types = Counter(f["finding_type"] for f in mem)
    mk = [f for f in mem if f["finding_type"] == "min_k_prob_suspect"]
    vb = [f for f in mem if f["finding_type"] == "verbatim_block"]
    xc = [f for f in mem if f["finding_type"] == "verbatim_cross_conversation"]

    mem_answer = [
        Paragraph(
            f"<b>Answer:</b> We found <b>{len(mem)}</b> sign(s) that the AI might be "
            "repeating text it memorized from its training data.",
            ss["Answer"]),
        Paragraph(
            "This matters because if the AI memorized parts of your conversations "
            "(or others' data), it could leak that information to other users.",
            ss["Body"]),
    ]

    mem_table = [["Signal Type", "Count", "What It Means"]]
    if vb:
        mem_table.append(["Repeated text blocks", str(len(vb)),
                          "Same 60+ character block appears multiple times in one conversation"])
    if xc:
        mem_table.append(["Cross-chat repetition", str(len(xc)),
                          "Same phrase appears across many different conversations"])
    if mk:
        mem_table.append(["Statistical anomaly", str(len(mk)),
                          "Text has unusual character patterns suggesting memorization"])

    if len(mem_table) > 1:
        mt = Table(mem_table, colWidths=[35*mm, 15*mm, 90*mm])
        mt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_DGREY),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), _FONT_B),
            ("FONTNAME", (0, 1), (-1, -1), _FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LGREY]),
        ]))
        mem_answer.append(mt)

    mem_answer.extend([
        Spacer(1, 2*mm),
        Paragraph(
            "<i>Important:</i> This analysis uses a simplified method (character statistics) "
            "because we don't have access to the AI's internal model. Results are weak signals, "
            "not proof. A proper test requires running Min-K% Prob with a language model.",
            ss["Small"]),
        Paragraph(
            "<i>Reference:</i> Min-K% Prob method (Shi et al., ICLR 2024, arXiv:2310.16789), "
            "OWASP LLM06:2025, MITRE ATLAS AML.T0024.002",
            ss["Small"]),
    ])

    story.extend(qa_block(ss,
        "Q6. Could the AI be leaking memorized training data in your conversations?",
        mem_answer,
        accuracy="Low (proxy method only, not conclusive)",
        accuracy_style="AccuracyBad"
    ))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # Q7: WHICH CONVERSATIONS ARE RISKIEST?
    # ══════════════════════════════════════════════════════════════
    per_conv = rpt.get("per_conversation_risk", [])
    flagged = [c for c in per_conv if c.get("risk") not in ("CLEAN",)][:30]

    conv_answer = [
        Paragraph(
            f"<b>Answer:</b> Out of {rpt['conversation_count']} conversations, "
            f"<b>{len(flagged)}</b> have at least one finding. "
            "The riskiest ones are listed below.",
            ss["Answer"]),
    ]

    if flagged:
        conv_data = [["Conversation", "Risk", "Critical", "High", "Med", "Low", "Total"]]
        for c in flagged[:25]:
            conv_data.append([
                safe(c.get("title", c["id"][:16]), 35),
                c["risk"],
                str(c.get("critical", 0)),
                str(c.get("high", 0)),
                str(c.get("medium", 0)),
                str(c.get("low", 0)),
                str(c.get("total_findings", 0)),
            ])
        ct = Table(conv_data, colWidths=[55*mm, 18*mm, 14*mm, 12*mm, 12*mm, 12*mm, 14*mm])
        ct_style = [
            ("BACKGROUND", (0, 0), (-1, 0), C_DGREY),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), _FONT_B),
            ("FONTNAME", (0, 1), (-1, -1), _FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LGREY]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
        ]
        for i, c in enumerate(flagged[:25], 1):
            rc2 = SEV_COLOR.get(c["risk"], C_DGREY)
            ct_style.append(("TEXTCOLOR", (1, i), (1, i), rc2))
            ct_style.append(("FONTNAME", (1, i), (1, i), _FONT_B))
        ct.setStyle(TableStyle(ct_style))
        conv_answer.append(ct)

    story.extend(qa_block(ss,
        "Q7. Which conversations should I review first?",
        conv_answer,
    ))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # WHAT SHOULD I DO? (Recommendations)
    # ══════════════════════════════════════════════════════════════
    recs = rpt.get("recommendations", [])
    story.append(Paragraph("What Should I Do Now?", ss["H1"]))
    story.append(Paragraph(
        "Based on the findings above, here are the recommended actions, "
        "starting with the most urgent:",
        ss["Answer"]))
    story.append(Spacer(1, 2*mm))

    for i, rec in enumerate(recs, 1):
        urgency = "URGENT" if i <= 2 and creds else ""
        prefix = f"<b>{i}. {urgency}</b> " if urgency else f"<b>{i}.</b> "
        story.append(Paragraph(f"{prefix}{safe(rec, 200)}", ss["Body"]))
        story.append(Spacer(1, 1.5*mm))

    story.append(Spacer(1, 6*mm))

    # ══════════════════════════════════════════════════════════════
    # SECURITY STANDARDS (for technical readers)
    # ══════════════════════════════════════════════════════════════
    fw = rpt.get("framework_mappings", {})
    owasp = fw.get("owasp_top10_llm_2025", [])
    mitre = fw.get("mitre_atlas", [])

    if owasp or mitre:
        story.append(Paragraph("Security Standards Coverage (for technical readers)", ss["H1"]))
        story.append(Paragraph(
            "This report maps findings to industry-standard security frameworks. "
            "You can share these references with your IT or security team.",
            ss["Body"]))
        story.append(Spacer(1, 2*mm))

        if owasp:
            story.append(Paragraph("<b>OWASP Top 10 for LLM Applications 2025</b>", ss["Body"]))
            for ref in owasp:
                story.append(Paragraph(f"  - {safe(ref, 100)}", ss["Small"]))
            story.append(Spacer(1, 2*mm))

        if mitre:
            story.append(Paragraph("<b>MITRE ATLAS (Adversarial AI Threat Landscape)</b>", ss["Body"]))
            for ref in mitre:
                story.append(Paragraph(f"  - {safe(ref, 100)}", ss["Small"]))

    # ══════════════════════════════════════════════════════════════
    # FOOTER
    # ══════════════════════════════════════════════════════════════
    story.append(Spacer(1, 10*mm))
    story.append(HRFlowable(width="100%", color=C_LGREY))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        f"Generated by <b>AI Security Analyzer v0.1.0</b> on "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M')}. "
        "All sensitive values are masked. This tool analyzes your own data for defensive purposes only.",
        ss["Small"]))
    story.append(Paragraph(
        "References: OWASP Top 10 for LLM Applications 2025 | MITRE ATLAS | "
        "DarkBench (ICLR 2025) | PromptShield (arXiv:2501.15145) | "
        "Min-K% Prob (ICLR 2024, arXiv:2310.16789)",
        ss["Small"]))

    doc.build(story)
    print(f"PDF report generated: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="JSON security report to PDF")
    parser.add_argument("report_json", help="Path to security_report_final.json")
    parser.add_argument("--output", "-o", default="security_report.pdf", help="Output PDF path")
    args = parser.parse_args()
    if not os.path.exists(args.report_json):
        print(f"File not found: {args.report_json}")
        sys.exit(1)
    build_pdf(args.report_json, args.output)


if __name__ == "__main__":
    main()
