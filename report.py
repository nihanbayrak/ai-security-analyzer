"""
Report Generator — JSON + PDF

PDF structure:
  Page 1  — Cover  (risk score gauge, file info, scan date)
  Page 2  — How to Read This Report
  Pages 3+ — 14 security topic sections, each answering a plain-English question:
              1  Prompt Injection          OWASP LLM01:2025
              2  System Prompt Leakage     OWASP LLM07:2025
              3  Sensitive Info Disclosure OWASP LLM02:2025
              4  PII & Privacy             GDPR / CCPA
              5  Credentials & Secrets     OWASP LLM06:2025
              6  Excessive Agency          OWASP LLM06:2025 (Agentic)
              7  Harmful AI Output         OWASP LLM05:2025
              8  AI Hallucination          OWASP LLM09:2025
              9  Dark Patterns             DarkBench ICLR 2025
             10  Anomalous Behavior        MITRE ATLAS
             11  Training Data Leakage     OWASP LLM04:2025
             12  Multimodal / File Risks   OWASP LLM05:2025
             13  Agentic / Tool Risks      OWASP Agentic Top 10 2026
             14  Supply-Chain / Third-Party OWASP LLM03:2025
  Last Page — Action Plan
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any
from model import Finding, Severity


# ---------------------------------------------------------------------------
# Colour palette (R, G, B)
# ---------------------------------------------------------------------------
C_DARK_BLUE   = (0, 51, 102)
C_RED         = (180, 30, 30)
C_ORANGE      = (210, 95, 0)
C_AMBER       = (180, 130, 0)
C_BLUE        = (20, 80, 170)
C_GREEN       = (30, 120, 60)
C_LIGHT_GRAY  = (245, 245, 245)
C_MID_GRAY    = (130, 130, 130)
C_WHITE       = (255, 255, 255)
C_BLACK       = (0, 0, 0)
C_SECTION_BG  = (235, 242, 255)   # pale blue for section headers


def _severity_color(sev: Severity):
    return {
        Severity.CRITICAL: C_RED,
        Severity.HIGH:     C_ORANGE,
        Severity.MEDIUM:   C_AMBER,
        Severity.LOW:      C_BLUE,
        Severity.INFO:     C_MID_GRAY,
    }.get(sev, C_BLACK)


def _severity_label(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH:     "HIGH",
        Severity.MEDIUM:   "MEDIUM",
        Severity.LOW:      "LOW",
        Severity.INFO:     "INFO",
    }.get(sev, "UNKNOWN")


# ---------------------------------------------------------------------------
# 14 security topic definitions
# ---------------------------------------------------------------------------
SECTIONS = [
    {
        "num": 1,
        "question": "Did anyone try to hijack the AI? (Prompt Injection)",
        "what_is_it": (
            "Prompt injection is when someone sneaks hidden commands into a conversation "
            "to make the AI ignore its rules and do something it shouldn't — like revealing "
            "secrets, impersonating an admin, or bypassing safety filters. Think of it like "
            "someone slipping a fake note inside a letter to trick the recipient."
        ),
        "framework": "OWASP LLM01:2025 | MITRE ATLAS T0051/T0054",
        "match": lambda f: any(x in f.id for x in ["INJ_OVERRIDE", "INJ_JAILBREAK", "INJ_DELIM", "INJ_ENC", "INJ_ROLEPLAY"]) or "Prompt Injection" in f.category or "Jailbreak" in f.category or "Delimiter" in f.category or "Obfuscation" in f.category,
    },
    {
        "num": 2,
        "question": "Were the AI's secret instructions exposed? (System Prompt Leakage)",
        "what_is_it": (
            "AI chatbots are often given hidden instructions — called a system prompt — before "
            "your conversation starts. These might contain confidential business logic or data. "
            "Attackers try to trick the AI into repeating these instructions. We look for both "
            "attempts to extract them and signs they may have been revealed."
        ),
        "framework": "OWASP LLM07:2025",
        "match": lambda f: "INJ_LEAK" in f.id or "System Prompt Leak" in f.category or "LLM07" in f.framework_mapping,
    },
    {
        "num": 3,
        "question": "Did the AI accidentally reveal sensitive information? (Info Disclosure)",
        "what_is_it": (
            "AI models sometimes reveal information from their training data, internal "
            "configurations, or previous conversations. This includes business data, user "
            "information from other sessions, or internal system details that should never "
            "be visible to end users."
        ),
        "framework": "OWASP LLM02:2025",
        "match": lambda f: "LLM02" in f.framework_mapping or "Information Disclosure" in f.category,
    },
    {
        "num": 4,
        "question": "Is there any personal information in these conversations? (PII & Privacy)",
        "what_is_it": (
            "Personal Identifiable Information (PII) includes anything that can identify a "
            "specific person: emails, phone numbers, Social Security numbers, credit cards, "
            "passport numbers, dates of birth, and home addresses. Sharing these with an AI "
            "chatbot can create serious privacy risks — the data may be used for training or "
            "exposed in breaches. Under GDPR and CCPA, companies must protect this data."
        ),
        "framework": "OWASP LLM02:2025 | GDPR Article 4 | CCPA",
        "match": lambda f: "PII_" in f.id or "Personal Information" in f.category,
    },
    {
        "num": 5,
        "question": "Were any passwords or API keys leaked? (Credentials & Secrets)",
        "what_is_it": (
            "API keys, passwords, tokens, and private keys are the 'master keys' to your "
            "accounts and services. If these appear in your AI conversations, they could be "
            "exposed to anyone with access to the chat history. AWS keys, OpenAI keys, and "
            "GitHub tokens can give attackers full control of your cloud infrastructure."
        ),
        "framework": "OWASP LLM06:2025",
        "match": lambda f: "SEC_" in f.id or "Credentials" in f.category or "Secrets" in f.category,
    },
    {
        "num": 6,
        "question": "Did the AI act beyond its role? (Excessive Agency)",
        "what_is_it": (
            "AI systems connected to tools — like web browsers, code runners, or APIs — can "
            "take actions in the real world. 'Excessive Agency' means the AI took actions "
            "it wasn't clearly authorized to take, or gained more access than it needed. "
            "This is especially risky when AI agents can read files, send emails, or modify "
            "databases on your behalf."
        ),
        "framework": "OWASP LLM06:2025 (Agentic) | OWASP Agentic AI Top 10 2026",
        "match": lambda f: "ASI_" in f.id or "Agentic" in f.category or "Agency" in f.category,
    },
    {
        "num": 7,
        "question": "Did the AI generate dangerous content? (Harmful Output)",
        "what_is_it": (
            "AI chatbots can generate code, commands, and instructions that are dangerous if "
            "followed without review — like scripts that delete files, commands that download "
            "and execute unknown software, or web code containing cross-site scripting (XSS). "
            "The risk is highest when users run AI-generated code without understanding it."
        ),
        "framework": "OWASP LLM05:2025",
        "match": lambda f: "OUT_" in f.id or "Output Security" in f.category or "LLM05" in f.framework_mapping,
    },
    {
        "num": 8,
        "question": "Was the AI making things up? (Hallucination & Misinformation)",
        "what_is_it": (
            "AI models can generate confident-sounding but completely false information. "
            "This includes made-up citations, fake statistics, and claims about current events "
            "the model cannot know. Hallucinations are especially dangerous in medical, legal, "
            "and financial contexts. We flag patterns that suggest the AI may be fabricating facts."
        ),
        "framework": "OWASP LLM09:2025",
        "match": lambda f: "HAL_" in f.id or "Hallucination" in f.category or "LLM09" in f.framework_mapping,
    },
    {
        "num": 9,
        "question": "Was the AI trying to manipulate you? (Dark Patterns)",
        "what_is_it": (
            "AI chatbots can be designed — or influenced — to manipulate users through subtle "
            "psychological techniques. These include: sycophancy (always agreeing with you), "
            "artificial urgency ('act now!'), sneaking in unsolicited product recommendations, "
            "creating emotional dependency ('I care about you'), and inserting affiliate tracking "
            "links. These are called 'dark patterns' and were catalogued in DarkBench (ICLR 2025)."
        ),
        "framework": "DarkBench ICLR 2025 | OWASP LLM05:2025",
        "match": lambda f: "DARK_" in f.id or "Advertising" in f.category or "Manipulation" in f.category,
    },
    {
        "num": 10,
        "question": "Are there suspicious behavior patterns? (Anomalies)",
        "what_is_it": (
            "Statistical analysis of conversation patterns can reveal attacks or bot behavior "
            "that individual message checks miss. Red flags include: messages that are "
            "dramatically longer than normal (context stuffing), high-entropy strings that look "
            "like encoded payloads, and unusual message timing patterns. These are analyzed using "
            "MITRE ATLAS threat intelligence frameworks."
        ),
        "framework": "MITRE ATLAS AML.T0043 / AML.T0024",
        "match": lambda f: "ANOM_" in f.id or "Anomalous" in f.category,
    },
    {
        "num": 11,
        "question": "Is the AI repeating things it memorized from training? (Data Memorization)",
        "what_is_it": (
            "AI models trained on internet data can 'memorize' and then reproduce copyrighted "
            "text, personal information from public datasets, and proprietary content. This can "
            "create legal liability (copyright), privacy violations (GDPR), and trade secret "
            "risks. We look for verbatim repetition of long text blocks and regurgitation triggers."
        ),
        "framework": "OWASP LLM04:2025",
        "match": lambda f: "MEM_" in f.id or "Memorization" in f.category or "LLM04" in f.framework_mapping,
    },
    {
        "num": 12,
        "question": "Are the uploaded files safe? (File & Multimodal Risks)",
        "what_is_it": (
            "Files uploaded alongside AI conversations can carry hidden dangers: PDFs with "
            "embedded JavaScript, Office documents with macros (VBA), images with malicious "
            "metadata or hidden instructions (steganography), and CSV files with formula "
            "injection attacks. Even image EXIF metadata can contain hidden text."
        ),
        "framework": "OWASP LLM05:2025 | File Security",
        "match": lambda f: ("FILE_" in f.id and "SVG" not in f.id) or "File" in f.category or "CSV" in f.category or "PDF" in f.category or "Image" in f.category,
    },
    {
        "num": 13,
        "question": "Are there risks from AI agents and tools? (Agentic Risks)",
        "what_is_it": (
            "Modern AI assistants can use 'tools' — browsing the web, running code, calling "
            "APIs, reading/writing files. When AI acts as an agent, attackers can hijack its "
            "goals through malicious content it encounters online (indirect injection). We check "
            "for: goal hijacking via tool arguments, dangerous shell commands, credential "
            "forwarding to external services, and unauthorized privilege escalation."
        ),
        "framework": "OWASP Agentic AI Top 10 2026 (ASI01-ASI10)",
        "match": lambda f: "ASI_" in f.id or "Agentic" in f.category,
    },
    {
        "num": 14,
        "question": "Are there risks from plugins or third-party services? (Supply Chain)",
        "what_is_it": (
            "AI chatbots often rely on plugins, RAG knowledge bases, external APIs, and "
            "third-party tools. If any of these are compromised, the AI can be manipulated "
            "without the user or developer being aware. This includes poisoned RAG databases, "
            "malicious plugins, and indirect injection via external content the AI fetches."
        ),
        "framework": "OWASP LLM03:2025",
        "match": lambda f: "LLM03" in f.framework_mapping or "Supply Chain" in f.category or "Plugin" in f.category,
    },
]


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def generate_json_report(findings: List[Finding], summary: Dict[str, Any], out_path: str):
    """Generate machine-readable JSON report."""
    report_data = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            **summary,
            # convert Severity enum keys to strings
            "severity_counts": {k.value: v for k, v in summary["severity_counts"].items()},
        },
        "findings": [],
    }

    for f in findings:
        report_data["findings"].append({
            "id": f.id,
            "category": f.category,
            "framework": f.framework_mapping,
            "severity": f.severity.value,
            "score": f.score,
            "confidence": round(f.confidence, 2),
            "evidence": f.safe_redaction if f.safe_redaction else f.evidence,
            "location": {
                "conversation": f.provenance.conversation_id,
                "message_index": f.provenance.message_index,
                "role": f.provenance.role,
                "file": f.provenance.file_path,
                "locator": f.provenance.source_locator,
            },
            "recommendations": f.recommended_action,
        })

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report_data, fh, indent=2)


# ---------------------------------------------------------------------------
# PDF report — main entry point
# ---------------------------------------------------------------------------

def generate_pdf_report(
    findings: List[Finding],
    summary: Dict[str, Any],
    out_path: str,
    export_format: str = "unknown",
    conversation_count: int = 0,
    convs=None,
    msgs=None,
):
    """
    Generate a readable PDF security audit report.

    Each of the 14 sections answers a plain-English question about the user's
    conversation data, explains what the risk means, and shows findings with
    actionable recommendations.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        return  # fpdf2 not installed, skip silently

    overall_score = summary.get("overall_score", 0)
    risk_level = summary.get("risk_level", "Unknown")
    total_findings = summary.get("total_findings", 0)
    sev_counts = summary.get("severity_counts", {})

    # ---- Build PDF class --------------------------------------------------
    class SecPDF(FPDF):
        def header(self):
            # Thin top bar
            self.set_fill_color(*C_DARK_BLUE)
            self.rect(0, 0, 210, 6, "F")

        def footer(self):
            self.set_y(-14)
            self.set_font("Helvetica", "I", 7)
            self.set_text_color(*C_MID_GRAY)
            self.cell(0, 5, "AI Security Analyzer Report  |  Confidential  |  2026", align="C")
            self.ln(3)
            self.cell(0, 5, f"Page {self.page_no()}", align="C")

    pdf = SecPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(15, 15, 15)

    # ===================================================================
    # PAGE 1 — COVER
    # ===================================================================
    pdf.add_page()
    pdf.ln(10)

    # Title block
    pdf.set_fill_color(*C_DARK_BLUE)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 14, "AI Security Audit Report", ln=True, align="C", fill=True)
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 8, "Your Conversation Security Analysis", ln=True, align="C", fill=True)
    pdf.set_text_color(*C_BLACK)

    pdf.ln(8)

    # Meta info row
    scan_date = datetime.now().strftime("%B %d, %Y at %H:%M")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*C_MID_GRAY)
    fmt_label = export_format.upper() if export_format != "unknown" else "Unknown"
    pdf.cell(0, 6, f"Scan Date: {scan_date}   |   Format: {fmt_label} Export   |   Conversations: {conversation_count}", ln=True, align="C")
    pdf.set_text_color(*C_BLACK)
    pdf.ln(6)

    # Risk Score gauge (text-based)
    gauge_color = (
        C_RED if overall_score >= 80 else
        C_ORANGE if overall_score >= 60 else
        C_AMBER if overall_score >= 35 else
        C_BLUE if overall_score >= 10 else
        C_GREEN
    )
    pdf.set_fill_color(*gauge_color)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 48)
    pdf.cell(0, 24, str(overall_score), ln=True, align="C", fill=True)
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, f"RISK LEVEL: {risk_level.upper()}", ln=True, align="C", fill=True)
    pdf.set_text_color(*C_BLACK)
    pdf.ln(5)

    # Score explanation
    score_explanation = {
        "Critical": "Serious threats found. Immediate action is required.",
        "High":     "Significant risks detected. Review findings promptly.",
        "Medium":   "Some concerns found. Review at your earliest convenience.",
        "Low":      "Minor issues found. Consider the suggestions below.",
        "Info":     "No significant security issues detected in your conversations.",
    }.get(risk_level, "Risk level could not be determined.")
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(*C_MID_GRAY)
    pdf.multi_cell(0, 6, score_explanation, align="C")
    pdf.set_text_color(*C_BLACK)
    pdf.ln(8)

    # Severity breakdown table
    _section_header(pdf, "Findings at a Glance")
    pdf.ln(3)

    table_data = [
        ("CRITICAL", sev_counts.get(Severity.CRITICAL, 0), C_RED),
        ("HIGH",     sev_counts.get(Severity.HIGH, 0),     C_ORANGE),
        ("MEDIUM",   sev_counts.get(Severity.MEDIUM, 0),   C_AMBER),
        ("LOW",      sev_counts.get(Severity.LOW, 0),      C_BLUE),
        ("INFO",     sev_counts.get(Severity.INFO, 0),     C_MID_GRAY),
    ]

    col_w = 35
    for label, count, color in table_data:
        pdf.set_fill_color(*color)
        pdf.set_text_color(*C_WHITE)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(col_w, 8, label, fill=True, align="C")
    pdf.ln()
    for _, count, color in table_data:
        pdf.set_fill_color(*C_LIGHT_GRAY)
        pdf.set_text_color(*C_BLACK)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(col_w, 8, str(count), fill=True, align="C", border=1)
    pdf.ln(12)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*C_MID_GRAY)
    pdf.multi_cell(0, 5, f"Total findings: {total_findings} across 14 security topics. See the following pages for details.")
    pdf.set_text_color(*C_BLACK)

    # ===================================================================
    # PAGE 2 — WHAT TO DO RIGHT NOW (top 3 urgent actions, big font)
    # ===================================================================
    urgent_findings = sorted(
        [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)],
        key=lambda x: x.score, reverse=True
    )
    seen_urgent: set = set()
    urgent_actions: list = []
    for f in urgent_findings:
        for action in f.recommended_action:
            if action not in seen_urgent and len(urgent_actions) < 3:
                seen_urgent.add(action)
                urgent_actions.append((f.severity, f.category, action))

    pdf.add_page()
    pdf.ln(8)
    pdf.set_fill_color(*C_RED)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 14, "  What to Do RIGHT NOW", ln=True, fill=True, align="L")
    pdf.set_text_color(*C_BLACK)
    pdf.ln(6)

    if not urgent_actions:
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*C_GREEN)
        pdf.cell(0, 10, "Nothing urgent! No Critical or High severity findings.", ln=True, align="C")
        pdf.set_text_color(*C_BLACK)
        pdf.set_font("Helvetica", "", 11)
        pdf.multi_cell(0, 7,
            "Your scan found no Critical or High-severity issues. "
            "Review the Medium findings on the following pages when convenient.")
    else:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*C_MID_GRAY)
        pdf.multi_cell(0, 6,
            "Address Critical items immediately. High items within 24 hours.")
        pdf.set_text_color(*C_BLACK)
        pdf.ln(8)

        for i, (sev, cat, action) in enumerate(urgent_actions, 1):
            col = _severity_color(sev)
            sev_lbl = _severity_label(sev)
            pdf.set_fill_color(*col)
            pdf.set_text_color(*C_WHITE)
            pdf.set_font("Helvetica", "B", 22)
            pdf.cell(14, 14, str(i), fill=True, align="C")
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(28, 14, f" {sev_lbl}", fill=True, align="L")
            pdf.set_fill_color(*C_LIGHT_GRAY)
            pdf.set_text_color(*C_DARK_BLUE)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 14, f"  {_safe(cat)}", fill=True, ln=True, align="L")
            pdf.set_text_color(*C_BLACK)
            pdf.set_font("Helvetica", "", 12)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 8, _safe(f"   {action}"))
            pdf.ln(6)

    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*C_MID_GRAY)
    pdf.multi_cell(0, 5,
        "For full details, see the security sections on the following pages. "
        "The complete action plan is on the final page.")
    pdf.set_text_color(*C_BLACK)

    # ===================================================================
    # PAGE 3 — HOW TO READ THIS REPORT
    # ===================================================================
    pdf.add_page()
    pdf.ln(6)
    _page_title(pdf, "How to Read This Report")
    pdf.ln(4)

    intro_text = (
        "This report analyzed your AI chatbot conversation history and checked it against the "
        "latest 2026 cybersecurity standards for Large Language Models (LLMs).\n\n"
        "Each section below answers a simple question about your conversations. You do not need "
        "to be a cybersecurity expert to understand this report — it is written in plain language.\n\n"
        "HOW SEVERITY LEVELS WORK:\n"
        "  CRITICAL  ->  Immediate action required. Data may already be at risk.\n"
        "  HIGH      ->  Serious issue. Address within 24 hours.\n"
        "  MEDIUM    ->  Worth reviewing. Address within a week.\n"
        "  LOW       ->  Minor concern. Good to know about.\n"
        "  INFO      ->  For your awareness only. No action needed.\n\n"
        "HOW TO USE THE RECOMMENDATIONS:\n"
        "Each finding includes a 'What To Do' suggestion. Start with CRITICAL and HIGH findings. "
        "If you are unsure how to fix something, ask your IT or security team.\n\n"
        "PRIVACY NOTE:\n"
        "This report was generated entirely on your device. Your conversation data was never "
        "sent to any external server. The findings in this report are based only on pattern "
        "matching and statistical analysis of your local data."
    )
    _body_text(pdf, intro_text)

    pdf.ln(5)
    _section_header(pdf, "Security Frameworks Referenced in This Report")
    pdf.ln(3)

    frameworks = [
        ("OWASP Top 10 for LLMs 2025", "The industry-standard list of the 10 biggest security risks in AI chatbots, maintained by the Open Web Application Security Project."),
        ("OWASP Agentic AI Top 10 2026", "New 2026 standards covering risks specific to AI agents that can take real-world actions (browse web, run code, call APIs)."),
        ("MITRE ATLAS", "A knowledge base of adversarial tactics and techniques specifically targeting AI/ML systems, maintained by MITRE Corporation."),
        ("DarkBench (ICLR 2025)", "Research benchmark from the 2025 International Conference on Learning Representations cataloguing manipulation techniques used by AI systems."),
        ("GDPR / CCPA", "European and California privacy regulations that define how personal data must be protected in digital systems."),
    ]
    for name, desc in frameworks:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*C_DARK_BLUE)
        pdf.cell(0, 6, name, ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*C_BLACK)
        pdf.multi_cell(0, 5, desc)
        pdf.ln(2)

    # ===================================================================
    # PAGES 3+ — 14 SECURITY TOPIC SECTIONS
    # ===================================================================
    used_ids = set()

    for sec in SECTIONS:
        pdf.add_page()
        pdf.ln(4)

        # Section number badge + title
        _section_number_badge(pdf, sec["num"])
        pdf.ln(2)
        _page_title(pdf, sec["question"])

        # Framework tag
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*C_MID_GRAY)
        pdf.cell(0, 5, sec["framework"], ln=True)
        pdf.set_text_color(*C_BLACK)
        pdf.ln(3)

        # "What is this?" box
        _info_box(pdf, "What Is This Risk?", sec["what_is_it"])
        pdf.ln(4)

        # Filter matching findings
        matched = [
            f for f in findings
            if f.id not in used_ids and sec["match"](f)
        ]
        matched = sorted(matched, key=lambda x: x.score, reverse=True)[:20]

        if not matched:
            _status_badge(pdf, "CLEAR", C_GREEN)
            pdf.ln(3)
            pdf.set_font("Helvetica", "I", 10)
            pdf.set_text_color(*C_GREEN)
            pdf.multi_cell(0, 6, "Good news! We did not find any issues of this type in your conversations.")
            pdf.set_text_color(*C_BLACK)
        else:
            count_text = f"{len(matched)} finding{'s' if len(matched) != 1 else ''} detected"
            worst_sev = matched[0].severity
            _status_badge(pdf, f"ISSUES FOUND — {count_text.upper()}", _severity_color(worst_sev))
            pdf.ln(4)

            for f in matched:
                used_ids.add(f.id)
                _finding_card(pdf, f)
                pdf.ln(2)

        pdf.ln(3)

    # ===================================================================
    # TOP 5 RISKIEST CONVERSATIONS
    # ===================================================================
    if convs and findings:
        from collections import defaultdict

        # Score each conversation by summing finding severity weights
        _sev_w = {Severity.CRITICAL: 40, Severity.HIGH: 15,
                  Severity.MEDIUM: 5, Severity.LOW: 1, Severity.INFO: 0}
        conv_scores: dict = defaultdict(int)
        conv_finding_counts: dict = defaultdict(int)
        for f in findings:
            cid = f.provenance.conversation_id
            if cid and cid != "N/A":
                conv_scores[cid] += _sev_w.get(f.severity, 0)
                conv_finding_counts[cid] += 1

        # Build conv title lookup
        conv_titles = {c.id: c.title for c in convs}

        top5 = sorted(conv_scores.items(), key=lambda x: x[1], reverse=True)[:5]

        if top5:
            pdf.add_page()
            pdf.ln(6)
            _page_title(pdf, "Top 5 Highest-Risk Conversations")
            pdf.ln(3)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*C_MID_GRAY)
            pdf.multi_cell(0, 5,
                "These conversations had the most security findings. Review them first.")
            pdf.set_text_color(*C_BLACK)
            pdf.ln(5)

            for rank, (cid, raw_score) in enumerate(top5, 1):
                title = _safe(conv_titles.get(cid, f"Conversation {cid[:16]}"))
                n_findings = conv_finding_counts[cid]

                # Rank badge
                pdf.set_fill_color(*C_DARK_BLUE)
                pdf.set_text_color(*C_WHITE)
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(8, 9, str(rank), fill=True, align="C")

                # Title + stats
                pdf.set_fill_color(*C_SECTION_BG)
                pdf.set_text_color(*C_BLACK)
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 9, f"  {title[:70]}", fill=True, ln=True)

                # Findings breakdown for this conversation
                conv_findings = [f for f in findings
                                 if f.provenance.conversation_id == cid]
                sev_summary = {}
                for f in conv_findings:
                    lbl = f.severity.value
                    sev_summary[lbl] = sev_summary.get(lbl, 0) + 1

                breakdown = "  ".join(
                    f"{lbl}: {cnt}"
                    for lbl, cnt in sorted(sev_summary.items(),
                                           key=lambda x: _sev_w.get(
                                               Severity(x[0]), 0), reverse=True)
                )
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*C_MID_GRAY)
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 5, f"  {n_findings} findings  |  {breakdown}")
                pdf.set_text_color(*C_BLACK)
                pdf.ln(3)

    # ===================================================================
    # LAST PAGE — ACTION PLAN
    # ===================================================================
    pdf.add_page()
    pdf.ln(6)
    _page_title(pdf, "Your Action Plan")
    pdf.ln(3)

    all_actions = []
    priority_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

    for sev in priority_order:
        sev_findings = [f for f in findings if f.severity == sev]
        for f in sev_findings:
            for action in f.recommended_action:
                entry = (sev, f.category, action)
                if entry not in all_actions:
                    all_actions.append(entry)

    if not all_actions:
        pdf.set_font("Helvetica", "I", 11)
        pdf.set_text_color(*C_GREEN)
        pdf.multi_cell(0, 7, "No action items required. Your conversations appear clean.")
        pdf.set_text_color(*C_BLACK)
    else:
        # Deduplicate by action text, keep highest severity
        seen_actions = {}
        for sev, cat, action in all_actions:
            if action not in seen_actions:
                seen_actions[action] = (sev, cat)

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*C_MID_GRAY)
        pdf.cell(0, 5, "Items are ordered by priority. Start from the top.", ln=True)
        pdf.set_text_color(*C_BLACK)
        pdf.ln(3)

        count = 1
        for action, (sev, cat) in list(seen_actions.items())[:30]:
            col = _severity_color(sev)
            pdf.set_fill_color(*col)
            pdf.set_text_color(*C_WHITE)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(22, 7, _severity_label(sev), fill=True, align="C")
            pdf.set_fill_color(*C_LIGHT_GRAY)
            pdf.set_text_color(*C_BLACK)
            pdf.set_font("Helvetica", "", 8)
            safe_action = action.encode("latin-1", "replace").decode("latin-1")
            pdf.multi_cell(0, 7, f"  {count}. [{cat}]  {safe_action}", fill=True)
            pdf.ln(1)
            count += 1

    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*C_MID_GRAY)
    pdf.multi_cell(0, 5,
        "This report was generated by AI Security Analyzer. Findings are based on pattern "
        "matching and statistical analysis. Always verify critical findings with a qualified "
        "security professional before taking irreversible actions."
    )

    try:
        pdf.output(out_path)
    except Exception as e:
        print(f"[Report] PDF write error: {e}")


# ---------------------------------------------------------------------------
# PDF helper functions
# ---------------------------------------------------------------------------

def _safe(text: str) -> str:
    """Encode text for latin-1 PDF rendering, replacing unsupported chars."""
    if not text:
        return ""
    return str(text).encode("latin-1", "replace").decode("latin-1")


def _page_title(pdf, text: str):
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*C_DARK_BLUE)
    pdf.multi_cell(0, 8, _safe(text))
    pdf.set_text_color(*C_BLACK)


def _section_header(pdf, text: str):
    pdf.set_fill_color(*C_SECTION_BG)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*C_DARK_BLUE)
    pdf.cell(0, 8, _safe("  " + text), ln=True, fill=True)
    pdf.set_text_color(*C_BLACK)


def _section_number_badge(pdf, num: int):
    pdf.set_fill_color(*C_DARK_BLUE)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(24, 8, f"  TOPIC {num:02d}", fill=True)
    pdf.set_text_color(*C_BLACK)
    pdf.ln()


def _status_badge(pdf, label: str, color: tuple):
    pdf.set_fill_color(*color)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 8, _safe(f"  STATUS: {label}  "), fill=True, ln=True)
    pdf.set_text_color(*C_BLACK)


def _info_box(pdf, title: str, body: str):
    pdf.set_fill_color(*C_LIGHT_GRAY)
    pdf.set_draw_color(*C_DARK_BLUE)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*C_DARK_BLUE)
    pdf.cell(0, 7, _safe(f"  {title}"), ln=True, fill=True, border="B")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*C_BLACK)
    pdf.set_fill_color(*C_LIGHT_GRAY)
    pdf.multi_cell(0, 5, _safe("  " + body), fill=True)
    pdf.set_draw_color(0, 0, 0)


def _finding_card(pdf, f: Finding):
    """Render a single finding as a structured card."""
    sev_color = _severity_color(f.severity)
    sev_label = _severity_label(f.severity)

    # Severity + category header
    pdf.set_fill_color(*sev_color)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(22, 7, sev_label, fill=True, align="C")
    pdf.set_fill_color(250, 250, 250)
    pdf.set_text_color(*C_BLACK)
    pdf.set_font("Helvetica", "B", 9)
    category_text = _safe(f"  {f.category}")
    pdf.cell(0, 7, category_text, fill=True, ln=True, border="B")

    # Always reset to left margin before multi_cell calls
    pdf.set_x(pdf.l_margin)

    # Evidence
    evidence = _safe(f.safe_redaction or f.evidence)
    if evidence:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*C_BLACK)
        pdf.multi_cell(0, 5, _safe(f"  What was found:  {evidence[:250]}"), fill=True)

    # Location
    pdf.set_x(pdf.l_margin)
    loc = f.provenance
    loc_parts = []
    if loc.file_path:
        loc_parts.append(f"File: {os.path.basename(loc.file_path)}")
    if loc.conversation_id and loc.conversation_id != "N/A":
        loc_parts.append(f"Conversation: {str(loc.conversation_id)[:40]}")
    if loc.role:
        loc_parts.append(f"Sent by: {loc.role}")
    if loc.message_index is not None and loc.message_index >= 0:
        loc_parts.append(f"Message #{loc.message_index + 1}")
    if loc_parts:
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*C_MID_GRAY)
        pdf.multi_cell(0, 5, _safe("  Located in: " + "  |  ".join(loc_parts)), fill=True)
        pdf.set_text_color(*C_BLACK)

    # Recommendations
    pdf.set_x(pdf.l_margin)
    if f.recommended_action:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*C_GREEN)
        pdf.cell(0, 5, "  What to do:", ln=True)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "", 8)
        for action in f.recommended_action[:2]:
            pdf.multi_cell(0, 5, _safe(f"    -> {action}"))
            pdf.set_x(pdf.l_margin)
        pdf.set_text_color(*C_BLACK)

    # Framework reference
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(*C_MID_GRAY)
    pdf.cell(0, 5, _safe(f"  Framework: {f.framework_mapping}"), ln=True)
    pdf.set_text_color(*C_BLACK)

    # Bottom border line
    pdf.set_draw_color(*C_MID_GRAY)
    pdf.cell(0, 0, "", border="B", ln=True)
    pdf.set_draw_color(*C_BLACK)
    pdf.ln(1)


def _body_text(pdf, text: str):
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*C_BLACK)
    pdf.multi_cell(0, 5, _safe(text))
