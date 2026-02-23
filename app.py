#!/usr/bin/env python3
"""
AI Security Analyzer — Gradio Web App
Upload your ChatGPT conversations.json and get a full security analysis.
Designed for HuggingFace Spaces deployment.
"""

import json
import logging
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import gradio as gr
import pandas as pd
import plotly.graph_objects as go

logger = logging.getLogger(__name__)

from chatgpt_export import ChatGPTExportParser
from prompt_injection import PromptInjectionDetector
from pii_detector import PIIDetector
from anomaly_detector import ConversationAnomalyDetector
from advertising_detector import AdvertisingDetector
from membership_inference import MembershipInferenceAnalyzer
from security_report import ReportGenerator
from generate_custom_instructions import analyse as ci_analyse, build_custom_instruction, build_pdf as ci_build_pdf
from generate_pdf_report import build_pdf as security_build_pdf

# ── Constants ────────────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEV_ICON = {
    "CRITICAL": "🔴 Critical",
    "HIGH": "🟠 High",
    "MEDIUM": "🟡 Medium",
    "LOW": "🟢 Low",
}

MAX_PREVIEW = 80
MAX_DETAIL = 90
MAX_TABLE_ROWS = 200

def _sev(severity):
    return SEV_ICON.get(severity, severity)


def _title(title_map, conv_id):
    return title_map.get(conv_id, (conv_id or "?")[:20])


def _sort_findings(items):
    return sorted(items, key=lambda x: SEV_ORDER.get(x.get("severity", "LOW"), 3))


def _to_dataframe(rows, columns):
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=columns)


def _type_breakdown_table(by_type, explanations):
    if not by_type:
        return ""
    lines = ["\n| Type | Count | What It Means |", "|---|---|---|"]
    for ftype, cnt in by_type.most_common():
        label = ftype.replace("_", " ").title()
        lines.append(f"| {label} | {cnt} | {explanations.get(ftype, '')} |")
    return "\n".join(lines) + "\n"


# ── Conversations → DataFrame bridge for custom instructions ─────────────────

def conversations_to_dataframe(conversations):
    """Convert parsed Conversation objects to the DataFrame format
    expected by generate_custom_instructions.analyse()."""
    rows = []
    for conv in conversations:
        for msg in conv.messages:
            ts = None
            if msg.timestamp:
                ts = datetime.fromtimestamp(msg.timestamp, tz=timezone.utc).isoformat()
            rows.append({
                "conversation_id": conv.id,
                "conversation_title": conv.title,
                "role": msg.role,
                "text": msg.content or "",
                "timestamp_utc": ts,
            })
    return pd.DataFrame(rows)


def run_pipeline(file_path, progress=gr.Progress()):
    """Execute the full 6-module analysis pipeline.
    Returns (report_dict, title_map).
    """
    progress(0.05, desc="Parsing conversations.json ...")
    parser = ChatGPTExportParser(file_path)
    conversations = parser.parse()
    tmap = {
        c.id: (getattr(c, "title", None) or c.id[:16])
        for c in conversations
    }

    # 1 — Prompt injection
    progress(0.15, desc="Scanning for prompt injection ...")
    inj_det = PromptInjectionDetector(use_transformer=False, use_perplexity=False)
    all_inj = []
    for conv in conversations:
        for msg in conv.user_messages:
            all_inj.extend(inj_det.analyze_message(msg.content, msg.id, conv.id))
        esc = inj_det.detect_multi_turn_escalation(conv.messages)
        for f in esc:
            f.conversation_id = conv.id
        all_inj.extend(esc)
    seen = {}
    for f in all_inj:
        k = (f.message_id, f.injection_type, f.detection_layer)
        if k not in seen or f.confidence > seen[k].confidence:
            seen[k] = f
    all_inj = list(seen.values())

    # 2 — PII & credentials
    progress(0.30, desc="Scanning for PII & credentials ...")
    pii_det = PIIDetector(use_presidio=False)
    all_pii = []
    for conv in conversations:
        for msg in conv.messages:
            all_pii.extend(
                pii_det.analyze_message(msg.content, msg.id, conv.id, msg.role)
            )

    # 3 — Anomalies
    progress(0.50, desc="Detecting anomalies ...")
    anom_det = ConversationAnomalyDetector()
    all_anom = []
    for conv in conversations:
        all_anom.extend(anom_det.analyze_conversation(conv.messages, conv.id))

    # 4 — Advertising
    progress(0.65, desc="Checking for advertising & manipulation ...")
    adv_det = AdvertisingDetector()
    all_adv = []
    for conv in conversations:
        for msg in conv.assistant_messages:
            all_adv.extend(
                adv_det.analyze_message(msg.content, msg.id, conv.id, msg.role)
            )

    # 5 — Membership inference
    progress(0.80, desc="Membership inference analysis ...")
    mi_det = MembershipInferenceAnalyzer()
    all_mi = []
    for conv in conversations:
        all_mi.extend(mi_det.analyze_conversation(conv.messages, conv.id))
    all_mi.extend(mi_det.cross_conversation_verbatim(conversations))

    # 6 — Report
    progress(0.92, desc="Building report ...")
    rg = ReportGenerator()
    report = rg.generate(
        conversations=conversations,
        injection_findings=all_inj,
        pii_findings=all_pii,
        anomaly_findings=all_anom,
        advertising_findings=all_adv,
        image_findings=[],
        membership_findings=all_mi,
    )

    progress(0.96, desc="Serializing report ...")
    rpt_dict = report.to_dict()

    progress(1.0, desc="Done!")
    return rpt_dict, tmap, conversations


# ── Formatters — one per tab ─────────────────────────────────────────────────

def fmt_overview(rpt):
    risk = rpt["overall_risk_level"]
    score = rpt["risk_score"]
    n_conv = rpt["conversation_count"]
    n_msg = rpt["message_count"]
    ts = rpt["scan_timestamp"][:19].replace("T", " ")
    sev = rpt.get("severity_breakdown", {})
    summary = rpt.get("summary", {})
    findings = rpt.get("findings", {})

    md = f"""## Scan Complete

| | |
|---|---|
| **Conversations scanned** | {n_conv:,} |
| **Messages analyzed** | {n_msg:,} |
| **Scan time** | {ts} |
| **Overall risk** | **{risk}** ({score}/100) |
"""

    cats = [
        ("Prompt Injection", summary.get("prompt_injection", 0)),
        ("Passwords & Keys", len([f for f in findings.get("pii_leakage", [])
                                   if f.get("is_credential")])),
        ("Personal Info", summary.get("pii_leakage", 0)),
        ("Unusual Behavior", summary.get("anomalies", 0)),
        ("Ads & Manipulation", summary.get("advertising", 0)),
        ("Training Data Leaks", summary.get("membership_inference", 0)),
    ]
    means = [
        "Did anyone try to hijack the AI?",
        "Are passwords or API keys exposed?",
        "Is personal data visible in chats?",
        "Are there strange patterns?",
        "Is the AI pushing products?",
        "Is memorized text being repeated?",
    ]
    rows = []
    for (name, count), meaning in zip(cats, means):
        result = "✅ Clean" if count == 0 else f"⚠️ {count} found"
        rows.append({
            "Security Check": name,
            "Findings": count,
            "Result": result,
            "What It Means": meaning,
        })
    summary_df = pd.DataFrame(rows)

    labels = ["Critical", "High", "Medium", "Low"]
    values = [sev.get("critical", 0), sev.get("high", 0),
              sev.get("medium", 0), sev.get("low", 0)]
    bar_colors = ["#e74c3c", "#f39c12", "#f1c40f", "#27ae60"]

    fig = go.Figure(data=[go.Bar(
        x=labels, y=values,
        marker_color=bar_colors,
        text=values, textposition="auto",
    )])
    fig.update_layout(
        title="Findings by Severity",
        xaxis_title="Severity", yaxis_title="Count",
        height=320,
        margin=dict(l=40, r=20, t=50, b=40),
        plot_bgcolor="white",
    )

    recs = rpt.get("recommendations", [])
    if recs:
        md += "\n### What should I do now?\n"
        for i, r in enumerate(recs[:8], 1):
            md += f"{i}. {r}\n"

    return md, fig, summary_df


def fmt_injection(rpt, tmap):
    items = rpt.get("findings", {}).get("prompt_injection", [])
    total = rpt["message_count"]
    n = len(items)

    if n == 0:
        md = f"""### Did anyone try to hijack or trick the AI?

**Answer: No.** We scanned all {total:,} messages for prompt injection attacks — tricks that make the AI ignore its rules or reveal secrets. **Zero attacks found.**

**How we check:** Known attack patterns (like "ignore all previous instructions") verified by trained heuristics. Both must agree.

**Why it matters:** Prompt injection is the #1 AI security risk ([OWASP LLM01:2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)).

**Confidence: Very High (97-100%)**"""
    else:
        md = f"""### Did anyone try to hijack or trick the AI?

**Answer: Yes — {n} attack attempt(s) found.**

We scanned all {total:,} messages. The table below shows each attempt with the conversation it appeared in, what type of attack it was, and a preview of the suspicious message.

**How we check:** Pattern matching + heuristic verification. Both must agree.

**Confidence: Very High (97-100%)**"""

    rows = []
    for f in sorted(items, key=lambda x: SEV_ORDER.get(x.get("severity", "LOW"), 3)):
        rows.append({
            "Conversation": _title(tmap, f.get("conversation_id")),
            "Attack Type": f.get("injection_type", ""),
            "Confidence": f"{f.get('confidence', 0):.0%}",
            "Message Preview": (f.get("message_preview", "") or "")[:80],
            "Severity": _sev(f.get("severity", "LOW")),
        })
    df = pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["Conversation", "Attack Type", "Confidence", "Message Preview", "Severity"])
    return md, df


def fmt_credentials(rpt, tmap):
    pii = rpt.get("findings", {}).get("pii_leakage", [])
    creds = [f for f in pii if f.get("is_credential")]
    passwords = [f for f in pii if f["category"] == "password"]
    cc = [f for f in pii if f["category"] == "credit_card"]
    n = len(creds)

    if n == 0:
        md = """### Are any passwords, API keys, or credit cards exposed?

**Answer: No.** No passwords, API keys, tokens, or credit card numbers were found.

**How we check:** Pattern matching for credential formats (`sk-...`, `ghp_...`, `AKIA...`), password keywords, credit cards verified with Luhn checksum.

**Confidence: Very High (97-100%)**"""
    else:
        parts = []
        if passwords:
            parts.append(f"**{len(passwords)} password(s)** in plain text — change them immediately")
        if cc:
            parts.append(f"**{len(cc)} credit card number(s)** (Luhn-validated) — monitor for charges")
        detail = ". ".join(parts) + "." if parts else ""

        md = f"""### Are any passwords, API keys, or credit cards exposed?

**Answer: Yes — {n} credential(s) found!**

{detail}

Anyone with access to your export file can see these. The table below shows each one, which conversation it appeared in, and what to do.

**Confidence: Very High (97-100%)**"""

    rows = []
    for f in sorted(creds, key=lambda x: SEV_ORDER.get(x.get("severity", "LOW"), 3)):
        rows.append({
            "Conversation": _title(tmap, f.get("conversation_id")),
            "Type": f.get("category", "").replace("_", " ").title(),
            "Masked Value": (f.get("matched_value", "") or "")[:40],
            "Severity": _sev(f.get("severity", "LOW")),
            "What To Do": (f.get("recommendation", "") or "")[:60],
        })
    df = pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["Conversation", "Type", "Masked Value", "Severity", "What To Do"])
    return md, df


def fmt_pii(rpt, tmap):
    pii = rpt.get("findings", {}).get("pii_leakage", [])
    non_cred = [f for f in pii if not f.get("is_credential")]
    by_cat = Counter(f["category"] for f in non_cred)
    n = len(non_cred)

    breakdown = ""
    if by_cat:
        breakdown = "\n| Type | Count |\n|---|---|\n"
        nice = {"email": "Email addresses", "phone": "Phone numbers",
                "ip_address": "IP addresses", "ssn": "SSN-like numbers",
                "internal_url": "Internal URLs", "iban": "IBAN numbers"}
        for cat, cnt in by_cat.most_common():
            breakdown += f"| {nice.get(cat, cat)} | {cnt} |\n"

    md = f"""### Is any personal information visible in your chats?

**Answer: {"Yes — " + str(n) + " item(s) found." if n else "No personal data detected."}**
{breakdown}
**How we check:** Regex patterns with context validation. Phones require nearby keywords ("call", "phone"). IPs exclude DNS servers & version numbers. Credit cards are Luhn-verified. IBANs use MOD-97. Passwords in code snippets are skipped.

**Note:** Emails are very accurate (99%+). Phone and IP findings are high-confidence after filtering (>90%).

**Confidence: High (95-99% after filtering)**"""

    rows = []
    for f in sorted(non_cred,
                    key=lambda x: SEV_ORDER.get(x.get("severity", "LOW"), 3))[:200]:
        rows.append({
            "Conversation": _title(tmap, f.get("conversation_id")),
            "Type": f.get("category", "").replace("_", " ").title(),
            "Value (masked)": (f.get("matched_value", "") or "")[:40],
            "Severity": _sev(f.get("severity", "LOW")),
            "Why Flagged": (f.get("recommendation", "") or "")[:70],
        })
    df = pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["Conversation", "Type", "Value (masked)", "Severity", "Why Flagged"])
    return md, df


def fmt_anomalies(rpt, tmap):
    items = rpt.get("findings", {}).get("anomalies", [])
    n = len(items)
    high = [f for f in items if f.get("severity") in ("CRITICAL", "HIGH")]
    by_type = Counter(f["anomaly_type"] for f in items)

    explanations = {
        "repeated_message": "Same message sent multiple times (retries or bots)",
        "response_ratio": "AI response far longer than the question asked",
        "message_length": "Unusually long or short message compared to average",
        "high_entropy": "Random-looking text (could be code or attack strings)",
        "language_switch": "Unexpected language change mid-conversation",
        "burst_messages": "Many messages sent in rapid succession",
        "adversarial_suffix": "Possible automated attack pattern (GCG/AutoDAN)",
    }

    table = ""
    if by_type:
        table = "\n| Pattern | Count | What It Means |\n|---|---|---|\n"
        for atype, cnt in by_type.most_common():
            table += f"| {atype.replace('_', ' ').title()} | {cnt} | {explanations.get(atype, '')} |\n"

    md = f"""### Is there any unusual or suspicious behavior?

**Answer:** We detected **{n}** unusual pattern(s). **{len(high)}** are high-priority.
{table}
**How we check:** Statistical analysis of message lengths, response ratios, character entropy (after stripping code/URLs/base64), language scripts, and word-bigram patterns for adversarial suffixes.

**Note:** High-priority items (adversarial suffixes, extreme ratios) are reliable. Low-priority items (repeated messages, minor length outliers) are informational only.

**Confidence: Medium** (high-priority reliable, low-priority informational)"""

    rows = []
    for f in sorted(items,
                    key=lambda x: SEV_ORDER.get(x.get("severity", "LOW"), 3))[:200]:
        rows.append({
            "Conversation": _title(tmap, f.get("conversation_id")),
            "Type": f.get("anomaly_type", "").replace("_", " ").title(),
            "Details": (f.get("details", "") or "")[:90],
            "Severity": _sev(f.get("severity", "LOW")),
        })
    df = pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["Conversation", "Type", "Details", "Severity"])
    return md, df


def fmt_advertising(rpt, tmap):
    items = rpt.get("findings", {}).get("advertising", [])
    n = len(items)
    by_type = Counter(f["finding_type"] for f in items)

    explanations = {
        "brand_bias": "AI repeatedly mentions one brand much more than alternatives",
        "promotional": "AI uses sales-like language (urgency, superlatives, calls-to-action)",
        "affiliate": "URLs with tracking / affiliate parameters found",
        "anthropomorphism": "AI implies it has human feelings (builds emotional attachment)",
        "sycophancy": "AI agrees with everything instead of being honest",
        "sneaking": "AI subtly alters your intent",
        "user_retention": "AI tries to keep you engaged longer than needed",
    }

    table = ""
    if by_type:
        table = "\n| Type | Count | What It Means |\n|---|---|---|\n"
        for ftype, cnt in by_type.most_common():
            table += (f"| {ftype.replace('_', ' ').title()} | {cnt} "
                      f"| {explanations.get(ftype, '')} |\n")

    md = f"""### Is the AI trying to sell you things or manipulate your behavior?

**Answer:** We found **{n}** instance(s) of potential advertising or manipulation.
{table}
Below is every finding ranked by severity. Each row shows the **conversation** where it happened, the **evidence from your data**, and **why** it was flagged.

**How we check:** Promotional language scoring, brand mention density (8+ mentions at 5%+ density), tracking URL detection (whitelisting ChatGPT browsing & academic sites), and DarkBench dark pattern categories (3+ signals for sycophancy, 2+ for sneaking/retention).

**Reference:** DarkBench (ICLR 2025), OWASP LLM09:2025

**Confidence: Medium** (multi-signal thresholds reduce false positives)"""

    rows = []
    for f in sorted(items,
                    key=lambda x: SEV_ORDER.get(x.get("severity", "LOW"), 3)):
        indicators = f.get("indicators", [])
        evidence = "; ".join(str(i)[:60] for i in indicators[:3]) if indicators else ""
        rows.append({
            "Conversation": _title(tmap, f.get("conversation_id")),
            "Type": f.get("finding_type", "").replace("_", " ").title(),
            "Evidence from Data": evidence[:140],
            "Severity": _sev(f.get("severity", "LOW")),
            "Why Flagged": (f.get("details", "") or "")[:80],
        })
    df = pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["Conversation", "Type", "Evidence from Data",
                 "Severity", "Why Flagged"])
    return md, df


def fmt_membership(rpt, tmap):
    items = rpt.get("findings", {}).get("membership_inference", [])
    n = len(items)
    by_type = Counter(f["finding_type"] for f in items)

    explanations = {
        "min_k_prob_suspect": "Unusual character-frequency pattern suggesting memorization",
        "verbatim_block": "Same 60+ character block repeated within a conversation",
        "verbatim_cross_conversation": "Same phrase appears across many conversations",
    }

    table = ""
    if by_type:
        table = "\n| Signal | Count | What It Means |\n|---|---|---|\n"
        for ftype, cnt in by_type.most_common():
            table += (f"| {ftype.replace('_', ' ').title()} | {cnt} "
                      f"| {explanations.get(ftype, '')} |\n")

    md = f"""### Could the AI be leaking memorized training data?

**Answer:** We found **{n}** signal(s) suggesting the AI may be repeating memorized text.
{table}
**Why it matters:** If the AI memorized data from its training set, it could leak information to other users.

**Important:** This uses a simplified proxy method (character statistics), not direct model access. Results are **weak signals, not proof**.

**Reference:** Min-K% Prob (ICLR 2024), OWASP LLM06:2025

**Confidence: Low** (proxy method only, not conclusive)"""

    rows = []
    for f in sorted(items,
                    key=lambda x: SEV_ORDER.get(x.get("severity", "LOW"), 3))[:200]:
        rows.append({
            "Conversation": _title(tmap, f.get("conversation_id")),
            "Type": f.get("finding_type", "").replace("_", " ").title(),
            "Details": (f.get("details", "") or "")[:90],
            "Severity": _sev(f.get("severity", "LOW")),
        })
    df = pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["Conversation", "Type", "Details", "Severity"])
    return md, df


def fmt_conversations(rpt):
    per_conv = rpt.get("per_conversation_risk", [])
    flagged = [c for c in per_conv if c.get("risk") != "CLEAN"]
    total = rpt["conversation_count"]

    md = f"""### Which conversations should I review first?

**Answer:** Out of **{total:,}** conversations, **{len(flagged)}** have at least one security finding.

The table below shows the riskiest conversations sorted by total findings. Start your review from the top."""

    rows = []
    for c in sorted(flagged,
                    key=lambda x: x.get("total_findings", 0),
                    reverse=True)[:100]:
        rows.append({
            "Conversation": (c.get("title") or c["id"][:20])[:55],
            "Risk Level": _sev(c.get("risk", "LOW")),
            "Critical": c.get("critical", 0),
            "High": c.get("high", 0),
            "Medium": c.get("medium", 0),
            "Low": c.get("low", 0),
            "Total": c.get("total_findings", 0),
        })
    df = pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["Conversation", "Risk Level", "Critical", "High",
                 "Medium", "Low", "Total"])
    return md, df


def fmt_custom_instructions(ci_stats):
    """Format custom-instruction analysis results for the Gradio tab."""
    dc = ci_stats["domain_counts"]
    total = ci_stats["total_user_msgs"] or 1
    tone = ci_stats["tone"]
    ai_pct = round(100 * dc.get("ai_ml_llm", 0) / total)
    sub = ci_stats["ai_sub_counts"]
    sub_total = sum(sub.values()) or 1
    img = ci_stats["image_stats"]
    inj = ci_stats["injection_stats"]

    md = f"""## Your Conversation Profile

| Metric | Value |
|--------|-------|
| Total user messages | {total:,} |
| AI / ML / LLM share | {ai_pct}% |
| Avg message length (all topics) | {ci_stats['avg_len_all']} chars |
| Avg message length (AI topics) | {ci_stats['avg_len_ai']} chars |
"""
    if ci_stats["peak_hour"] >= 0:
        md += f"| Peak usage hour (UTC) | {ci_stats['peak_hour']}:00 |\n"

    md += "\n### Domain Breakdown\n\n"
    for domain, cnt in sorted(dc.items(), key=lambda x: x[1], reverse=True):
        pct = round(100 * cnt / total)
        md += f"- **{domain.replace('_', ' ').title()}** — {cnt:,} messages ({pct}%)\n"

    if sub:
        md += "\n### AI/ML Sub-Categories\n\n"
        for sub_cat, cnt in sorted(sub.items(), key=lambda x: x[1], reverse=True):
            pct = round(100 * cnt / sub_total)
            md += f"- **{sub_cat.replace('_', ' ').title()}** — {cnt:,} messages ({pct}%)\n"

    md += f"""\n### Tone Preferences

Based on your conversation style, here's how you prefer AI responses:

- **Concise / direct:** {tone['concise']}%
- **Detailed explanations:** {tone['detailed']}%
- **Examples / snippets:** {tone['examples']}%
"""

    if img["confirmed_dalle_count"] > 0:
        md += f"""\n### Image Generation
- **DALL-E generations confirmed:** {img['confirmed_dalle_count']}
- **User prompts recovered:** {img['prompt_count']}
"""
        if img["style_counts"]:
            md += "- **Styles:** " + ", ".join(
                f"{s} ({c})" for s, c in sorted(
                    img["style_counts"].items(), key=lambda x: x[1], reverse=True)
            ) + "\n"
        if img["subject_counts"]:
            md += "- **Subjects:** " + ", ".join(
                f"{s} ({c})" for s, c in sorted(
                    img["subject_counts"].items(), key=lambda x: x[1], reverse=True)
            ) + "\n"

    md += f"""\n### Prompt Injection Scan (regex-based)

Scanned **{inj['total_msgs']:,}** messages with **{inj['total_patterns']}** patterns across **{inj['total_categories']}** attack categories.

- **Flagged:** {inj['total_flagged']}
- **Risk level:** {inj['risk_level']}
"""

    sample_qa = ci_stats.get("sample_qa", [])
    if sample_qa:
        md += "\n### Sample Q&A from Your Conversations\n\n"
        for i, pa in enumerate(sample_qa[:5], 1):
            md += f"**{i}. _{pa.get('title', '')}_**\n\n"
            md += f"- **Q:** {pa['question']}\n"
            md += f"- **A:** {pa['answer']}\n\n"

    # Domain breakdown chart
    domains = list(dc.keys())
    counts = [dc[d] for d in domains]
    nice_names = [d.replace("_", " ").title() for d in domains]
    colors = ["#3498db", "#2ecc71", "#e67e22", "#9b59b6", "#95a5a6",
              "#1abc9c", "#e74c3c", "#f39c12"]
    fig = go.Figure(data=[go.Bar(
        x=nice_names, y=counts,
        marker_color=colors[:len(domains)],
        text=counts, textposition="auto",
    )])
    fig.update_layout(
        title="Message Distribution by Domain",
        xaxis_title="Domain", yaxis_title="Messages",
        height=340,
        margin=dict(l=40, r=20, t=50, b=40),
        plot_bgcolor="white",
    )

    # Top phrases table
    top = ci_stats.get("top_phrases_ai", [])
    topic_rows = [{"Phrase": p, "Occurrences": c} for p, c in top[:20]]
    topics_df = pd.DataFrame(topic_rows) if topic_rows else pd.DataFrame(
        columns=["Phrase", "Occurrences"])

    instruction = build_custom_instruction(ci_stats)

    return md, fig, topics_df, instruction


# ── Main orchestrator ────────────────────────────────────────────────────────

def _empty():
    """Return blank outputs for all tabs."""
    edf = pd.DataFrame()
    efig = go.Figure()
    prompt = ("⬆️ **Upload your `conversations.json` file above** "
              "and click **Analyze My Data** to begin.")
    return ("", efig, edf, "",
            prompt,
            efig, edf,
            "", edf, "", edf, "", edf,
            "", edf, "", edf, "", edf,
            "", edf,
            None, None)


def analyze(file, progress=gr.Progress()):
    if file is None:
        return _empty()

    try:
        rpt, tmap, conversations = run_pipeline(file, progress)
    except Exception as e:
        edf = pd.DataFrame()
        efig = go.Figure()
        err = (f"### ❌ Analysis Failed\n\n**Error:** `{e}`\n\n"
               "**How to fix:** Make sure you uploaded a valid "
               "`conversations.json` from ChatGPT's data export.\n\n"
               "Go to **ChatGPT → Settings → Data Controls → Export Data** "
               "→ download the ZIP → extract `conversations.json`.")
        return (err, efig, edf, "",
                err, efig, edf,
                err, edf, err, edf, err, edf,
                err, edf, err, edf, err, edf,
                err, edf,
                None, None)

    ov_md, ov_fig, ov_df = fmt_overview(rpt)
    q1_md, q1_df = fmt_injection(rpt, tmap)
    q2_md, q2_df = fmt_credentials(rpt, tmap)
    q3_md, q3_df = fmt_pii(rpt, tmap)
    q4_md, q4_df = fmt_anomalies(rpt, tmap)
    q5_md, q5_df = fmt_advertising(rpt, tmap)
    q6_md, q6_df = fmt_membership(rpt, tmap)
    q7_md, q7_df = fmt_conversations(rpt)

    # Custom Instructions analysis
    df_msg = conversations_to_dataframe(conversations)
    ci_stats = ci_analyse(df_msg, df_ses=None)
    ci_md, ci_fig, ci_topics_df, ci_instruction = fmt_custom_instructions(ci_stats)

    # Generate Custom Instructions PDF
    ci_pdf_path = None
    try:
        ci_pdf_tmp = tempfile.NamedTemporaryFile(
            suffix="_custom_instructions.pdf", delete=False)
        ci_pdf_tmp.close()
        ci_build_pdf(ci_stats, Path(ci_pdf_tmp.name))
        ci_pdf_path = ci_pdf_tmp.name
    except Exception:
        logger.exception("Custom Instructions PDF generation failed")
        ci_pdf_path = None

    sec_pdf_path = None
    try:
        sec_json_tmp = tempfile.NamedTemporaryFile(
            suffix="_report.json", delete=False, mode="w", encoding="utf-8")
        json.dump(rpt, sec_json_tmp, indent=2, default=str, ensure_ascii=False)
        sec_json_tmp.close()

        sec_pdf_tmp = tempfile.NamedTemporaryFile(
            suffix="_security_report.pdf", delete=False)
        sec_pdf_tmp.close()
        security_build_pdf(sec_json_tmp.name, sec_pdf_tmp.name)
        sec_pdf_path = sec_pdf_tmp.name
    except Exception:
        logger.exception("Security Report PDF generation failed")
        sec_pdf_path = None

    return (ci_md, ci_fig, ci_topics_df, ci_instruction,
            ov_md, ov_fig, ov_df,
            q1_md, q1_df,
            q2_md, q2_df,
            q3_md, q3_df,
            q4_md, q4_df,
            q5_md, q5_df,
            q6_md, q6_df,
            q7_md, q7_df,
            ci_pdf_path, sec_pdf_path)


# ── Custom CSS ────────────────────────────────────────────────────────────────

CUSTOM_CSS = """
.main-header {
    text-align: center;
    padding: 1.5rem 1rem 0.5rem;
}
.main-header h1 {
    font-size: 2.4rem;
    margin-bottom: 0.3rem;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}
.main-header p {
    font-size: 1.1rem;
    color: #6b7280;
    max-width: 700px;
    margin: 0 auto;
}
.privacy-banner {
    background: linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 100%);
    border: 1px solid #bbf7d0;
    border-radius: 12px;
    padding: 0.8rem 1.2rem;
    margin: 0.5rem auto 1rem;
    max-width: 720px;
    text-align: center;
    font-size: 0.92rem;
}
.privacy-banner strong { color: #15803d; }
.upload-area {
    border: 2px dashed #c7d2fe !important;
    border-radius: 16px !important;
    background: #fafafe !important;
    transition: border-color 0.2s;
}
.upload-area:hover {
    border-color: #818cf8 !important;
}
.analyze-btn {
    min-height: 52px !important;
    font-size: 1.1rem !important;
    font-weight: 600 !important;
    border-radius: 12px !important;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
    border: none !important;
    box-shadow: 0 4px 14px rgba(102, 126, 234, 0.4) !important;
    transition: transform 0.15s, box-shadow 0.15s !important;
}
.analyze-btn:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5) !important;
}
.how-to-box {
    background: linear-gradient(135deg, #eff6ff 0%, #f5f3ff 100%);
    border: 1px solid #c7d2fe;
    border-radius: 14px;
    padding: 1.5rem 2rem;
    margin-top: 0.5rem;
}
.how-to-box h3 { color: #4338ca; margin-top: 0; }
.how-to-box ol { padding-left: 1.4rem; }
.how-to-box li { margin-bottom: 0.5rem; line-height: 1.6; }
.how-to-box code {
    background: #e0e7ff;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.9em;
}
.badge-row {
    display: flex;
    justify-content: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-top: 0.5rem;
}
footer { display: none !important; }
"""

EMPTY_STATE_MD = """
<div class="how-to-box">
<h3>How to get your ChatGPT data</h3>
<ol>
<li>Open <a href="https://chatgpt.com" target="_blank">chatgpt.com</a> → <strong>Settings</strong> → <strong>Data Controls</strong></li>
<li>Click <strong>Export Data</strong> → confirm via email</li>
<li>Download the ZIP → extract <code>conversations.json</code></li>
<li>Upload it above and click <strong>Analyze My Data</strong></li>
</ol>
<p style="margin-top:0.8rem;color:#4338ca;font-size:0.95rem;">
<strong>Want to try it first?</strong> Download the <code>example_conversations.json</code> from the Files tab to see a demo with planted security issues.
</p>
<p style="margin-top:0.5rem;color:#6b7280;font-size:0.9rem;">
🔒 Your file is processed entirely in memory and <strong>never stored or sent anywhere</strong>. Deleted when your session ends.
</p>
</div>
"""

# ── Gradio UI ────────────────────────────────────────────────────────────────

theme = gr.themes.Soft(
    primary_hue="indigo",
    secondary_hue="purple",
    neutral_hue="slate",
    font=[gr.themes.GoogleFont("Inter"), "ui-sans-serif", "system-ui", "sans-serif"],
).set(
    body_background_fill="linear-gradient(135deg, #f8faff 0%, #f5f3ff 100%)",
    block_background_fill="white",
    block_border_width="1px",
    block_border_color="#e5e7eb",
    block_radius="12px",
    block_shadow="0 1px 3px rgba(0,0,0,0.06)",
    button_primary_background_fill="linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
    button_primary_text_color="white",
)

with gr.Blocks(theme=theme, css=CUSTOM_CSS, title="AI Security Analyzer") as demo:
    gr.HTML(
        '<div class="main-header">'
        "<h1>🛡️ AI Security Analyzer</h1>"
        "<p>Upload your ChatGPT export and discover what's hiding in your conversations — "
        "prompt injections, exposed passwords, PII leaks, manipulation patterns, and more.</p>"
        '<div class="badge-row">'
        '<img src="https://img.shields.io/badge/OWASP-Top_10_LLM_2025-4338ca" alt="OWASP">'
        '<img src="https://img.shields.io/badge/MITRE-ATLAS-e67e22" alt="MITRE ATLAS">'
        '<img src="https://img.shields.io/badge/DarkBench-ICLR_2025-16a34a" alt="DarkBench">'
        '<img src="https://img.shields.io/badge/Privacy-100%25_Local-15803d" alt="Privacy">'
        "</div>"
        "</div>"
    )
    gr.HTML(
        '<div class="privacy-banner">'
        "🔒 <strong>100% Private</strong> — your file is processed in memory and "
        "<strong>never stored, logged, or sent to third parties</strong>. "
        "Deleted when your session ends."
        "</div>"
    )

    with gr.Row():
        file_input = gr.File(
            label="📄 Upload conversations.json",
            file_types=[".json"],
            type="filepath",
            elem_classes=["upload-area"],
        )
        analyze_btn = gr.Button(
            "🔍 Analyze My Data",
            variant="primary",
            scale=0,
            elem_classes=["analyze-btn"],
        )

    with gr.Tabs():
        with gr.Tab("🏠 Overview"):
            ov_md = gr.Markdown(EMPTY_STATE_MD)
            with gr.Row():
                ov_fig = gr.Plot(label="Severity Distribution")
            ov_df = gr.Dataframe(label="Security Summary", interactive=False)

        with gr.Tab("🎯 Custom Instructions"):
            gr.Markdown(
                "**Generate a personalized Custom Instruction** based on your "
                "conversation history. Copy the generated text directly into "
                "ChatGPT → Settings → Custom Instructions."
            )
            ci_md = gr.Markdown()
            with gr.Row():
                ci_fig = gr.Plot(label="Domain Breakdown")
            ci_topics_df = gr.Dataframe(
                label="Top Recurring Topics",
                interactive=False)
            gr.Markdown("### Your Generated Custom Instruction")
            ci_instruction = gr.Textbox(
                label="Copy this into ChatGPT → Settings → Custom Instructions",
                lines=20,
                interactive=False,
                show_copy_button=True,
            )

        with gr.Tab("🔓 Prompt Injection"):
            q1_md = gr.Markdown()
            q1_df = gr.Dataframe(label="Detected Attacks", interactive=False)

        with gr.Tab("🔑 Passwords & Keys"):
            q2_md = gr.Markdown()
            q2_df = gr.Dataframe(label="Exposed Credentials", interactive=False)

        with gr.Tab("👤 Personal Info"):
            q3_md = gr.Markdown()
            q3_df = gr.Dataframe(label="PII Findings", interactive=False)

        with gr.Tab("📊 Anomalies"):
            q4_md = gr.Markdown()
            q4_df = gr.Dataframe(label="Unusual Patterns", interactive=False)

        with gr.Tab("📢 Manipulation"):
            q5_md = gr.Markdown()
            q5_df = gr.Dataframe(
                label="Advertising & Dark Patterns",
                interactive=False)

        with gr.Tab("🧠 Memorization"):
            q6_md = gr.Markdown()
            q6_df = gr.Dataframe(label="Training Data Signals", interactive=False)

        with gr.Tab("⚠️ Riskiest Chats"):
            q7_md = gr.Markdown()
            q7_df = gr.Dataframe(
                label="Conversations ranked by risk",
                interactive=False)

        with gr.Tab("📥 Download"):
            gr.Markdown(
                "### Download Your Reports\n\n"
                "Run the analysis first, then download your reports as PDF."
            )
            with gr.Row():
                dl_ci_pdf = gr.File(
                    label="Custom Instructions Report (PDF)",
                    interactive=False)
                dl_sec_pdf = gr.File(
                    label="Security Analysis Report (PDF)",
                    interactive=False)

    analyze_btn.click(
        fn=analyze,
        inputs=[file_input],
        outputs=[
            ci_md, ci_fig, ci_topics_df, ci_instruction,
            ov_md, ov_fig, ov_df,
            q1_md, q1_df,
            q2_md, q2_df,
            q3_md, q3_df,
            q4_md, q4_df,
            q5_md, q5_df,
            q6_md, q6_df,
            q7_md, q7_df,
            dl_ci_pdf, dl_sec_pdf,
        ],
    )

if __name__ == "__main__":
    demo.launch(
        server_name="0.0.0.0",
        server_port=7865,
        ssr_mode=False,
    )
