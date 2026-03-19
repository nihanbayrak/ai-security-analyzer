"""
Chief Supervisor — reviews all confirmed findings and generates
a plain-language executive summary + top 3 urgent actions.
Uses Qwen3-8B via HF Inference API with offline fallback.
"""

import json
from typing import List
from .base import llm_call, parse_verdict, is_llm_online
from .prompts import CHIEF_PROMPT


def _detect_language(findings: list) -> str:
    """Simple heuristic: if evidence contains Turkish chars → tr, German → de."""
    all_evidence = " ".join(f.get("evidence", "") for f in findings)
    tr_chars = set("çğıöşüÇĞİÖŞÜ")
    de_chars = set("äöüßÄÖÜ")
    if any(c in tr_chars for c in all_evidence):
        return "tr"
    if any(c in de_chars for c in all_evidence):
        return "de"
    return "en"


def _heuristic_summary(confirmed: list, score: int, risk_level: str) -> dict:
    """Offline fallback: rule-based summary without LLM."""
    from collections import Counter
    ids = [f.get("id", "") for f in confirmed]
    id_counts = Counter(ids)

    top_actions = []
    patterns = []

    # Check for credentials
    cred_ids = [i for i in ids if i.startswith("SEC_")]
    if cred_ids:
        top_actions.append("Rotate any exposed API keys or passwords immediately — treat them as compromised.")
        patterns.append("Credential exposure detected")

    # Check for PII
    pii_ids = [i for i in ids if i.startswith("PII_")]
    if pii_ids:
        top_actions.append("Review shared personal data and consider deleting those conversation(s) from your AI history.")

    # Check for injection
    inj_ids = [i for i in ids if i.startswith("INJ_")]
    if inj_ids:
        top_actions.append("Review injection-flagged conversations — someone may have attempted to manipulate your AI assistant.")
        patterns.append("Prompt injection attempts found")

    if not top_actions:
        top_actions = [
            "Review the flagged conversations and delete any you don't recognize.",
            "Enable 2FA on your AI service account.",
            "Avoid sharing sensitive personal information in AI conversations.",
        ]

    n = len(confirmed)
    summary = (
        f"Your AI conversation history received a risk score of {score}/100 ({risk_level}). "
        f"The scan confirmed {n} security finding{'s' if n != 1 else ''}. "
    )
    if cred_ids:
        summary += "Exposed credentials were detected — this is the most urgent issue. "
    if pii_ids:
        summary += "Personal information was found in conversations. "
    if inj_ids:
        summary += "Prompt injection attempts suggest someone tried to manipulate your AI assistant. "
    summary += "See the action plan below for next steps."

    return {
        "summary": summary,
        "top_actions": top_actions[:3],
        "patterns_found": patterns,
        "improvements": ["Enable LLM supervisor (set HF_TOKEN) for higher accuracy validation."],
        "overall_confidence": 60,
        "llm_validated": False,
    }


def generate_chief_summary(confirmed_findings: list, score: int, risk_level: str) -> dict:
    """
    Run Chief Supervisor over all confirmed findings.
    Returns plain-language summary + top 3 actions.
    """
    if not confirmed_findings:
        return {
            "summary": f"No security concerns were confirmed. Risk score: {score}/100 ({risk_level}).",
            "top_actions": ["Continue using AI services normally.", "Re-scan periodically as your history grows."],
            "patterns_found": [],
            "improvements": [],
            "overall_confidence": 90,
            "llm_validated": False,
        }

    lang = _detect_language(confirmed_findings)

    if not is_llm_online():
        return _heuristic_summary(confirmed_findings, score, risk_level)

    # Build compact finding summary for LLM (stay within token budget)
    finding_lines = []
    for f in confirmed_findings[:50]:  # cap at 50 to stay within context
        fid = f.get("id", "?")
        sev = f.get("severity", "?")
        ev = f.get("evidence", "")[:80]
        finding_lines.append(f"  [{sev}] {fid}: {ev}")
    findings_text = "\n".join(finding_lines)

    lang_note = {"tr": "Respond in Turkish.", "de": "Respond in German."}.get(lang, "")

    messages = [
        {"role": "system", "content": CHIEF_PROMPT},
        {"role": "user", "content": (
            f"Risk score: {score}/100 ({risk_level})\n"
            f"Total confirmed findings: {len(confirmed_findings)}\n"
            f"Language: {lang}. {lang_note}\n\n"
            f"Confirmed findings:\n{findings_text}\n\n"
            "Generate the executive summary and top 3 actions.\n"
            'Respond as JSON: {"summary":"...","top_actions":["...","...","..."],'
            '"patterns_found":["..."],"improvements":["..."],"overall_confidence":0-100}'
        )},
    ]

    raw = llm_call(messages, max_tokens=500)
    if not raw:
        return _heuristic_summary(confirmed_findings, score, risk_level)

    try:
        import re
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            data = json.loads(m.group(0))
            return {
                "summary": data.get("summary", ""),
                "top_actions": data.get("top_actions", [])[:3],
                "patterns_found": data.get("patterns_found", []),
                "improvements": data.get("improvements", []),
                "overall_confidence": int(data.get("overall_confidence", 70)),
                "llm_validated": True,
            }
    except Exception:
        pass

    return _heuristic_summary(confirmed_findings, score, risk_level)
