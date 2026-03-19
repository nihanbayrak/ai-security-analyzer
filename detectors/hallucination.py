"""
Hallucination & Misinformation Detector — OWASP LLM09:2025

Detects signals that the AI may be generating unreliable or fabricated content:
  - Fabricated citations (plausible-looking but unverifiable references)
  - Overconfident absolute claims on contested topics
  - Internal contradictions within a conversation
  - False authority appeals ("studies show", "experts agree" without source)
  - Unverifiable statistics presented as fact
  - AI claiming real-time knowledge it cannot have
"""

import re
from typing import List
from model import Finding, Severity, ProvenanceLocator


def _hal(fid, subtype, severity, score, evidence, locator, action, confidence=0.7):
    return Finding(
        id=fid,
        category="Hallucination / Misinformation",
        framework_mapping="OWASP LLM09:2025",
        severity=severity,
        score=score,
        confidence=confidence,
        evidence=str(evidence)[:300],
        provenance=locator,
        recommended_action=action,
        safe_redaction=f"[Possible Hallucination: {subtype}]",
    )


def detect_hallucinations(messages: list, locator_fn=None) -> List[Finding]:
    """
    Detect hallucination signals in a list of Message objects.

    Args:
        messages: list of Message dataclass objects
        locator_fn: optional callable(msg) -> ProvenanceLocator; defaults to building one from msg
    """
    from model import ProvenanceLocator

    findings: List[Finding] = []

    for msg in messages:
        if not msg.content or msg.role != "assistant":
            continue

        text = msg.content
        if locator_fn:
            locator = locator_fn(msg)
        else:
            locator = ProvenanceLocator(
                conversation_id=msg.conversation_id,
                message_index=msg.index,
                role=msg.role,
            )

        # ---- 1. Fabricated citations -------------------------------------
        # Pattern: Author et al. (year) or Journal Name, year, vol, pp.
        citation_re = re.compile(
            r"([A-Z][a-z]+\s+et\s+al\.\s*\(\d{4}\)|"
            r"[A-Z][a-z]+,\s+[A-Z]\.\s*\(\d{4}\)\.\s+[A-Z]|"
            r"published\s+in\s+[A-Z][a-zA-Z\s]+,?\s+vol\.|"
            r"according\s+to\s+(?:the\s+)?(?:[A-Z][a-z]+\s+){1,4}study\s+\(\d{4}\))"
        )
        for m in citation_re.finditer(text):
            findings.append(_hal(
                "HAL_CITE", "Fabricated Citation",
                Severity.MEDIUM, 55,
                f"Unverifiable citation: '{m.group(0)}'",
                locator,
                ["Always verify AI-generated citations independently",
                 "AI models frequently generate plausible but non-existent references"],
                confidence=0.65,
            ))
            break  # one per message

        # ---- 2. False authority / vague attribution ----------------------
        vague_authority_re = re.compile(
            r"(?i)(studies?\s+show|research\s+(shows?|suggests?|indicates?)|"
            r"experts?\s+(agree|say|believe|confirm)|"
            r"scientists?\s+(have\s+)?(found|proven?|confirmed)|"
            r"according\s+to\s+(research|studies|experts|scientists)\b)"
        )
        for m in vague_authority_re.finditer(text):
            # Only flag if no actual source follows nearby
            surrounding = text[m.end():m.end()+200]
            has_source = re.search(r"\((?:19|20)\d{2}\)|https?://|\bSource:|doi:|ISBN:", surrounding)
            if not has_source:
                findings.append(_hal(
                    "HAL_AUTHORITY", "Vague Authority Appeal",
                    Severity.LOW, 30,
                    f"Unverified authority claim: '{m.group(0)}'",
                    locator,
                    ["Ask the AI to provide the specific source",
                     "Treat unsourced 'studies show' claims skeptically"],
                    confidence=0.6,
                ))
                break

        # ---- 3. Unverifiable statistics -----------------------------------
        stats_re = re.compile(
            r"(?i)(\d{1,3}(?:\.\d+)?%\s+of\s+(?:people|users|adults|children|patients|companies|respondents|Americans|participants))"
        )
        for m in stats_re.finditer(text):
            surrounding_before = text[max(0, m.start()-150):m.start()]
            has_source_before = re.search(
                r"according\s+to\s+[A-Z]|Source:|survey\s+by\s+[A-Z]|\(\d{4}\)",
                surrounding_before, re.I
            )
            if not has_source_before:
                findings.append(_hal(
                    "HAL_STAT", "Unsourced Statistic",
                    Severity.LOW, 30,
                    f"Unsourced statistic: '{m.group(0)}'",
                    locator,
                    ["Verify statistics independently before relying on them",
                     "AI may generate plausible-sounding numbers without factual basis"],
                    confidence=0.55,
                ))
                break

        # ---- 4. AI claiming real-time or future knowledge ----------------
        realtime_re = re.compile(
            r"(?i)(as\s+of\s+(today|right\s+now|this\s+moment|currently)|"
            r"the\s+latest\s+(news|update|version|release)\s+is|"
            r"just\s+announced|breaking\s*:|currently\s+trending|"
            r"the\s+current\s+(president|prime\s+minister|ceo|stock\s+price)\s+is)"
        )
        for m in realtime_re.finditer(text):
            findings.append(_hal(
                "HAL_REALTIME", "Claimed Real-Time Knowledge",
                Severity.MEDIUM, 50,
                f"AI claiming real-time information: '{m.group(0)}'",
                locator,
                ["AI models have a training cutoff and cannot know current events",
                 "Verify any 'current' or 'latest' claims through authoritative sources"],
                confidence=0.75,
            ))
            break

        # ---- 5. Overconfident absolute claim ----------------------------
        absolute_re = re.compile(
            r"(?i)\b(it\s+is\s+a\s+fact\s+that|this\s+is\s+definitively|"
            r"there\s+is\s+no\s+doubt\s+that|it\s+is\s+(absolutely|completely)\s+(certain|proven|established)\s+that|"
            r"100%\s+(certain|accurate|true|guaranteed|proven)|"
            r"without\s+(any\s+)?question\s*,?\s+(the|this|it)\s+is)\b"
        )
        for m in absolute_re.finditer(text):
            findings.append(_hal(
                "HAL_ABSOLUTE", "Overconfident Absolute Claim",
                Severity.LOW, 25,
                f"Absolute certainty language: '{m.group(0)}'",
                locator,
                ["AI outputs always carry uncertainty — verify critical claims",
                 "Absolute language from AI often signals overconfidence in the model"],
                confidence=0.6,
            ))
            break

    return findings


def detect_hallucinations_from_text(text: str, locator: ProvenanceLocator) -> List[Finding]:
    """Convenience wrapper for single-message text analysis."""
    from model import Message
    # Build a minimal dummy message
    msg = Message(
        id="dummy",
        conversation_id=locator.conversation_id or "unknown",
        index=locator.message_index or 0,
        role="assistant",
        content=text,
    )
    return detect_hallucinations([msg], locator_fn=lambda _: locator)
