"""
Training Data Memorization Detector — OWASP LLM04:2025

Detects potential training data memorization via two signals:

1. Verbatim repetition across conversations
   - Finds long assistant phrases (≥60 chars) that appear verbatim in 3+ different
     conversations. A phrase that appears identically across many conversations was
     likely memorized from training data rather than generated fresh each time.

2. Cross-conversation phrase fingerprinting
   - Extracts distinctive n-gram fingerprints from assistant messages and flags
     phrases that appear suspiciously often across different conversation threads.

Skill spec reference:
  - Min-K% Prob proxy via character n-gram rarity scoring
  - Verbatim block detection (exact string matching across conversations)
  - Cross-conversation fingerprinting (repeated unusual phrases)
"""

import re
from collections import defaultdict
from typing import List, Dict, Tuple
from model import Finding, Severity, ProvenanceLocator, Message

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Minimum phrase length — short phrases are almost never real memorization
MIN_PHRASE_LEN = 80

# A phrase repeated across this many *distinct* conversations triggers a finding
# Fix 1D: Raise from 3 to 5 — reduces template phrase false positives
VERBATIM_CONV_THRESHOLD = 5

# Phrase n-gram window for fingerprinting (characters)
NGRAM_SIZE = 80
NGRAM_STRIDE = 40
# Fix 1D: Raise from 4 to 7 — n-grams must be very widespread to flag
NGRAM_CONV_THRESHOLD = 7

# Ignore very common phrases — ALL standard LLM boilerplate that always repeats
# Fix 1D: Extended to cover the most common template phrases
_COMMON_PHRASES_RE = re.compile(
    r"(?i)^("
    # Standard AI openers
    r"i('m| am) (here|happy|glad|ready|an ai|not able|unable|sorry)|"
    r"(as an ai|as a language model|i (cannot|can't|don't have|apologize))|"
    r"(how can i (help|assist))|"
    r"(feel free to|please (let me know|note|be aware|feel free))|"
    r"(i (hope|trust) this (helps?|is helpful|clarifies|answers))|"
    r"(let me know if (you|there is|you have)|is there anything else)|"
    r"(i'd be (happy|glad|delighted) to (help|assist|answer|explain))|"
    r"(certainly|of course|absolutely|sure|great question|that's a great)|"
    r"(here('s| is) (what|how|a|an|the|some)|based on (my|the|your|this))|"
    r"(in (summary|conclusion|short)|to summarize|first,? let me)|"
    r"(i (understand|see|notice|observe|appreciate) (that|your|this|the))|"
    r"(this is (a|an|the|just|simply|quite|very|really)|it('s| is) (important|worth|helpful))|"
    r"(you (can|may|might|should|could)|there are (several|many|a few|multiple))|"
    r"(to (answer|address|help with) your (question|request|inquiry))|"
    r"(i'll (help|start|begin|explain|show|walk you))|"
    r"(here are (some|the|a few|several|key))|"
    r"(note (that|:)|please (note|keep in mind))|"
    r"(the (following|above|below|key|main|most important))"
    r")",
    re.IGNORECASE,
)

# Strip punctuation for comparison
_NORMALIZE_RE = re.compile(r"\s+")


def _normalize(text: str) -> str:
    return _NORMALIZE_RE.sub(" ", text.lower().strip())


def _extract_phrases(text: str) -> List[str]:
    """Split assistant text into candidate phrases for verbatim comparison."""
    # Split on sentence boundaries and newlines
    candidates = re.split(r"[.!?\n]+", text)
    return [
        c.strip()
        for c in candidates
        if len(c.strip()) >= MIN_PHRASE_LEN and not _COMMON_PHRASES_RE.match(c.strip())
    ]


def _build_phrase_map(msgs: List[Message]) -> Dict[str, List[Tuple[str, int]]]:
    """
    Map normalized phrase → [(conversation_id, message_index), ...]
    Only considers assistant messages.
    """
    phrase_map: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
    for msg in msgs:
        if msg.role != "assistant":
            continue
        for phrase in _extract_phrases(msg.content):
            key = _normalize(phrase)
            phrase_map[key].append((msg.conversation_id, msg.index))
    return phrase_map


def _build_ngram_map(msgs: List[Message]) -> Dict[str, List[Tuple[str, int]]]:
    """
    Map character n-gram → [(conversation_id, message_index), ...]
    """
    ngram_map: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
    for msg in msgs:
        if msg.role != "assistant":
            continue
        text = _normalize(msg.content)
        for i in range(0, max(0, len(text) - NGRAM_SIZE), NGRAM_STRIDE):
            gram = text[i : i + NGRAM_SIZE]
            if len(gram) == NGRAM_SIZE and not _COMMON_PHRASES_RE.match(gram):
                ngram_map[gram].append((msg.conversation_id, msg.index))
    return ngram_map


def _locator(conv_id: str, msg_idx: int) -> ProvenanceLocator:
    return ProvenanceLocator(
        conversation_id=conv_id,
        message_index=msg_idx,
        role="assistant",
    )


def detect_memorization(msgs: List[Message]) -> List[Finding]:
    """
    Scan assistant messages for signs of training data memorization.

    Returns a list of Finding objects.
    """
    findings: List[Finding] = []
    seen_phrases: set = set()  # avoid duplicate findings for same phrase

    # --- Signal 1: Verbatim phrase repetition across conversations ---
    phrase_map = _build_phrase_map(msgs)
    for phrase_key, occurrences in phrase_map.items():
        distinct_convs = {conv_id for conv_id, _ in occurrences}
        if len(distinct_convs) < VERBATIM_CONV_THRESHOLD:
            continue
        if phrase_key in seen_phrases:
            continue
        seen_phrases.add(phrase_key)

        # Report on the first occurrence
        first_conv, first_idx = occurrences[0]
        severity = (
            Severity.HIGH if len(distinct_convs) >= 8
            else Severity.MEDIUM if len(distinct_convs) >= 5
            else Severity.LOW
        )
        findings.append(Finding(
            id="MEM_VERBATIM",
            category="Training Data Memorization",
            framework_mapping="OWASP LLM04:2025",
            severity=severity,
            score=60 if severity == Severity.HIGH else 40 if severity == Severity.MEDIUM else 20,
            confidence=min(0.95, 0.5 + len(distinct_convs) * 0.05),
            evidence=(
                f"Phrase repeated verbatim in {len(distinct_convs)} conversations: "
                f"\"{phrase_key[:120]}…\""
            ),
            provenance=_locator(first_conv, first_idx),
            recommended_action=[
                "Verify this phrase isn't boilerplate by checking the conversations.",
                "If it represents sensitive or copyrighted training data, "
                "consider reporting to the AI provider.",
                "High repetition may indicate memorized PII or proprietary text.",
            ],
        ))

    # --- Signal 2: High-frequency n-gram fingerprinting ---
    ngram_map = _build_ngram_map(msgs)
    seen_ngrams: set = set()
    for gram, occurrences in ngram_map.items():
        distinct_convs = {conv_id for conv_id, _ in occurrences}
        if len(distinct_convs) < NGRAM_CONV_THRESHOLD:
            continue
        if gram in seen_ngrams:
            continue
        seen_ngrams.add(gram)

        first_conv, first_idx = occurrences[0]
        findings.append(Finding(
            id="MEM_FINGERPRINT",
            category="Training Data Memorization",
            framework_mapping="OWASP LLM04:2025",
            severity=Severity.LOW,
            score=15,
            confidence=0.4,
            evidence=(
                f"N-gram pattern appears in {len(distinct_convs)} conversations "
                f"(possible memorized fragment): \"{gram[:100]}…\""
            ),
            provenance=_locator(first_conv, first_idx),
            recommended_action=[
                "Low-confidence signal — review manually.",
                "High-frequency n-grams across many conversations may suggest "
                "the model was trained on similar data to your conversations.",
            ],
        ))

    return findings
