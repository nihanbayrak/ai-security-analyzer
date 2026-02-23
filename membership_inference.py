"""
Membership Inference Analyzer
Estimates whether conversation content may have been used in LLM training data.

Methods implemented:
  1. Min-K% Prob proxy -- measures "rarity" of tokens via character n-gram frequency.
     Full reference implementation requires a HuggingFace LM (GPT-2, Llama, etc.),
     but this standalone version approximates the signal using vocabulary richness
     and term-frequency statistics (no ML required).
     Paper: "Detecting Pretraining Data from Large Language Models" (Shi et al.,
     ICLR 2024, arXiv:2310.16789).

  2. Canary token detection -- flags conversations that contain known synthetic
     "canary" identifiers that researchers embed in training corpora to detect
     memorisation. Reference: CanaryBench (arXiv:2601.18834).

  3. Verbatim block detection -- long character n-gram matches between consecutive
     messages or across conversations can indicate memorised training data.
     Excludes structured data (CSV/tables) and common boilerplate to avoid FP.

Maps to OWASP LLM06:2025 -- Sensitive Information Disclosure
Maps to MITRE ATLAS -- AML.T0024 Exfiltration via Cyber Means
"""

import re
import math
import hashlib
from typing import List, Dict, Tuple
from dataclasses import dataclass
from collections import Counter


@dataclass
class MembershipFinding:
    """A finding from membership inference analysis."""
    message_id: str
    conversation_id: str
    finding_type: str
    severity: str
    confidence: float
    details: str
    metric_value: float
    message_preview: str
    owasp_ref: str = "LLM06:2025"
    mitre_ref: str = "AML.T0024"


class MembershipInferenceAnalyzer:
    """
    Standalone membership inference analyzer.

    Without a local LM it cannot compute true token log-probabilities, so it
    uses character-level and word-level statistics as proxy signals. Results
    are weak signals only -- not definitive proof of memorization.
    """

    MIN_TEXT_LENGTH = 200
    MIN_K_PERCENT = 0.2
    MI_SCORE_THRESHOLD = 0.85
    VERBATIM_NGRAM_SIZE = 80
    VERBATIM_MIN_MATCHES = 8

    CANARY_PATTERNS: List[Tuple[str, str]] = [
        (r'\bcanary[_-]?\d{4,}\b', "Numeric canary token"),
        (r'\bTESTCANARY[A-Z0-9]{6,}\b', "Alpha-numeric canary token"),
        (r'The quick brown fox jumps over the lazy dog \d{4}', "Classic canary sentence with year"),
        (r'cf8b0a7b-5f3c-4d9a', "CanaryBench UUID fragment"),
        (r'SUPERSECRETCANARY', "Explicit canary label"),
    ]

    # Patterns that indicate structured/tabular data (not memorization)
    _STRUCTURED_DATA_RE = re.compile(
        r'(?:'
        r'[\t,|]{2,}'               # tab/comma/pipe delimiters (CSV, TSV)
        r'|^\s*\|.*\|.*\|\s*$'      # markdown table rows
        r'|(?:\w+\s*[=:]\s*\S+\s*[,;\n]){3,}'  # key=value pairs
        r'|(?:^\s*\d+[\.\)]\s+){3,}'  # numbered lists
        r')',
        re.MULTILINE
    )

    # Common ChatGPT boilerplate starts (not memorized training data)
    _BOILERPLATE_STARTS = [
        "sure, here", "of course!", "here's", "here is", "certainly!",
        "great question", "i'd be happy to", "let me", "absolutely!",
        "you're right", "that's a great", "good question", "i understand",
        "based on", "according to", "in summary", "to summarize",
    ]

    def __init__(self):
        self._phrase_index: Dict[str, List[Tuple[str, str]]] = {}

    def analyze_conversation(self, messages: list, conv_id: str) -> List[MembershipFinding]:
        findings: List[MembershipFinding] = []
        for msg in messages:
            if len(msg.content) < self.MIN_TEXT_LENGTH:
                continue
            if self._is_structured_data(msg.content):
                continue
            findings.extend(self._check_canary(msg, conv_id))
            findings.extend(self._min_k_proxy(msg, conv_id))

        findings.extend(self._verbatim_block_detection(messages, conv_id))
        self._index_phrases(messages, conv_id)
        return findings

    def cross_conversation_verbatim(self, conversations: list) -> List[MembershipFinding]:
        """
        Detect verbatim phrase repetitions spanning multiple conversations.
        Filters out boilerplate (phrases appearing in too many conversations
        are common templates, not memorized training data).
        """
        findings: List[MembershipFinding] = []

        for fp, locations in self._phrase_index.items():
            conv_ids = list({c for c, _ in locations})
            n_convs = len(conv_ids)
            n_msgs = len(locations)

            # Too few: not a signal
            if n_msgs < 5 or n_convs < 3:
                continue

            # Too many: this is boilerplate, not memorization
            # If a phrase appears in >5% of all conversations, it's common template text
            total_convs = len({c.id for c in conversations}) if conversations else 1
            if n_convs > max(10, total_convs * 0.05):
                continue

            msg_id = locations[0][1]
            findings.append(MembershipFinding(
                message_id=msg_id,
                conversation_id=locations[0][0],
                finding_type="verbatim_cross_conversation",
                severity="LOW",
                confidence=min(0.3 + n_convs * 0.05, 0.65),
                details=(
                    f"Verbatim phrase appears in {n_msgs} messages across "
                    f"{n_convs} conversations -- possible memorised text"
                ),
                metric_value=float(n_msgs),
                message_preview=f"Fingerprint: {fp[:40]}..."
            ))

        return findings

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def _is_structured_data(self, text: str) -> bool:
        """Detect CSV, tables, product catalogs, and other structured data."""
        lines = text.strip().split("\n")
        if len(lines) < 3:
            return False

        # Check for consistent delimiter patterns (CSV/TSV)
        delim_counts = []
        for line in lines[:10]:
            delim_counts.append(line.count(",") + line.count("\t") + line.count("|"))
        if delim_counts and min(delim_counts) >= 2:
            variance = max(delim_counts) - min(delim_counts)
            if variance <= 2:
                return True

        # Check for repetitive structure (same words appearing in >50% of lines)
        if len(lines) >= 5:
            word_sets = [set(l.lower().split()) for l in lines[:20]]
            common = word_sets[0]
            for ws in word_sets[1:]:
                common = common & ws
            if len(common) >= 2:
                return True

        if self._STRUCTURED_DATA_RE.search(text[:500]):
            return True

        return False

    def _is_boilerplate(self, text: str) -> bool:
        """Check if text starts with common ChatGPT boilerplate."""
        lower = text.lower().strip()[:60]
        return any(lower.startswith(bp) for bp in self._BOILERPLATE_STARTS)

    def _check_canary(self, msg, conv_id: str) -> List[MembershipFinding]:
        findings = []
        for pattern, description in self.CANARY_PATTERNS:
            match = re.search(pattern, msg.content, re.IGNORECASE)
            if match:
                findings.append(MembershipFinding(
                    message_id=msg.id,
                    conversation_id=conv_id,
                    finding_type="canary_detected",
                    severity="HIGH",
                    confidence=0.90,
                    details=(
                        f"Canary token detected: '{description}'. "
                        "This is a synthetic identifier used in membership inference research."
                    ),
                    metric_value=1.0,
                    message_preview=msg.content[:100]
                ))
        return findings

    def _min_k_proxy(self, msg, conv_id: str) -> List[MembershipFinding]:
        """
        Proxy for Min-K% Prob (Shi et al., ICLR 2024).
        Uses character 4-gram frequency as a proxy for token log-prob.
        """
        findings = []
        text = msg.content.lower()

        if self._is_boilerplate(text):
            return findings

        n = 4
        ngrams = [text[i:i+n] for i in range(len(text) - n + 1)]
        if len(ngrams) < 20:
            return findings

        freq = Counter(ngrams)
        total = sum(freq.values())
        probs = sorted([c / total for c in freq.values()])

        k_count = max(1, int(len(probs) * self.MIN_K_PERCENT))
        min_k_probs = probs[:k_count]
        avg_min_k = sum(min_k_probs) / len(min_k_probs)

        vocab_size = len(freq)
        baseline = 1.0 / max(vocab_size, 1)
        ratio = avg_min_k / max(baseline, 1e-9)
        score = max(0.0, min(1.0, 1.0 - ratio / 5.0))

        words = text.split()
        ttr = len(set(words)) / max(len(words), 1)

        combined_score = score * 0.7 + (1.0 - ttr) * 0.3

        if combined_score > self.MI_SCORE_THRESHOLD:
            findings.append(MembershipFinding(
                message_id=msg.id,
                conversation_id=conv_id,
                finding_type="min_k_prob_suspect",
                severity="LOW",
                confidence=round(combined_score, 3),
                details=(
                    f"Min-K% proxy score {combined_score:.3f} > threshold {self.MI_SCORE_THRESHOLD} "
                    f"(rarity={score:.3f}, TTR={ttr:.3f}). "
                    "Content may contain verbatim text from training data (weak signal)."
                ),
                metric_value=combined_score,
                message_preview=msg.content[:100]
            ))

        return findings

    def _verbatim_block_detection(self, messages: list, conv_id: str) -> List[MembershipFinding]:
        """
        Detect repeated long character blocks within the same conversation.
        Skips structured data and boilerplate.
        """
        findings = []
        n = self.VERBATIM_NGRAM_SIZE
        seen_blocks: Dict[str, str] = {}

        for msg in messages:
            if len(msg.content) < n * 2:
                continue
            if self._is_structured_data(msg.content):
                continue
            if self._is_boilerplate(msg.content):
                continue

            text = msg.content.lower()
            blocks = {text[i:i+n] for i in range(0, len(text) - n, n)}
            match_count = sum(1 for b in blocks if b in seen_blocks)

            if match_count >= self.VERBATIM_MIN_MATCHES:
                findings.append(MembershipFinding(
                    message_id=msg.id,
                    conversation_id=conv_id,
                    finding_type="verbatim_block",
                    severity="LOW",
                    confidence=min(0.3 + match_count * 0.03, 0.6),
                    details=(
                        f"{match_count} verbatim {n}-char blocks repeated within conversation "
                        "-- possible memorised or templated text"
                    ),
                    metric_value=float(match_count),
                    message_preview=msg.content[:100]
                ))

            for b in blocks:
                if b not in seen_blocks:
                    seen_blocks[b] = msg.id

        return findings

    def _index_phrases(self, messages: list, conv_id: str) -> None:
        """Build cross-conversation phrase fingerprint index, skipping boilerplate."""
        n = self.VERBATIM_NGRAM_SIZE
        for msg in messages:
            if len(msg.content) < n * 3:
                continue
            if self._is_structured_data(msg.content):
                continue

            text = msg.content.lower()

            # Skip the first 100 chars (usually boilerplate greeting)
            start = min(100, len(text) // 4)
            for offset in range(start, min(len(text) - n, 300), 60):
                block = text[offset:offset + n]
                # Skip blocks that are mostly whitespace or punctuation
                alpha_ratio = sum(1 for c in block if c.isalpha()) / len(block)
                if alpha_ratio < 0.5:
                    continue
                fp = hashlib.md5(block.encode()).hexdigest()[:12]
                if fp not in self._phrase_index:
                    self._phrase_index[fp] = []
                self._phrase_index[fp].append((conv_id, msg.id))
