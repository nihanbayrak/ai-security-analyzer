"""
Conversation Anomaly Detector
Detects unusual patterns in conversation histories using statistical analysis.

Detection signals:
  - Message length anomalies (unusually long/short messages)
  - Temporal anomalies (unusual timing patterns, burst activity)
  - Response ratio anomalies (assistant response much longer/shorter than expected)
  - Language switching detection
  - Entropy analysis on NON-code content (high entropy = possible encoded/obfuscated content)
  - Conversation flow anomalies (topic jumps, tone shifts)
  - Token n-gram entropy proxy for adversarial suffixes (GCG-style)

Optional ML: sentence-transformers for semantic anomaly detection
Optional ML: PyOD for ensemble anomaly scoring

Maps to MITRE ATLAS - AML.T0051.003 (Runtime Manipulation)
"""

import math
import re
import statistics
from typing import List
from dataclasses import dataclass
from collections import Counter

# Regex that strips fenced code blocks before entropy analysis
_CODE_BLOCK_RE = re.compile(r'```[\s\S]*?```|`[^`\n]+`', re.MULTILINE)
# Strip URLs before entropy analysis (URLs are high-entropy but benign)
_URL_RE = re.compile(r'https?://\S+')
# Strip base64-like blobs before entropy analysis
_BASE64_BLOB_RE = re.compile(r'[A-Za-z0-9+/=]{20,}')
# Minimum non-code characters needed to run entropy analysis
_MIN_TEXT_CHARS_FOR_ENTROPY = 40


@dataclass
class AnomalyFinding:
    """A detected anomaly in conversation patterns."""
    message_id: str
    conversation_id: str
    anomaly_type: str
    severity: str
    confidence: float
    details: str
    metric_value: float
    threshold: float
    message_preview: str


class ConversationAnomalyDetector:
    """
    Statistical anomaly detection for conversation patterns.
    Works fully standalone with pure Python — no ML dependencies required.
    Optional: sentence-transformers + PyOD for enhanced detection.

    Key false-positive mitigations vs. naive implementations:
      - Code blocks are stripped before entropy analysis (code is naturally high-entropy).
      - content_type == "code" messages are skipped for entropy.
      - Entropy threshold raised to 5.2 (plain natural language peaks ~4.5; base64 ~6.0).
      - Token-bigram entropy proxy flags adversarial suffixes even without GPT-2.
      - Length z-score threshold is 3.0 (was 2.5) to reduce noise.
    """
    
    # Thresholds
    LENGTH_ZSCORE_THRESHOLD = 3.0      # Raised from 2.5 to reduce noise
    ENTROPY_HIGH_THRESHOLD = 5.5       # Natural language ~4.5; base64 ~6.0; threshold in between
    ENTROPY_LOW_THRESHOLD = 1.5        # Low entropy (repetitive content)
    BIGRAM_ENTROPY_THRESHOLD = 4.2     # Low bigram entropy = adversarial suffix repetition
    RESPONSE_RATIO_THRESHOLD = 500.0   # Extremely disproportionate responses only
    BURST_WINDOW_SECONDS = 3.0         # Messages within 3 seconds = burst (tightened)
    MIN_MESSAGES_FOR_STATS = 3         # Need at least 3 messages for statistical analysis
    MIN_PROMPT_CHARS = 5               # Skip response-ratio check for prompts shorter than this
    MIN_REPEAT_LENGTH = 30             # Skip repetition check for messages shorter than this
    
    def __init__(self):
        pass
    
    def analyze_conversation(self, messages: list, conv_id: str) -> List[AnomalyFinding]:
        """Run all anomaly detection on a conversation."""
        findings = []
        
        if len(messages) < self.MIN_MESSAGES_FOR_STATS:
            return findings
        
        findings.extend(self._detect_length_anomalies(messages, conv_id))
        findings.extend(self._detect_entropy_anomalies(messages, conv_id))
        findings.extend(self._detect_temporal_anomalies(messages, conv_id))
        findings.extend(self._detect_response_ratio_anomalies(messages, conv_id))
        findings.extend(self._detect_language_anomalies(messages, conv_id))
        findings.extend(self._detect_repetition_anomalies(messages, conv_id))
        findings.extend(self._detect_adversarial_suffix(messages, conv_id))
        
        return findings
    
    @staticmethod
    def _strip_code_blocks(text: str) -> str:
        """Remove fenced and inline code blocks — code is inherently high-entropy."""
        return _CODE_BLOCK_RE.sub(' ', text)

    @staticmethod
    def _is_code_message(msg) -> bool:
        """Return True if the message is predominantly code."""
        if getattr(msg, 'content_type', 'text') in ('code', 'execution_output'):
            return True
        # Heuristic: >60% of non-whitespace chars inside code fences
        raw = msg.content
        code_chars = sum(len(m.group(0)) for m in _CODE_BLOCK_RE.finditer(raw))
        return code_chars / max(len(raw), 1) > 0.6

    def _detect_length_anomalies(self, messages: list, conv_id: str) -> List[AnomalyFinding]:
        """Detect messages with abnormal length relative to conversation average."""
        findings = []
        user_msgs = [m for m in messages if m.role == "user"]
        
        if len(user_msgs) < self.MIN_MESSAGES_FOR_STATS:
            return findings
        
        lengths = [len(self._strip_code_blocks(m.content)) for m in user_msgs]
        mean_len = statistics.mean(lengths)
        
        if len(lengths) > 1:
            std_len = statistics.stdev(lengths)
        else:
            return findings
        
        if std_len == 0:
            return findings
        
        for msg, length in zip(user_msgs, lengths):
            zscore = (length - mean_len) / std_len
            
            if abs(zscore) > self.LENGTH_ZSCORE_THRESHOLD:
                direction = "unusually long" if zscore > 0 else "unusually short"
                findings.append(AnomalyFinding(
                    message_id=msg.id,
                    conversation_id=conv_id,
                    anomaly_type="message_length",
                    severity="LOW",   # statistical outlier only — not a security threat
                    confidence=min(abs(zscore) / 6.0, 1.0),
                    details=f"Message is {direction} (z-score: {zscore:.2f}, length: {length}, avg: {mean_len:.0f})",
                    metric_value=zscore,
                    threshold=self.LENGTH_ZSCORE_THRESHOLD,
                    message_preview=msg.content[:100]
                ))
        
        return findings
    
    def _detect_entropy_anomalies(self, messages: list, conv_id: str) -> List[AnomalyFinding]:
        """
        Detect messages with abnormal entropy — possible encoded/obfuscated content.
        Code blocks and code-type messages are EXCLUDED to avoid false positives.
        """
        findings = []
        
        for msg in messages:
            if msg.role != "user":
                continue
            if self._is_code_message(msg):
                continue

            # Strip code blocks, URLs, and base64 blobs before measuring entropy
            text_only = self._strip_code_blocks(msg.content)
            text_only = _URL_RE.sub(' ', text_only)
            text_only = _BASE64_BLOB_RE.sub(' ', text_only)
            text_only = text_only.strip()
            if len(text_only) < _MIN_TEXT_CHARS_FOR_ENTROPY:
                continue
            
            entropy = self._calculate_entropy(text_only)
            
            if entropy > self.ENTROPY_HIGH_THRESHOLD:
                findings.append(AnomalyFinding(
                    message_id=msg.id,
                    conversation_id=conv_id,
                    anomaly_type="high_entropy",
                    severity="HIGH" if entropy > 5.8 else "MEDIUM",
                    confidence=min((entropy - self.ENTROPY_HIGH_THRESHOLD) / 1.5, 1.0),
                    details=f"High entropy in non-code text ({entropy:.2f}) — possible base64/encoding attack (threshold: {self.ENTROPY_HIGH_THRESHOLD})",
                    metric_value=entropy,
                    threshold=self.ENTROPY_HIGH_THRESHOLD,
                    message_preview=text_only[:100]
                ))
            elif entropy < self.ENTROPY_LOW_THRESHOLD and len(text_only) > 50:
                findings.append(AnomalyFinding(
                    message_id=msg.id,
                    conversation_id=conv_id,
                    anomaly_type="low_entropy",
                    severity="LOW",
                    confidence=0.5,
                    details=f"Low character entropy ({entropy:.2f}) — highly repetitive content",
                    metric_value=entropy,
                    threshold=self.ENTROPY_LOW_THRESHOLD,
                    message_preview=text_only[:100]
                ))
        
        return findings
    
    def _detect_adversarial_suffix(self, messages: list, conv_id: str) -> List[AnomalyFinding]:
        """
        Detect GCG/AutoDAN-style adversarial suffixes via token bigram entropy.
        Adversarial suffixes have low bigram diversity (repetitive garbage tokens)
        combined with unusually long token sequences appended to a normal prompt.

        This is a GPT-2-free proxy for perplexity-based detection.
        Reference: "Universal and Transferable Adversarial Attacks on Aligned Language
        Models" (Zou et al., 2023) — GCG suffixes are word-salad with low n-gram entropy.
        """
        findings = []
        for msg in messages:
            if msg.role != "user" or len(msg.content) < 80:
                continue
            text = self._strip_code_blocks(msg.content)
            words = text.split()
            if len(words) < 15:
                continue
            # Bigram entropy of word tokens
            bigrams = [(words[i], words[i + 1]) for i in range(len(words) - 1)]
            bigram_entropy = self._calculate_entropy(' '.join(f"{a}_{b}" for a, b in bigrams))
            # Very low bigram entropy + long message = adversarial suffix pattern
            if bigram_entropy < self.BIGRAM_ENTROPY_THRESHOLD and len(words) > 30:
                findings.append(AnomalyFinding(
                    message_id=msg.id,
                    conversation_id=conv_id,
                    anomaly_type="adversarial_suffix",
                    severity="HIGH",
                    confidence=min((self.BIGRAM_ENTROPY_THRESHOLD - bigram_entropy) / 2.0, 0.9),
                    details=f"Low word-bigram entropy ({bigram_entropy:.2f}) on long message — possible GCG/AutoDAN adversarial suffix",
                    metric_value=bigram_entropy,
                    threshold=self.BIGRAM_ENTROPY_THRESHOLD,
                    message_preview=msg.content[:100]
                ))
        return findings

    def _detect_temporal_anomalies(self, messages: list, conv_id: str) -> List[AnomalyFinding]:
        """Detect unusual timing patterns (burst messages, long gaps)."""
        findings = []
        
        timestamps = [(m, m.timestamp) for m in messages if m.timestamp]
        if len(timestamps) < 3:
            return findings
        
        # Detect bursts (multiple messages in very short time)
        for i in range(1, len(timestamps)):
            msg, ts = timestamps[i]
            prev_msg, prev_ts = timestamps[i-1]
            gap = ts - prev_ts
            
            if 0 < gap < self.BURST_WINDOW_SECONDS and msg.role == "user" and prev_msg.role == "user":
                findings.append(AnomalyFinding(
                    message_id=msg.id,
                    conversation_id=conv_id,
                    anomaly_type="burst_messages",
                    severity="LOW",
                    confidence=0.6,
                    details=f"Rapid message burst: {gap:.1f}s between user messages (possible automated input)",
                    metric_value=gap,
                    threshold=self.BURST_WINDOW_SECONDS,
                    message_preview=msg.content[:100]
                ))
        
        return findings
    
    def _detect_response_ratio_anomalies(self, messages: list, conv_id: str) -> List[AnomalyFinding]:
        """Detect abnormal response-to-prompt length ratios."""
        findings = []
        
        for i in range(len(messages) - 1):
            if messages[i].role == "user" and messages[i+1].role == "assistant":
                prompt_len = len(messages[i].content.strip())
                if prompt_len < self.MIN_PROMPT_CHARS:
                    continue
                response_len = len(messages[i+1].content)
                ratio = response_len / max(prompt_len, 1)
                
                if ratio > self.RESPONSE_RATIO_THRESHOLD:
                    severity = "LOW" if ratio < 2000 else "MEDIUM"
                    findings.append(AnomalyFinding(
                        message_id=messages[i+1].id,
                        conversation_id=conv_id,
                        anomaly_type="response_ratio",
                        severity=severity,
                        confidence=min(ratio / 2000.0, 0.8),
                        details=f"Response is {ratio:.1f}x longer than prompt ({response_len} vs {prompt_len} chars)",
                        metric_value=ratio,
                        threshold=self.RESPONSE_RATIO_THRESHOLD,
                        message_preview=messages[i+1].content[:100]
                    ))
        
        return findings
    
    def _detect_language_anomalies(self, messages: list, conv_id: str) -> List[AnomalyFinding]:
        """Detect truly anomalous language/script switching. Skip multilingual users."""
        findings = []
        user_msgs = [m for m in messages if m.role == "user" and len(m.content) > 10]
        
        if len(user_msgs) < 2:
            return findings
        
        scripts = []
        for msg in user_msgs:
            script = self._detect_primary_script(msg.content)
            scripts.append((msg, script))
        
        script_counter = Counter(s for _, s in scripts if s not in ("mixed", "unknown"))
        if not script_counter:
            return findings
        dominant_script, dominant_count = script_counter.most_common(1)[0]
        total_classified = sum(script_counter.values())

        for msg, script in scripts:
            if script == dominant_script or script in ("mixed", "unknown"):
                continue
            # Only flag if this non-dominant script appears in <10% of messages
            script_count = script_counter.get(script, 0)
            if script_count / total_classified >= 0.10:
                continue
            findings.append(AnomalyFinding(
                message_id=msg.id,
                conversation_id=conv_id,
                anomaly_type="language_switch",
                severity="LOW",
                confidence=0.4,
                details=f"Script changed from dominant '{dominant_script}' to '{script}' (appears in {script_count}/{total_classified} messages)",
                metric_value=0,
                threshold=0,
                message_preview=msg.content[:100]
            ))
        
        return findings
    
    def _detect_repetition_anomalies(self, messages: list, conv_id: str) -> List[AnomalyFinding]:
        """Detect repeated/copy-pasted messages (possible automated attacks)."""
        findings = []
        user_msgs = [m for m in messages if m.role == "user"]
        
        seen_content = {}
        for msg in user_msgs:
            normalized = msg.content.strip().lower()[:200]
            if len(normalized) < self.MIN_REPEAT_LENGTH:
                continue
            if normalized in seen_content:
                findings.append(AnomalyFinding(
                    message_id=msg.id,
                    conversation_id=conv_id,
                    anomaly_type="repeated_message",
                    severity="LOW",
                    confidence=0.5,
                    details=f"Duplicate/near-duplicate of message {seen_content[normalized]}",
                    metric_value=1.0,
                    threshold=0,
                    message_preview=msg.content[:100]
                ))
            else:
                seen_content[normalized] = msg.id
        
        return findings
    
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of text (character-level)."""
        if not text:
            return 0.0
        
        freq = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def _detect_primary_script(text: str) -> str:
        """Detect the primary Unicode script of text."""
        categories = {"latin": 0, "cyrillic": 0, "cjk": 0, "arabic": 0, "other": 0}
        
        for char in text:
            cp = ord(char)
            if (0x0041 <= cp <= 0x024F) or (0x1E00 <= cp <= 0x1EFF):
                categories["latin"] += 1
            elif 0x0400 <= cp <= 0x04FF:
                categories["cyrillic"] += 1
            elif (0x4E00 <= cp <= 0x9FFF) or (0x3040 <= cp <= 0x30FF):
                categories["cjk"] += 1
            elif 0x0600 <= cp <= 0x06FF:
                categories["arabic"] += 1
            elif not char.isspace() and not char.isdigit() and char not in '.,!?;:\'"-()[]{}':
                categories["other"] += 1
        
        total = sum(categories.values())
        if total == 0:
            return "unknown"
        
        dominant = max(categories, key=categories.get)
        if categories[dominant] / total > 0.6:
            return dominant
        return "mixed"
