"""
Prompt Injection Detector
Multi-layer detection pipeline:
  Layer 1: Regex pattern matching (fast, zero-cost)
  Layer 2: Heuristic scoring (phrase-based, context-aware)
  Layer 3: Transformer-based classification (DeBERTa-v3 via HuggingFace)
  Layer 4: Perplexity anomaly detection (GPT-2 based)
  Cross-layer: Consensus logic — heuristic-only findings require transformer
               confirmation when available; negative-context suppression.

Maps to OWASP LLM01:2025 - Prompt Injection
Maps to MITRE ATLAS - AML.T0051 (LLM Prompt Injection)
"""

import logging
import re
import base64
import binascii
import math
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False

try:
    from transformers import GPT2LMHeadModel, GPT2TokenizerFast
    import torch
    HAS_PERPLEXITY = True
except ImportError:
    HAS_PERPLEXITY = False


class InjectionType(Enum):
    DIRECT_INJECTION = "direct_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    ROLE_PLAY_ATTACK = "role_play_attack"
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    ENCODING_ATTACK = "encoding_attack"
    DELIMITER_ATTACK = "delimiter_attack"
    CONTEXT_MANIPULATION = "context_manipulation"


@dataclass
class InjectionFinding:
    """A single prompt injection detection result."""
    message_id: str
    conversation_id: str
    injection_type: InjectionType
    confidence: float  # 0.0 - 1.0
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    detection_layer: str  # regex, heuristic, transformer, perplexity
    matched_pattern: str
    message_preview: str
    owasp_ref: str = "LLM01:2025"
    mitre_ref: str = "AML.T0051"


class PromptInjectionDetector:
    """
    Multi-layer prompt injection detection engine.
    Designed for high precision (near-zero false positives) by combining:
      - Tight regex patterns that match actual attack syntax
      - Phrase-based heuristics (not single keywords) with negative-context suppression
      - Transformer model as the final arbiter when available
    """

    # ═══════════════════════════════════════════════════════════════
    # LAYER 1: Regex Patterns — tight, low-FP attack signatures
    # ═══════════════════════════════════════════════════════════════
    INJECTION_PATTERNS: Dict[InjectionType, List[Tuple[str, float]]] = {
        InjectionType.DIRECT_INJECTION: [
            (r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)', 0.95),
            (r'disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)', 0.95),
            (r'forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|prompts?|rules?|training)', 0.90),
            (r'override\s+(all\s+)?(previous|prior|system)\s+(instructions?|prompts?|settings?)', 0.95),
            (r'your\s+new\s+(role|persona|identity|purpose)\s+(is|will\s+be)', 0.85),
        ],
        InjectionType.JAILBREAK: [
            (r'\bDAN\b.*?(do\s+anything\s+now|freed|no\s+restrictions?)', 0.95),
            (r'you\s+are\s+now\s+(DAN|unrestricted|unfiltered|uncensored|jailbr[oe]ken)', 0.95),
            (r'act\s+(as|like)\s+(DAN|an?\s+unrestricted|an?\s+unfiltered)', 0.90),
            (r'pretend\s+(you\s+)?(are|have)\s+(no|zero)\s+(restrictions?|limits?|rules?|filters?)', 0.90),
            (r'developer\s+mode\s+(enabled|activated|on)', 0.90),
            (r'(enable|activate|enter)\s+(developer|god|admin|root|sudo)\s+mode', 0.90),
            (r'bypass\s+(your\s+)?(safety|content|ethical)\s+(filters?|guidelines?|restrictions?)', 0.85),
            (r'(anti[- ]?AI|anti[- ]?filter|anti[- ]?safety)\s+(mode|protocol)', 0.85),
        ],
        InjectionType.SYSTEM_PROMPT_LEAK: [
            (r'(reveal|show|display|print|output|tell\s+me)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|hidden\s+instructions?)', 0.95),
            (r'what\s+(are|were)\s+(your\s+)?(system|initial|original|hidden)\s+(prompt|instructions?)', 0.90),
            (r'(repeat|echo|recite)\s+(everything|all|your)\s+(above|before|system)', 0.85),
            (r'<\|im_(start|end)\|>', 0.95),
            (r'\[system\]\s*\(#(override|context|additional_instructions)\)', 0.95),
            (r'(start|begin)\s+your\s+response\s+with\s+"(system|instructions?|rules?):', 0.80),
        ],
        InjectionType.ROLE_PLAY_ATTACK: [
            (r'(pretend|imagine|hypothetical|suppose)\s+.{0,30}(no\s+restrictions?|unrestricted|anything\s+goes)', 0.80),
            (r'in\s+this\s+(scenario|story|fiction|game)\s*,?\s*(you\s+)?(can|are\s+able|have\s+permission)\s+to\s+(do\s+anything|ignore)', 0.75),
        ],
        InjectionType.ENCODING_ATTACK: [
            (r'base64\s*:\s*[A-Za-z0-9+/=]{20,}', 0.80),
            (r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}', 0.85),
            (r'&#x?[0-9a-fA-F]+;(&#x?[0-9a-fA-F]+;){5,}', 0.80),
        ],
        InjectionType.DELIMITER_ATTACK: [
            (r'---+\s*(system|new\s+instructions?|override|admin)', 0.85),
            (r'```\s*(system|instructions?|override)', 0.80),
            (r'<\|(system|im_start|endoftext)\|>', 0.95),
            (r'\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>', 0.90),
        ],
        InjectionType.CONTEXT_MANIPULATION: [
            (r'(the\s+above|previous)\s+(text|instructions?|content)\s+(is|was|were)\s+(fake|wrong|test|placeholder)', 0.80),
            (r'(actually|in\s+reality)\s*,?\s*(your|the)\s+(real|true|actual)\s+(instructions?|purpose|task)', 0.85),
            (r'(everything|all)\s+(above|before|prior)\s+(is|was)\s+(a\s+)?(lie|false|test|joke)', 0.80),
            (r'correction\s*:\s*(your\s+)?(real|actual|true)\s+(task|job|purpose|instructions?)', 0.85),
        ],
    }

    # ═══════════════════════════════════════════════════════════════
    # LAYER 2: Phrase-based heuristic keywords
    # Single ambiguous words (DAN, override, unrestricted, system prompt)
    # are REMOVED as standalone signals. Only multi-word attack phrases
    # contribute to the score.
    # ═══════════════════════════════════════════════════════════════
    SUSPICIOUS_PHRASES: List[Tuple[str, float, str]] = [
        # Direct injection phrases
        ("ignore all instructions", 0.45, "direct_injection"),
        ("ignore previous instructions", 0.45, "direct_injection"),
        ("ignore prior instructions", 0.45, "direct_injection"),
        ("disregard all instructions", 0.45, "direct_injection"),
        ("disregard previous instructions", 0.45, "direct_injection"),
        ("forget your instructions", 0.40, "direct_injection"),
        ("forget your training", 0.40, "direct_injection"),
        ("new instructions:", 0.30, "direct_injection"),
        ("your real purpose", 0.25, "context_manipulation"),
        ("secret instructions", 0.25, "direct_injection"),
        # Jailbreak phrases
        ("do anything now", 0.45, "jailbreak"),
        ("you are now DAN", 0.50, "jailbreak"),
        ("act as DAN", 0.50, "jailbreak"),
        ("jailbreak", 0.30, "jailbreak"),
        ("bypass safety", 0.40, "jailbreak"),
        ("bypass filters", 0.40, "jailbreak"),
        ("developer mode enabled", 0.40, "jailbreak"),
        ("enable developer mode", 0.40, "jailbreak"),
        ("enable god mode", 0.45, "jailbreak"),
        ("admin mode", 0.25, "jailbreak"),
        ("no restrictions mode", 0.35, "jailbreak"),
        ("without any restrictions", 0.20, "jailbreak"),
        ("remove all filters", 0.35, "jailbreak"),
        ("disable your safety", 0.40, "jailbreak"),
        ("uncensored mode", 0.40, "jailbreak"),
        # System prompt extraction
        ("show me your system prompt", 0.45, "system_prompt_leak"),
        ("reveal your system prompt", 0.45, "system_prompt_leak"),
        ("print your system prompt", 0.45, "system_prompt_leak"),
        ("what is your system prompt", 0.40, "system_prompt_leak"),
        ("output your instructions", 0.35, "system_prompt_leak"),
        ("tell me your hidden instructions", 0.45, "system_prompt_leak"),
        # Role-play attack
        ("pretend you have no restrictions", 0.40, "role_play_attack"),
        ("pretend you are unrestricted", 0.40, "role_play_attack"),
        ("imagine you have no rules", 0.35, "role_play_attack"),
        ("in this scenario you can do anything", 0.35, "role_play_attack"),
    ]

    HEURISTIC_THRESHOLD = 0.65

    # ═══════════════════════════════════════════════════════════════
    # NEGATIVE CONTEXT: patterns that indicate the message is benign
    # despite containing suspicious keywords. Presence of these
    # suppresses or vetoes heuristic findings.
    # ═══════════════════════════════════════════════════════════════
    BENIGN_CONTEXT_PATTERNS = [
        # Legal / contract language
        r'(?:employment|contract|agreement|§\s?\d|clause|herein|pursuant|effective\s+from|party|parties)',
        # GPT builder / developer context
        r'(?:custom\s+gpt|gpt\s+builder|my\s+gpt|update\s+(?:the|my)\s+system\s+prompt|check\s+my\s+(?:latest\s+)?system\s+prompt)',
        # Educational / analytical discussion
        r'(?:what\s+is\s+(?:a\s+)?jailbreak|explain\s+prompt\s+injection|how\s+(?:does|do)\s+(?:prompt\s+)?injection|security\s+(?:research|analysis|audit))',
        # Resume / CV / job application
        r'(?:internship|resume|curriculum\s+vitae|job\s+description|cover\s+letter|employment\s+history)',
        # Technical documentation or code review
        r'(?:documentation|readme|changelog|release\s+notes|api\s+reference|config(?:uration)?)',
    ]

    # ═══════════════════════════════════════════════════════════════
    # TRANSFORMER SETTINGS
    # The DeBERTa-v3 prompt-injection model was trained as a guard
    # between system prompt and user input. In a conversation history
    # scan, almost every user message is classified as "INJECTION"
    # because it contains instructions directed at the AI. Therefore
    # we use the transformer ONLY as a confirmation layer — it can
    # upgrade or veto regex/heuristic findings but never fires alone.
    # ═══════════════════════════════════════════════════════════════
    TRANSFORMER_CONFIRM_THRESHOLD = 0.70

    def __init__(self, use_transformer: bool = True, use_perplexity: bool = False):
        self.use_transformer = use_transformer and HAS_TRANSFORMERS
        self.use_perplexity = use_perplexity and HAS_PERPLEXITY
        self._classifier = None
        self._perplexity_model = None
        self._perplexity_tokenizer = None

    def _load_transformer(self):
        """Load DeBERTa-v3 prompt injection classifier."""
        if self._classifier is None and self.use_transformer:
            try:
                self._classifier = pipeline(
                    "text-classification",
                    model="protectai/deberta-v3-base-prompt-injection-v2",
                    truncation=True,
                    max_length=512
                )
                logger.info("Loaded DeBERTa-v3 prompt injection model")
            except Exception as e:
                logger.warning("Could not load transformer model: %s", e)
                self.use_transformer = False

    def _load_perplexity_model(self):
        """Load GPT-2 for perplexity-based anomaly detection."""
        if self._perplexity_model is None and self.use_perplexity:
            try:
                self._perplexity_tokenizer = GPT2TokenizerFast.from_pretrained("gpt2")
                self._perplexity_model = GPT2LMHeadModel.from_pretrained("gpt2")
                self._perplexity_model.eval()
                logger.info("Loaded GPT-2 perplexity model")
            except Exception as e:
                logger.warning("Could not load perplexity model: %s", e)
                self.use_perplexity = False

    # ───────────────────────────────────────────────────────────────
    # Public API
    # ───────────────────────────────────────────────────────────────
    def analyze_message(self, text: str, msg_id: str, conv_id: str) -> List[InjectionFinding]:
        """Run all detection layers on a single message, then apply consensus."""
        if not text or len(text.strip()) < 5:
            return []

        regex_findings = self._regex_scan(text, msg_id, conv_id)
        encoding_findings = self._encoding_rescan(text, msg_id, conv_id)
        heuristic_finding = self._heuristic_scan(text, msg_id, conv_id)

        # Transformer scan (runs once per message, cached)
        transformer_finding = None
        transformer_label = None
        transformer_score = 0.0
        if self.use_transformer:
            self._load_transformer()
            transformer_finding, transformer_label, transformer_score = self._transformer_scan(text, msg_id, conv_id)

        # Perplexity scan
        perplexity_finding = None
        if self.use_perplexity:
            self._load_perplexity_model()
            perplexity_finding = self._perplexity_scan(text, msg_id, conv_id)

        # ── CONSENSUS LOGIC ──
        confirmed = []

        # Regex findings: high precision, keep as-is unless transformer vetoes
        for f in regex_findings:
            if self.use_transformer and transformer_label == "SAFE" and transformer_score > 0.90:
                # Strong transformer veto: suppress low-confidence regex matches
                if f.confidence < 0.85:
                    continue
            confirmed.append(f)

        # Encoding findings: high precision, keep
        confirmed.extend(encoding_findings)

        # Heuristic finding: requires corroboration
        if heuristic_finding:
            if self._is_benign_context(text):
                pass  # Suppressed by negative-context
            elif self.use_transformer:
                if transformer_label == "INJECTION" and transformer_score >= self.TRANSFORMER_CONFIRM_THRESHOLD:
                    heuristic_finding.confidence = max(heuristic_finding.confidence, transformer_score)
                    heuristic_finding.severity = self._confidence_to_severity(heuristic_finding.confidence)
                    heuristic_finding.matched_pattern += f" [transformer-confirmed: {transformer_score:.2f}]"
                    confirmed.append(heuristic_finding)
                # else: transformer did not confirm → suppress heuristic
            else:
                # No transformer available: only keep high-confidence heuristic (>=0.70)
                if heuristic_finding.confidence >= 0.70:
                    confirmed.append(heuristic_finding)

        # Transformer is confirmation-only — no standalone findings.
        # The model FPs on normal user messages in conversation history.

        # Perplexity finding
        if perplexity_finding:
            confirmed.append(perplexity_finding)

        return confirmed

    # ───────────────────────────────────────────────────────────────
    # Layer 1: Regex
    # ───────────────────────────────────────────────────────────────
    def _regex_scan(self, text: str, msg_id: str, conv_id: str) -> List[InjectionFinding]:
        """Layer 1: Tight regex pattern matching."""
        findings = []
        text_lower = text.lower()

        for inj_type, patterns in self.INJECTION_PATTERNS.items():
            for pattern, confidence in patterns:
                match = re.search(pattern, text_lower, re.DOTALL)
                if match:
                    # Extra check: suppress if this sits inside benign context
                    if self._is_benign_context(text):
                        continue
                    findings.append(InjectionFinding(
                        message_id=msg_id,
                        conversation_id=conv_id,
                        injection_type=inj_type,
                        confidence=confidence,
                        severity=self._confidence_to_severity(confidence),
                        detection_layer="regex",
                        matched_pattern=pattern[:60],
                        message_preview=text[:100]
                    ))
        return findings

    # ───────────────────────────────────────────────────────────────
    # Layer 2: Phrase-based heuristic
    # ───────────────────────────────────────────────────────────────
    def _heuristic_scan(self, text: str, msg_id: str, conv_id: str) -> Optional[InjectionFinding]:
        """
        Layer 2: Phrase-based heuristic scoring.
        Only multi-word attack phrases are scored. Single ambiguous words
        (DAN, override, unrestricted) do NOT contribute on their own.
        """
        text_lower = text.lower()
        score = 0.0
        matched = []
        type_votes: Dict[str, float] = {}

        for phrase, weight, hint in self.SUSPICIOUS_PHRASES:
            if phrase in text_lower:
                score += weight
                matched.append(phrase)
                type_votes[hint] = type_votes.get(hint, 0) + weight

        score = min(score, 1.0)

        if score >= self.HEURISTIC_THRESHOLD and matched:
            dominant_type_str = max(type_votes, key=type_votes.get) if type_votes else "direct_injection"
            try:
                dominant_type = InjectionType(dominant_type_str)
            except ValueError:
                dominant_type = InjectionType.DIRECT_INJECTION

            return InjectionFinding(
                message_id=msg_id,
                conversation_id=conv_id,
                injection_type=dominant_type,
                confidence=score,
                severity=self._confidence_to_severity(score),
                detection_layer="heuristic",
                matched_pattern=f"Phrases: {', '.join(matched[:5])}",
                message_preview=text[:100]
            )
        return None

    # ───────────────────────────────────────────────────────────────
    # Layer 1b: Encoding decode + rescan
    # ───────────────────────────────────────────────────────────────
    def _encoding_rescan(self, text: str, msg_id: str, conv_id: str) -> List[InjectionFinding]:
        """Decode base64 payloads and re-scan the decoded content."""
        findings = []
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        for match in b64_pattern.finditer(text):
            blob = match.group(0)
            if len(blob) < 20:
                continue
            try:
                decoded = base64.b64decode(blob + '==').decode('utf-8', errors='ignore')
            except (binascii.Error, UnicodeDecodeError):
                continue
            if len(decoded) < 10 or sum(1 for c in decoded if c.isprintable()) / len(decoded) < 0.7:
                continue
            sub_findings = self._regex_scan(decoded, msg_id, conv_id)
            for f in sub_findings:
                f.matched_pattern = f"[BASE64-DECODED] {f.matched_pattern}"
                f.detection_layer = "encoding_decode"
                f.injection_type = InjectionType.ENCODING_ATTACK
                findings.append(f)
        return findings

    # ───────────────────────────────────────────────────────────────
    # Layer 3: Transformer
    # ───────────────────────────────────────────────────────────────
    def _transformer_scan(self, text: str, msg_id: str, conv_id: str) -> Tuple[None, Optional[str], float]:
        """
        Layer 3: DeBERTa-v3 transformer classification.
        Returns (None, label, score). Used only for confirmation/veto,
        never generates standalone findings.
        """
        if not self._classifier:
            return None, None, 0.0

        try:
            result = self._classifier(text[:512])[0]
            return None, result["label"], result["score"]
        except Exception:
            return None, None, 0.0

    # ───────────────────────────────────────────────────────────────
    # Layer 4: Perplexity
    # ───────────────────────────────────────────────────────────────
    def _perplexity_scan(self, text: str, msg_id: str, conv_id: str) -> Optional[InjectionFinding]:
        """Layer 4: Perplexity-based anomaly detection for adversarial suffixes."""
        if not self._perplexity_model:
            return None
        try:
            encodings = self._perplexity_tokenizer(
                text[:512], return_tensors="pt", truncation=True, max_length=512
            )
            with torch.no_grad():
                outputs = self._perplexity_model(**encodings, labels=encodings["input_ids"])
                perplexity = math.exp(outputs.loss.item())
            if perplexity > 500:
                confidence = min((perplexity - 500) / 1000, 1.0)
                return InjectionFinding(
                    message_id=msg_id,
                    conversation_id=conv_id,
                    injection_type=InjectionType.ENCODING_ATTACK,
                    confidence=confidence,
                    severity=self._confidence_to_severity(confidence),
                    detection_layer="perplexity",
                    matched_pattern=f"Perplexity: {perplexity:.1f} (threshold: 500)",
                    message_preview=text[:100]
                )
        except Exception:
            pass
        return None

    # ───────────────────────────────────────────────────────────────
    # Negative-context detector
    # ───────────────────────────────────────────────────────────────
    def _is_benign_context(self, text: str) -> bool:
        """
        Check if the message is in a benign context that explains
        why suspicious keywords appear (legal text, GPT building, etc.).
        """
        text_lower = text.lower()
        for pattern in self.BENIGN_CONTEXT_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        return False

    # ───────────────────────────────────────────────────────────────
    # Multi-turn escalation
    # ───────────────────────────────────────────────────────────────
    def detect_multi_turn_escalation(self, messages: list) -> List[InjectionFinding]:
        """
        Detect multi-turn escalation attacks (Crescendo-style).
        Only triggers when a message has actual regex matches (not just keywords)
        after a sequence of clean messages.
        """
        findings = []
        user_msgs = [m for m in messages if m.role == "user"]

        if len(user_msgs) < 4:
            return findings

        for i, msg in enumerate(user_msgs):
            if i < 2:
                continue

            current_regex = self._regex_scan(msg.content, msg.id, "")
            if not current_regex:
                continue

            # Verify preceding messages were clean
            prev_clean = all(
                not self._regex_scan(user_msgs[j].content, user_msgs[j].id, "")
                for j in range(max(0, i - 3), i)
            )
            if prev_clean:
                best = max(current_regex, key=lambda f: f.confidence)
                findings.append(InjectionFinding(
                    message_id=msg.id,
                    conversation_id="",
                    injection_type=InjectionType.MULTI_TURN_ESCALATION,
                    confidence=best.confidence,
                    severity="HIGH",
                    detection_layer="multi_turn",
                    matched_pattern=f"Escalation at msg[{i}]: clean history then regex match ({best.matched_pattern[:40]})",
                    message_preview=msg.content[:100]
                ))

        return findings

    # ───────────────────────────────────────────────────────────────
    # Helpers
    # ───────────────────────────────────────────────────────────────
    @staticmethod
    def _confidence_to_severity(confidence: float) -> str:
        if confidence >= 0.9:
            return "CRITICAL"
        elif confidence >= 0.7:
            return "HIGH"
        elif confidence >= 0.5:
            return "MEDIUM"
        return "LOW"
