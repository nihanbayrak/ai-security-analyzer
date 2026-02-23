"""
PII & Data Leakage Detector
Detects personal information, credentials, and sensitive data in conversations.

Detection categories:
  - Personal: Names, emails, phones, SSN, addresses, dates of birth
  - Financial: Credit cards, bank accounts, IBAN
  - Credentials: API keys, passwords, tokens, AWS keys, private keys
  - Technical: IP addresses, internal URLs, database connection strings
  - Health: Medical record numbers (basic patterns)

Maps to OWASP LLM06:2025 - Excessive Agency / Sensitive Information Disclosure
Maps to MITRE ATLAS - AML.T0024.002 (Exfiltration via Cyber Means)
"""

import logging
import re
from typing import List, Dict, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class PIICategory(Enum):
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    ADDRESS = "address"
    API_KEY_OPENAI = "api_key_openai"
    API_KEY_GENERIC = "api_key_generic"
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GITHUB_TOKEN = "github_token"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    IP_ADDRESS = "ip_address"
    INTERNAL_URL = "internal_url"
    DB_CONNECTION_STRING = "db_connection_string"
    IBAN = "iban"
    DATE_OF_BIRTH = "date_of_birth"
    PASSPORT = "passport"
    JWT_TOKEN = "jwt_token"
    CRYPTO_WALLET = "crypto_wallet"


@dataclass
class PIIFinding:
    """A single PII/data leakage finding."""
    message_id: str
    conversation_id: str
    category: PIICategory
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float
    matched_value: str  # Redacted version
    position: Tuple[int, int]  # Start, end position in text
    message_preview: str
    recommendation: str
    owasp_ref: str = "LLM06:2025"
    
    @property
    def is_credential(self) -> bool:
        return self.category in {
            PIICategory.API_KEY_OPENAI, PIICategory.API_KEY_GENERIC,
            PIICategory.AWS_ACCESS_KEY, PIICategory.AWS_SECRET_KEY,
            PIICategory.GITHUB_TOKEN, PIICategory.PASSWORD,
            PIICategory.PRIVATE_KEY, PIICategory.JWT_TOKEN,
        }


class PIIDetector:
    """
    Multi-pattern PII and credential detector.
    Works standalone with regex patterns. 
    Optional: Presidio integration for enhanced NER-based detection.
    """
    
    # Pattern: (regex, PIICategory, severity, confidence, redact_func, recommendation)
    PATTERNS: List[tuple] = [
        # === CREDENTIALS (CRITICAL) ===
        (
            r'sk-(?:proj-)?[a-zA-Z0-9]{32,}',
            PIICategory.API_KEY_OPENAI, "CRITICAL", 0.98,
            "[CRITICAL] OpenAI API key detected. Rotate immediately at platform.openai.com"
        ),
        (
            r'sk-ant-api\d{2}-[a-zA-Z0-9\-_]{80,}',
            PIICategory.API_KEY_GENERIC, "CRITICAL", 0.98,
            "[CRITICAL] Anthropic API key detected. Rotate immediately."
        ),
        (
            r'AKIA[0-9A-Z]{16}',
            PIICategory.AWS_ACCESS_KEY, "CRITICAL", 0.99,
            "[CRITICAL] AWS Access Key detected. Rotate immediately in AWS IAM console."
        ),
        (
            r'(?:aws.{0,20}secret.{0,10}|wJalrXUtnFEMI)[A-Za-z0-9/+=]{30,50}',
            PIICategory.AWS_SECRET_KEY, "CRITICAL", 0.90,
            "[CRITICAL] Possible AWS Secret Key detected. Rotate immediately."
        ),
        (
            r'ghp_[a-zA-Z0-9]{36}',
            PIICategory.GITHUB_TOKEN, "CRITICAL", 0.99,
            "[CRITICAL] GitHub Personal Access Token detected. Revoke at github.com/settings/tokens"
        ),
        (
            r'gh[oups]_[a-zA-Z0-9]{36,}',
            PIICategory.GITHUB_TOKEN, "CRITICAL", 0.95,
            "[CRITICAL] GitHub token detected. Revoke at github.com/settings/tokens"
        ),
        (
            r'(?:password|passwd|pwd)\s*[:=]\s*\S{6,}',
            PIICategory.PASSWORD, "CRITICAL", 0.85,
            "[CRITICAL] Password detected in plain text. Change immediately."
        ),
        (
            r'-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----',
            PIICategory.PRIVATE_KEY, "CRITICAL", 0.99,
            "[CRITICAL] Private key detected. Regenerate key pair immediately."
        ),
        (
            r'eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}',
            PIICategory.JWT_TOKEN, "HIGH", 0.95,
            "[HIGH] JWT token detected. Verify it hasn't been compromised."
        ),
        (
            r'xox[boaprs]-[a-zA-Z0-9\-]{10,}',
            PIICategory.API_KEY_GENERIC, "CRITICAL", 0.95,
            "[CRITICAL] Slack token detected. Revoke at api.slack.com"
        ),
        
        # === PERSONAL INFO (HIGH) ===
        (
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            PIICategory.EMAIL, "HIGH", 0.95,
            "Email address exposed. Avoid sharing in AI conversations."
        ),
        (
            r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            PIICategory.PHONE, "HIGH", 0.80,
            "Phone number detected. Remove from conversation history."
        ),
        # International phone format (E.164)
        (
            r'\+\d{1,3}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{2,4}\b',
            PIICategory.PHONE, "HIGH", 0.85,
            "International phone number detected."
        ),
        (
            r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b',
            PIICategory.SSN, "CRITICAL", 0.75,
            "[CRITICAL] Possible SSN detected. This is extremely sensitive - rotate if real."
        ),
        
        # === FINANCIAL (CRITICAL) ===
        (
            r'\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{1}|6(?:011|5[0-9]{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}\b',
            PIICategory.CREDIT_CARD, "CRITICAL", 0.90,
            "[CRITICAL] Credit card number detected. Monitor for unauthorized charges."
        ),
        (
            r'\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,4}\s?\d{0,2}\b',
            PIICategory.IBAN, "HIGH", 0.85,
            "IBAN detected. Avoid sharing banking details."
        ),
        
        # === TECHNICAL (HIGH) ===
        # Only public IPs — private ranges (10.x, 172.16-31.x, 192.168.x, 127.x) excluded via post-filter
        (
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            PIICategory.IP_ADDRESS, "MEDIUM", 0.80,
            "Public IP address detected. May reveal network information."
        ),
        (
            r'https?://(?:internal|intranet|corp|private|staging|dev)\.[a-zA-Z0-9.-]+(?:/[^\s]*)?',
            PIICategory.INTERNAL_URL, "HIGH", 0.90,
            "Internal URL detected. May expose infrastructure details."
        ),
        (
            r'(?:mongodb|postgresql|mysql|redis|amqp)://[^\s]+',
            PIICategory.DB_CONNECTION_STRING, "CRITICAL", 0.95,
            "[CRITICAL] Database connection string detected. Contains credentials!"
        ),
        (
            r'(?:postgres|mysql|mssql)://\S+:\S+@\S+',
            PIICategory.DB_CONNECTION_STRING, "CRITICAL", 0.95,
            "[CRITICAL] Database connection string with credentials detected."
        ),
        
        # === CRYPTO ===
        (
            r'\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b',
            PIICategory.CRYPTO_WALLET, "MEDIUM", 0.75,
            "Crypto wallet address detected."
        ),
    ]

    # Private/reserved IP ranges — never flag these
    _PRIVATE_IP_RE = re.compile(
        r'^(?:10\.|127\.|169\.254\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)'
    )

    # Well-known / non-personal IPs — not worth flagging
    _IGNORE_IPS = {
        "0.0.0.0", "255.255.255.255",
        "1.1.1.1", "1.0.0.1",           # Cloudflare DNS
        "8.8.8.8", "8.8.4.4",           # Google DNS
        "9.9.9.9", "149.112.112.112",   # Quad9 DNS
        "208.67.222.222", "208.67.220.220",  # OpenDNS
    }

    # Version-number context: IP-like string preceded by 'v', 'version', '=' etc.
    _VERSION_CONTEXT_RE = re.compile(
        r'(?:version|ver|v)\s*\.?\s*$|=\s*$|[a-zA-Z]$',
        re.IGNORECASE
    )

    # Indirect exfiltration: URLs carrying suspicious query params (data encoding)
    # Reference: Perez & Ribeiro (2022) — prompt injection via GET params
    _EXFIL_URL_RE = re.compile(
        r'https?://[^\s]+\?[^\s]*(?:data|payload|token|key|secret|text|content|msg)=[^\s&]{20,}',
        re.IGNORECASE
    )

    # Domains that are part of normal ChatGPT operation — never flag as exfiltration
    _SAFE_DOMAINS = re.compile(
        r'https?://(?:[a-z0-9-]+\.)?(?:chatgpt\.com|openai\.com|oaiusercontent\.com|'
        r'githubusercontent\.com|github\.com|google\.com|bing\.com|'
        r'wikipedia\.org|stackoverflow\.com|stackexchange\.com|'
        r'youtube\.com|reddit\.com|medium\.com|docs\.python\.org|'
        r'npmjs\.com|pypi\.org|developer\.mozilla\.org|'
        r'arxiv\.org|doi\.org|pubmed\.ncbi\.nlm\.nih\.gov)',
        re.IGNORECASE
    )
    
    def __init__(self, use_presidio: bool = False):
        self.use_presidio = use_presidio
        self._presidio_analyzer = None
        
        if use_presidio:
            self._init_presidio()
    
    def _init_presidio(self):
        """Initialize Microsoft Presidio for enhanced NER-based PII detection."""
        try:
            from presidio_analyzer import AnalyzerEngine
            self._presidio_analyzer = AnalyzerEngine()
            logger.info("Presidio PII analyzer loaded")
        except ImportError:
            logger.info("Presidio not installed — using regex-only mode")
            self.use_presidio = False
    
    def analyze_message(self, text: str, msg_id: str, conv_id: str, role: str = "user") -> List[PIIFinding]:
        """Scan a message for PII and credential leakage."""
        findings = []
        
        # Regex-based detection
        for pattern, category, severity, confidence, recommendation in self.PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                matched = match.group()

                # --- False-positive filters ---
                if category == PIICategory.IP_ADDRESS:
                    if self._PRIVATE_IP_RE.match(matched):
                        continue
                    if matched in self._IGNORE_IPS:
                        continue
                    if self._is_version_number(text, match.start()):
                        continue

                if category == PIICategory.SSN:
                    if not self._ssn_context_valid(text, match.start()):
                        continue
                    if self._ssn_looks_like_date(text, match.start(), match.end()):
                        continue

                if category == PIICategory.PHONE:
                    if not self._phone_context_valid(text, match.start(), match.end()):
                        continue
                    if self._is_fake_phone(matched):
                        continue

                if category == PIICategory.IBAN:
                    if not self._iban_checksum_valid(matched):
                        continue

                if category == PIICategory.PASSWORD:
                    if self._password_in_code_context(text, match.start()):
                        continue

                if category == PIICategory.CREDIT_CARD:
                    digits = re.sub(r'[^0-9]', '', matched)
                    if not self._luhn_check(digits):
                        continue

                redacted = self._redact(matched, category)
                findings.append(PIIFinding(
                    message_id=msg_id,
                    conversation_id=conv_id,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    matched_value=redacted,
                    position=(match.start(), match.end()),
                    message_preview=text[:100],
                    recommendation=recommendation
                ))

        # Indirect exfiltration URL detection (GET params carrying large payloads)
        findings.extend(self._scan_exfil_urls(text, msg_id, conv_id))
        
        # Presidio-based detection (if available)
        if self.use_presidio and self._presidio_analyzer:
            findings.extend(self._presidio_scan(text, msg_id, conv_id))
        
        # Deduplicate overlapping findings
        findings = self._deduplicate(findings)
        
        return findings

    @staticmethod
    def _phone_context_valid(text: str, start: int, end: int) -> bool:
        """
        Require phone-related context near the matched digits to reduce false positives.
        Without this, any NNN-NNN-NNNN in code, hex, timestamps, or IDs triggers.
        """
        window = text[max(0, start - 80):end + 40].lower()
        # Explicit phone context
        phone_terms = (
            "phone", "tel", "call", "mobile", "cell", "fax", "whatsapp",
            "sms", "text me", "contact", "dial", "ring", "numara", "telefon",
            "arama", "iletişim", "+90", "+1", "+44", "+49",
            "number", "reach", "ext", "voicemail", "direct line",
        )
        if any(t in window for t in phone_terms):
            return True
        # International format (starts with +) is always valid
        raw = text[start:end].strip()
        if raw.startswith('+'):
            return True
        # Parenthesized area code like (555) is strong signal
        if '(' in raw and ')' in raw:
            return True
        return False

    @staticmethod
    def _luhn_check(digits: str) -> bool:
        """Luhn checksum — filters out random digit sequences that aren't real card numbers."""
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        for i, d in enumerate(reversed(digits)):
            n = int(d)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    @staticmethod
    def _ssn_context_valid(text: str, pos: int) -> bool:
        """
        Heuristic: an SSN-shaped number (NNN-NN-NNNN) is only flagged when the
        surrounding context contains SSN-related terms, reducing false positives
        from dates, order numbers, version strings, and phone numbers.
        """
        window = text[max(0, pos - 60):pos + 80].lower()
        ssn_terms = ("ssn", "social security", "taxpayer", "itin", "tax id", "ein")
        return any(t in window for t in ssn_terms)

    @staticmethod
    def _is_version_number(text: str, match_start: int) -> bool:
        """Check if the IP-like string is actually a version number (e.g., v2.1.0.1)."""
        prefix = text[max(0, match_start - 12):match_start]
        if re.search(r'(?:version|ver|v)\s*\.?\s*$', prefix, re.IGNORECASE):
            return True
        if re.search(r'[a-zA-Z]$', prefix):
            return True
        return False

    @staticmethod
    def _is_fake_phone(raw: str) -> bool:
        """Filter out known fake/test phone numbers (US 555 prefix, etc.)."""
        digits = re.sub(r'[^0-9]', '', raw)
        if len(digits) < 7:
            return True
        # US 555-0100 to 555-0199 are reserved fictional numbers
        if '555' in digits:
            return True
        return False

    @staticmethod
    def _ssn_looks_like_date(text: str, match_start: int, match_end: int) -> bool:
        """Check if an SSN-shaped pattern (NNN-NN-NNNN) is actually a date."""
        raw = text[match_start:match_end]
        parts = re.split(r'[-.\s]', raw)
        if len(parts) == 3:
            try:
                mid = int(parts[1])
                last = int(parts[2])
                if 1 <= mid <= 12 and 1900 <= last <= 2099:
                    return True
            except ValueError:
                pass
        return False

    @staticmethod
    def _password_in_code_context(text: str, match_start: int) -> bool:
        """Check if the password match is inside code/documentation (not a real credential)."""
        window = text[max(0, match_start - 100):match_start + 100].lower()
        code_markers = (
            "```", "def ", "function ", "const ", "var ", "let ", "class ",
            "example", "placeholder", "dummy", "test", "sample", "template",
            "todo", "fixme", "mock", "fake", "default",
        )
        return any(m in window for m in code_markers)

    @staticmethod
    def _iban_checksum_valid(raw: str) -> bool:
        """Validate IBAN using ISO 7064 MOD-97-10 check."""
        iban = raw.replace(" ", "").upper()
        if len(iban) < 5:
            return False
        rearranged = iban[4:] + iban[:4]
        numeric = ""
        for c in rearranged:
            if c.isdigit():
                numeric += c
            elif c.isalpha():
                numeric += str(ord(c) - ord('A') + 10)
            else:
                return False
        try:
            return int(numeric) % 97 == 1
        except (ValueError, OverflowError):
            return False

    def _scan_exfil_urls(self, text: str, msg_id: str, conv_id: str) -> List['PIIFinding']:
        """
        Detect indirect data exfiltration via URLs with data-carrying query parameters.
        Pattern: attacker crafts a URL like https://evil.com?data=<stolen_content>
        Reference: OWASP LLM06:2025 — Sensitive Information Disclosure via indirect exfil.
        """
        findings = []
        for match in self._EXFIL_URL_RE.finditer(text):
            url = match.group(0)
            if self._SAFE_DOMAINS.match(url):
                continue
            findings.append(PIIFinding(
                message_id=msg_id,
                conversation_id=conv_id,
                category=PIICategory.INTERNAL_URL,
                severity="HIGH",
                confidence=0.75,
                matched_value=url[:60] + "..." if len(url) > 60 else url,
                position=(match.start(), match.end()),
                message_preview=text[:100],
                recommendation="[WARNING] URL with large data payload in query params - possible indirect exfiltration attempt."
            ))
        return findings
    
    def _presidio_scan(self, text: str, msg_id: str, conv_id: str) -> List[PIIFinding]:
        """Run Microsoft Presidio PII analysis."""
        findings = []
        try:
            results = self._presidio_analyzer.analyze(
                text=text, language='en',
                entities=[
                    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", 
                    "CREDIT_CARD", "US_SSN", "IBAN_CODE",
                    "IP_ADDRESS", "US_PASSPORT", "LOCATION"
                ]
            )
            
            presidio_to_category = {
                "EMAIL_ADDRESS": PIICategory.EMAIL,
                "PHONE_NUMBER": PIICategory.PHONE,
                "CREDIT_CARD": PIICategory.CREDIT_CARD,
                "US_SSN": PIICategory.SSN,
                "IBAN_CODE": PIICategory.IBAN,
                "IP_ADDRESS": PIICategory.IP_ADDRESS,
                "US_PASSPORT": PIICategory.PASSPORT,
            }
            
            for result in results:
                category = presidio_to_category.get(result.entity_type)
                if category and result.score > 0.5:
                    matched = text[result.start:result.end]
                    findings.append(PIIFinding(
                        message_id=msg_id,
                        conversation_id=conv_id,
                        category=category,
                        severity="HIGH",
                        confidence=result.score,
                        matched_value=self._redact(matched, category),
                        position=(result.start, result.end),
                        message_preview=text[:100],
                        recommendation=f"Presidio detected {result.entity_type}."
                    ))
        except Exception:
            logger.exception("Presidio scan failed")
        return findings
    
    @staticmethod
    def _redact(value: str, category: PIICategory) -> str:
        """Redact sensitive values for safe display."""
        if len(value) <= 4:
            return "****"
        
        if category in {PIICategory.API_KEY_OPENAI, PIICategory.API_KEY_GENERIC,
                        PIICategory.AWS_SECRET_KEY, PIICategory.GITHUB_TOKEN,
                        PIICategory.JWT_TOKEN}:
            return value[:8] + "..." + value[-4:]
        
        if category == PIICategory.EMAIL:
            parts = value.split("@")
            return parts[0][:2] + "***@" + parts[1] if len(parts) == 2 else "***"
        
        if category == PIICategory.CREDIT_CARD:
            digits = re.sub(r'[^0-9]', '', value)
            return "****-****-****-" + digits[-4:] if len(digits) >= 4 else "****"
        
        if category == PIICategory.SSN:
            return "***-**-" + value[-4:]
        
        if category == PIICategory.PHONE:
            return "***-***-" + value[-4:]
        
        if category == PIICategory.PASSWORD:
            return value[:9] + "****"
        
        return value[:4] + "***" + value[-2:]
    
    @staticmethod
    def _deduplicate(findings: List[PIIFinding]) -> List[PIIFinding]:
        """Remove duplicate findings based on overlapping positions."""
        if not findings:
            return findings
        
        findings.sort(key=lambda f: (f.position[0], -f.confidence))
        result = [findings[0]]
        
        for f in findings[1:]:
            prev = result[-1]
            # Check for overlap
            if f.position[0] >= prev.position[1]:
                result.append(f)
            elif f.confidence > prev.confidence:
                result[-1] = f
        
        return result
    
    def get_risk_summary(self, findings: List[PIIFinding]) -> Dict:
        """Generate risk summary from findings."""
        if not findings:
            return {"risk_level": "LOW", "total_findings": 0}
        
        credential_count = sum(1 for f in findings if f.is_credential)
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        
        categories = {}
        for f in findings:
            cat = f.category.value
            if cat not in categories:
                categories[cat] = 0
            categories[cat] += 1
        
        if critical_count >= 3 or credential_count >= 2:
            risk = "CRITICAL"
        elif critical_count >= 1 or credential_count >= 1:
            risk = "HIGH"
        elif len(findings) >= 5:
            risk = "MEDIUM"
        else:
            risk = "LOW"
        
        return {
            "risk_level": risk,
            "total_findings": len(findings),
            "critical_findings": critical_count,
            "credentials_exposed": credential_count,
            "categories": categories,
            "top_recommendation": findings[0].recommendation if findings else None
        }
