import os
import re
import shutil
import tempfile
import gradio as gr
import plotly.graph_objects as go
from collections import Counter

from ingest import safe_extract_zip, ExtractionLimitsExceeded
from extractors.common import detect_and_parse
from theme import get_theme, DARK_CSS, FORCE_DARK_JS
from supervisors.base import reset_llm_state, is_llm_online
from supervisors import injection_sup, pii_sup, dark_sup, hallucination_sup, agentic_sup, multimodal_sup
from supervisors.chief import generate_chief_summary
from extractors.pdf_extractor import check_pdf_safety
from extractors.office import parse_office_safely
from extractors.images import parse_image_safely
from extractors.text_csv import parse_text_csv

from detectors.injection import detect_prompt_injection
from detectors.pii import detect_pii
from detectors.secrets import detect_secrets
from detectors.anomalies import detect_anomalies
from detectors.dark import detect_dark_patterns
from detectors.agentic import detect_agentic_risks
from detectors.output import detect_output_risks
from detectors.hallucination import detect_hallucinations
from detectors.memorization import detect_memorization
from detectors.recommendation_trust import detect_recommendation_trust
from detectors.multimodal_risk import detect_multimodal_risk
from detectors.context_filter import apply_suppression

from scoring import compute_overall_score
from report import generate_json_report, generate_pdf_report
from model import ProvenanceLocator, Finding, Severity

TEMP_DIR = os.environ.get("GRADIO_TEMP_DIR", tempfile.gettempdir())

# Human-readable name + "why it matters" per finding ID
_FINDING_META: dict[str, tuple[str, str]] = {
    # Prompt Injection
    "INJ_OVERRIDE":       ("Override Attempt",        "A command telling the AI to ignore its safety instructions."),
    "INJ_JAILBREAK":      ("Jailbreak Template",      "A known jailbreak pattern (e.g. DAN, AIM) to bypass AI alignment."),
    "INJ_LEAK":           ("System Prompt Leak",      "Attempt to extract hidden system instructions from the AI."),
    "INJ_ROLEPLAY":       ("Role-Play Hijack",         "Using a persona or role-play to bypass AI restrictions."),
    "INJ_DELIM":          ("Delimiter Confusion",      "Special tokens injected to confuse instruction boundaries."),
    "INJ_ENC_INJECTION":  ("Encoded Injection",        "Base64/encoded text that decodes to a prompt injection command."),
    "INJ_ENC_BLOCK":      ("Encoded Block",            "Suspicious encoded content found in the conversation."),
    # PII / Privacy
    "PII_EMAIL":          ("Email Address",            "Personal email address found — GDPR/CCPA regulated data."),
    "PII_PHONE":          ("Phone Number",             "Phone number found — could identify an individual."),
    "PII_SSN":            ("Social Security Number",   "SSN found — very high identity theft risk."),
    "PII_CC":             ("Credit Card Number",       "Credit card number found — financial fraud risk."),
    "PII_IBAN":           ("IBAN / Bank Account",      "Bank account number found."),
    "PII_PASSPORT":       ("Passport Number",          "Passport number found — identity document exposure."),
    "PII_DL":             ("Driver's License",         "Driver's license number found."),
    "PII_IP":             ("IP Address",               "IP address found — may reveal network location."),
    "PII_CRYPTO_BTC":     ("Bitcoin Wallet",           "Bitcoin wallet address found — financial data."),
    "PII_CRYPTO_ETH":     ("Ethereum Wallet",          "Ethereum wallet address found — financial data."),
    "PII_DOB":            ("Date of Birth",            "Date of birth found — used in identity theft."),
    "PII_TC_KIMLIK":      ("Turkish National ID",       "TC Kimlik No found — highly sensitive ID under Turkish KVKK law."),
    "PII_PHONE_TR":       ("Turkish Phone Number",      "Turkish mobile number found — personal data under KVKK."),
    "PII_IBAN_TR":        ("Turkish IBAN",              "Turkish bank account number — financial data under KVKK."),
    "PII_UK_NIN":         ("UK National Insurance No.", "UK NIN found — government ID under UK GDPR."),
    "PII_STEUER_ID":      ("German Steuer-ID",          "German tax ID found — sensitive PII under DSGVO."),
    "PII_PHONE_DE":       ("German Phone Number",       "German phone number — personal data under DSGVO."),
    "PII_IBAN_DE":        ("German IBAN",               "German bank account number — financial data under DSGVO."),
    # Secrets / Credentials
    "SEC_AWS":            ("AWS Credential",           "AWS access key found — rotate immediately to prevent cloud abuse."),
    "SEC_AWS_01":         ("AWS Credential",           "AWS access key found — rotate immediately to prevent cloud abuse."),
    "SEC_GH":             ("GitHub Token",             "GitHub token found — revoke to prevent unauthorized repo access."),
    "SEC_STRIPE":         ("Stripe API Key",           "Stripe key found — revoke to prevent unauthorized charges."),
    "SEC_OPENAI":         ("OpenAI API Key",           "OpenAI key found — revoke now to prevent billed API abuse."),
    "SEC_OAI_01":         ("OpenAI API Key",           "OpenAI key found — revoke now to prevent billed API abuse."),
    "SEC_GENERIC_KEY":    ("Generic API Key",          "Looks like an API key — verify and rotate if real."),
    "SEC_PASSWORD":       ("Password / Secret",        "Plaintext password found — change it and audit access logs."),
    "SEC_PWD_01":         ("Password / Secret",        "Plaintext password assignment found — never hardcode credentials."),
    "SEC_PRIVATE_KEY":    ("Private Key",              "Cryptographic private key found — very sensitive, rotate immediately."),
    "SEC_JWT_01":         ("JWT Token",                "JSON Web Token found — if long-lived, revoke and reissue."),
    # Dark Patterns
    "DARK_AFF":           ("Affiliate Link",           "AI inserted a tracking/affiliate URL without disclosing it."),
    "DARK_URG":           ("Artificial Urgency",       "AI used fake scarcity or deadline language to pressure a decision."),
    "DARK_SYC":           ("Sycophancy",               "AI agreed excessively — may shift positions to please rather than be accurate."),
    "DARK_SNEAK":         ("Sneaky Recommendation",    "AI inserted an unsolicited product/service recommendation."),
    "DARK_RET":           ("Retention Language",       "AI used language designed to create dependency and keep you coming back."),
    "DARK_ANTHRO":        ("Emotional Manipulation",   "AI falsely claimed human emotions (e.g. 'I'll miss you') to create false intimacy."),
    "DARK_BRAND":         ("Brand Bias",               "AI promoted a specific brand without being asked — possible commercial bias."),
    "DARK_PHISH":         ("Phishing Language",        "AI used wording that mimics phishing to trigger urgency or fear."),
    # Hallucination
    "HAL_CITE":           ("Fabricated Citation",      "AI cited a study or paper that may not exist — verify before using."),
    "HAL_AUTHORITY":      ("Vague Authority Claim",    "AI said 'studies show' without naming a source — unverifiable claim."),
    "HAL_STAT":           ("Unsourced Statistic",      "AI stated a number with no citation — may be fabricated."),
    "HAL_REALTIME":       ("Real-Time Knowledge Claim","AI claimed knowledge of recent events it cannot have — likely hallucination."),
    "HAL_ABSOLUTE":       ("Overconfident Claim",      "AI stated something as absolute fact — verify independently."),
    # Agentic (actual detector IDs)
    "ASI_01":             ("Agent Goal Hijack",        "Injected instruction detected in agent tool arguments — agent may be hijacked."),
    "ASI_03":             ("Credential in Tool Args",  "API key or secret passed to an agent tool — verify it's not being exfiltrated."),
    "ASI_04":             ("Dangerous Shell Command",  "Agent submitted a destructive or untrusted shell command to a tool."),
    # Legacy agentic IDs
    "ASI_EXEC":           ("Code Execution Risk",      "Agent requested or performed arbitrary code execution."),
    "ASI_EXFIL":          ("Data Exfiltration Risk",   "Agent may have sent data to an external endpoint."),
    "ASI_PROMPT_INJ":     ("Agentic Prompt Injection", "Injected instruction found inside agent tool output."),
    # Anomalies (actual detector IDs)
    "ANOM_LEN_01":        ("Unusual Message Length",   "Message is far longer than average — possible context-stuffing or exfiltration payload."),
    "ANOM_ENT_01":        ("High-Entropy Content",     "Message has unusually high randomness — may contain encoded or encrypted data."),
    # Legacy anomaly IDs
    "ANOM_ENTROPY":       ("High-Entropy Text",        "Unusually random text — may be encoded or obfuscated."),
    "ANOM_LANG_SWITCH":   ("Language Switch",          "Sudden language change — may attempt filter bypass."),
    "ANOM_RAPID":         ("Rapid Escalation",         "Conversation escalated unusually fast to sensitive topics."),
    # Memorization
    "MEM_VERBATIM":       ("Verbatim Memorization",    "AI repeated identical phrases across multiple conversations — possible training data memorization."),
    "MEM_FINGERPRINT":    ("Repeated N-gram Pattern",  "Same text fragment appears across many conversations — low-confidence memorization signal."),
    # Output / Files
    "OUT_CODE":           ("Dangerous Code Generated", "AI generated a shell command that could be destructive if executed."),
    "OUT_HATE":           ("Harmful Output — Hate",    "AI produced content that may contain hate speech."),
    "OUT_VIOLENCE":       ("Harmful Output — Violence","AI produced content describing violence."),
    "OUT_ADULT":          ("Harmful Output — Adult",   "AI produced adult/explicit content."),
    "FILE_MACRO":         ("Macro in File",            "Office macro found — potential code execution vector."),
    "FILE_EXIF":          ("EXIF / Metadata",          "File metadata may contain sensitive location or device info."),
    # Recommendation Trust
    "REC_UNTRUSTED_URL":  ("Untrusted URL Recommended","AI recommended a website with no established reputation."),
    "REC_TRACKING_URL":   ("Tracking Link in AI Reply","AI included affiliate/tracking parameters in a recommended URL."),
    "REC_SUSPICIOUS_APP": ("Suspicious App Recommended","AI recommended an app with no established reputation."),
    # Multimodal
    "MM_POST_IMAGE_BEHAVIOR": ("Post-Image Behavior Shift","AI behavior changed after a user uploaded an image — possible image injection."),
    "MM_IMAGE_INJECTION": ("Image Injection Attempt",  "Uploaded image may contain embedded instructions targeting the AI."),
    "MM_DALLE_INJECTION": ("DALL-E Prompt Injection",  "AI-generated image prompt contains injection-like keywords."),
    "MM_EXIF_DATA":       ("Image Metadata Exposure",  "User-uploaded image may contain GPS or device metadata."),
    # Test card (low severity)
    "PII_CC_TEST":        ("Test Credit Card",         "Known test/demo card number — not a real card, no action needed."),
}

# Sender-specific overrides: (finding_id, sender_category) → "why" text
# sender_category: "user" | "assistant" | "system" | "tool"
_WHY_BY_SENDER: dict[tuple[str, str], str] = {
    # Injection: user attacking the AI
    ("INJ_OVERRIDE",  "user"):      "User is actively trying to override AI safety instructions — a real-time attack.",
    ("INJ_JAILBREAK", "user"):      "User sent a known jailbreak template to bypass AI alignment — a real-time attack.",
    ("INJ_LEAK",      "user"):      "User tried to extract the hidden system prompt — a prompt extraction attempt.",
    ("INJ_ROLEPLAY",  "user"):      "User used a persona to try to bypass AI restrictions.",
    ("INJ_DELIM",     "user"):      "User injected special tokens to confuse instruction boundaries.",
    # Injection: from a document/tool (indirect injection)
    ("INJ_OVERRIDE",  "tool"):      "External document/tool returned injection instructions — indirect prompt injection attack.",
    ("INJ_OVERRIDE",  "system"):    "System prompt contains override language — this deployment may be configured maliciously.",
    # Credentials: user vs AI
    ("SEC_AWS_01",    "user"):      "User accidentally shared AWS credentials in chat — rotate immediately and check CloudTrail.",
    ("SEC_AWS_01",    "assistant"): "AI generated or leaked AWS credentials — rotate immediately.",
    ("SEC_OAI_01",    "user"):      "User accidentally shared an OpenAI API key — revoke now to prevent abuse.",
    ("SEC_OAI_01",    "assistant"): "AI generated or leaked an OpenAI API key — revoke now.",
    ("SEC_PWD_01",    "user"):      "User pasted a password into chat — this is stored in chat history, change it.",
    ("SEC_PWD_01",    "assistant"): "AI generated a hardcoded password — never store credentials in code or prompts.",
    ("SEC_JWT_01",    "user"):      "User shared a JWT token in chat — if unexpired, it may still grant access.",
    ("SEC_JWT_01",    "assistant"): "AI generated a JWT token — verify it's not a real long-lived token.",
    # PII: user sharing vs AI generating
    ("PII_SSN",       "user"):      "User shared their SSN with the AI — this is now in chat history, a data protection risk.",
    ("PII_SSN",       "assistant"): "AI generated a Social Security Number — this should never appear in AI output.",
    ("PII_CC",        "user"):      "User shared a credit card number — immediately at risk of fraud if stored or logged.",
    ("PII_CC",        "assistant"): "AI generated a credit card number — validate it's not a real card.",
    ("PII_IBAN_TR",   "user"):      "User shared a Turkish IBAN — financial data regulated under KVKK.",
    ("PII_TC_KIMLIK", "user"):      "User shared their Turkish National ID — highly sensitive under KVKK law.",
    # Agentic
    ("ASI_01",        "tool"):      "Agent tool output contained injection instructions — agent may have been hijacked by external data.",
    ("ASI_03",        "tool"):      "API credentials detected in agent tool arguments — verify the agent is not exfiltrating keys.",
    ("ASI_04",        "tool"):      "Agent submitted a destructive shell command — block at the tool perimeter immediately.",
    # Dark patterns: always from assistant
    ("DARK_ANTHRO",   "assistant"): "AI falsely claimed human emotions to create dependency — a manipulation tactic.",
    ("DARK_AFF",      "assistant"): "AI inserted a tracking URL without disclosure — possible undisclosed affiliate monetization.",
    ("DARK_PHISH",    "assistant"): "AI used phishing-style language — users may be tricked into unsafe actions.",
    # Output risks: always from assistant
    ("OUT_CODE",      "assistant"): "AI generated a destructive or untrusted shell command — do not run without careful review.",
}

_SENDER_LABELS = {
    "user":      "You (user)",
    "human":     "You (user)",
    "assistant": "AI response",
    "system":    "System prompt",
    "tool":      "AI Tool",
}

# Friendly names for ChatGPT tool authors (role stored as "tool:{name}")
_TOOL_NAME_LABELS = {
    "browser":       "AI Tool (Web Browser)",
    "python":        "AI Tool (Code Interpreter)",
    "dalle.text2im": "AI Tool (DALL-E)",
    "dalle":         "AI Tool (DALL-E)",
    "code_interpreter": "AI Tool (Code Interpreter)",
    "web_search":    "AI Tool (Web Search)",
    "file_search":   "AI Tool (File Search)",
    "retrieval":     "AI Tool (Retrieval)",
}


def _get_sender_label(role: str) -> str:
    """Resolve a role string (including 'tool:name' variants) to a human label."""
    if role.startswith("tool:"):
        tool_name = role[5:].strip()
        return _TOOL_NAME_LABELS.get(tool_name, f"AI Tool ({tool_name})")
    return _SENDER_LABELS.get(role.lower(), role or "unknown")


def _get_why(finding_id: str, role: str) -> str:
    """Return context-aware 'Why It's a Risk' text for a finding.

    Fix 6: Sender-aware explanations. Falls back to generic meta, then ID title.
    """
    role_lc = (role or "").lower()
    # Normalize role to category key for lookup
    if role_lc in ("user", "human"):
        cat = "user"
    elif role_lc == "assistant":
        cat = "assistant"
    elif role_lc == "system":
        cat = "system"
    else:
        cat = "tool"  # tool:* variants

    # 1. Exact sender-specific override
    key = (finding_id, cat)
    if key in _WHY_BY_SENDER:
        return _WHY_BY_SENDER[key]

    # 2. Generic meta entry
    meta = _FINDING_META.get(finding_id)
    if meta:
        return meta[1]

    # 3. Prefix-based fallback (covers SEC_*, PII_*, etc.)
    for prefix, (name, why) in _FINDING_META.items():
        if finding_id.startswith(prefix.rstrip("_")):
            return why

    # 4. Last resort
    return "Security detector triggered — review the evidence above."


def _deduplicate_findings(findings: list) -> list:
    """
    Remove exact-duplicate findings (same id + evidence + location).
    Keeps the first occurrence; logs how many were dropped.
    """
    seen: set = set()
    deduped = []
    for f in findings:
        loc = f.provenance
        key = (
            f.id,
            f.evidence[:80],                       # evidence prefix
            loc.conversation_id or "",
            loc.message_index or 0,
        )
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    dropped = len(findings) - len(deduped)
    if dropped:
        print(f"[DEDUP] Removed {dropped} duplicate findings ({len(deduped)} remain)")
    return deduped


_SEV_COLORS = {
    "Critical": "#d62728",
    "High":     "#ff7f0e",
    "Medium":   "#f0c040",
    "Low":      "#1f77b4",
    "Info":     "#aec7e8",
}


def _build_timeline(findings: list, msgs: list) -> go.Figure:
    """
    Build a Plotly scatter timeline of threats.
    X-axis: human-readable date string (Fix 7) when timestamps are available,
            otherwise sequential message index.
    Y-axis: finding category.
    Color: severity.
    """
    import datetime as _dt

    has_timestamps = any(m.time for m in msgs)

    # Build fast lookup: (conversation_id, message_index) → x value
    # When timestamps exist: use ISO datetime string for Plotly date axis
    # When no timestamps: use sequential integer index
    msg_map: dict[tuple, object] = {}
    global_idx = 0
    for msg in msgs:
        key = (msg.conversation_id, msg.index)
        if has_timestamps and msg.time:
            # Convert Unix timestamp → Python datetime for Plotly
            try:
                ts = float(msg.time)
                dt = _dt.datetime.utcfromtimestamp(ts)
                msg_map[key] = dt
            except (ValueError, OSError, OverflowError):
                msg_map[key] = global_idx
        else:
            msg_map[key] = global_idx
        global_idx += 1

    x_all, y_all, color_all, text_all = [], [], [], []

    for f in findings:
        loc = f.provenance
        key = (loc.conversation_id, loc.message_index)
        x_val = msg_map.get(key, global_idx)
        y_val = f.category
        color = _SEV_COLORS.get(f.severity.value, "#aec7e8")
        # Human-readable x in tooltip
        if isinstance(x_val, _dt.datetime):
            x_str = x_val.strftime("%b %Y, msg %d")
        else:
            x_str = f"Msg #{int(x_val) + 1}"
        tip = f"[{f.severity.value.upper()}] {f.id}<br>{x_str}<br>{f.evidence[:100]}"
        x_all.append(x_val)
        y_all.append(y_val)
        color_all.append(color)
        text_all.append(tip)

    if not x_all:
        fig = go.Figure()
        fig.add_annotation(
            text="No security findings detected - your conversations look clean!",
            showarrow=False,
            xref="paper", yref="paper", x=0.5, y=0.5,
            font=dict(size=18, color="#10B981"),
        )
        fig.update_layout(
            title="Threat Timeline",
            template="plotly_dark",
            paper_bgcolor="#1A1D27",
            plot_bgcolor="#1A1D27",
            height=400,
        )
        return fig

    # One trace per severity so we get a clean legend
    fig = go.Figure()
    for sev_label, color in _SEV_COLORS.items():
        mask = [i for i, c in enumerate(color_all) if c == color]
        if not mask:
            continue
        fig.add_trace(go.Scatter(
            x=[x_all[i] for i in mask],
            y=[y_all[i] for i in mask],
            mode="markers",
            marker=dict(
                color=color,
                size=14,
                opacity=0.9,
                line=dict(width=2, color="#1A1D27"),
                symbol="circle",
            ),
            name=f"{sev_label} ({len(mask)})",
            text=[text_all[i] for i in mask],
            hoverinfo="text",
            hoverlabel=dict(bgcolor=color, font_size=12),
        ))

    if has_timestamps:
        x_label = "Date"
        xaxis_cfg = dict(
            title=dict(text=x_label, font=dict(color="#94A3B8")),
            type="date",
            tickformat="%b %Y",
            dtick="M1",
            gridcolor="#2A2D3A",
            tickfont=dict(color="#94A3B8"),
        )
    else:
        x_label = "Message Index"
        xaxis_cfg = dict(
            title=dict(text=x_label, font=dict(color="#94A3B8")),
            gridcolor="#2A2D3A",
            tickfont=dict(color="#94A3B8"),
        )

    fig.update_layout(
        title=dict(
            text=f"Threat Timeline — {len(x_all)} Findings Detected",
            font=dict(size=18, color="#E2E8F0"),
        ),
        xaxis=xaxis_cfg,
        yaxis=dict(
            title=dict(text="Finding Category", font=dict(color="#94A3B8")),
            gridcolor="#2A2D3A",
            tickfont=dict(color="#94A3B8"),
        ),
        legend=dict(
            title=dict(text="Severity", font=dict(color="#94A3B8")),
            bgcolor="rgba(26,29,39,0.8)",
            font=dict(color="#E2E8F0"),
        ),
        template="plotly_dark",
        paper_bgcolor="#1A1D27",
        plot_bgcolor="#1A1D27",
        height=520,
        margin=dict(l=30, r=30, t=60, b=40),
        hovermode="closest",
    )
    return fig


def _generate_custom_instructions(msgs: list, convs: list, export_format: str = "chatgpt") -> str:
    """
    Deep analysis of user's AI conversation history (potentially 3+ years).
    Generates actionable insights and personalized custom instructions.

    Args:
        msgs: List of Message objects
        convs: List of Conversation objects
        export_format: "chatgpt" or "claude" - determines which instructions appear first

    Analyzes:
    - Expertise domains and skill progression
    - Task delegation patterns (what you use AI for)
    - Communication style evolution
    - Time-based usage patterns
    - Quality of AI interactions (when AI helped vs didn't)
    """
    import datetime as _dt

    user_msgs = [m for m in msgs if m.role in ("user", "human")]
    ai_msgs = [m for m in msgs if m.role == "assistant"]
    if not user_msgs:
        return "No user messages found — upload a ChatGPT or Claude export to generate instructions."

    total_user = len(user_msgs)
    total_ai = len(ai_msgs)

    # =========================================================================
    # COMPREHENSIVE STOP WORDS
    # =========================================================================
    _STOPS = {
        "the","a","an","is","are","was","were","i","my","me","you","your","it","its",
        "this","that","what","how","why","when","where","who","can","could","would","should",
        "will","do","does","did","have","has","had","be","been","being","and","or","but",
        "in","on","at","for","to","of","with","by","from","up","about","than","then","so",
        "if","as","not","no","yes","please","help","need","want","get","make","use","like",
        "just","also","more","some","very","any","all","here","there","into","they","them",
        "their","we","our","us","he","she","him","her","which","tell","show","give","look",
        "think","know","see","way","thing","things","time","work","used","using",
        "try","trying","write","read","find","take","add","create","change","something",
        "name","data","text","word","file","code","line","type","list","item","step","part",
        "point","area","case","form","note","test","page","user","strong","experience","team",
        "good","best","new","old","big","small","same","different","other","first","second",
        "last","next","right","left","information","question","answer","example","problem",
        "solution","result","number","value","function","variable","output","input","system",
        "process","let","got","set","put","run","go","say","back","one","two","three",
        "async","await","null","true","false","void","return","class","static","public",
        "private","protected","override","interface","enum","struct","import","export",
        "const","module","require","include","method","property","parameter","argument",
        # Turkish
        "bir","bu","ve","ile","için","olan","olarak","daha","çok","gibi","bunu","şu",
        "da","de","ki","mi","mı","ya","ama","hem","veya","ne","var","yok","ben","sen",
        # German
        "ich","ist","bin","haben","sein","dass","nicht","auch","aber","oder","eine",
        "und","der","die","das","ein","für","mit","auf","von","zu","den","dem",
    }

    _CODE_BLOCK_RE = re.compile(r"```[\s\S]*?```|`[^`\n]{2,}`", re.MULTILINE)
    _CAMEL_RE = re.compile(r"[a-z][A-Z]")

    def _strip_code(text: str) -> str:
        return _CODE_BLOCK_RE.sub(" ", text)

    def _tokens(text: str) -> list:
        text = _strip_code(text)
        result = []
        for w in re.findall(r"\b[a-zA-ZğüşıöçĞÜŞİÖÇäöüß]{3,}\b", text):
            if _CAMEL_RE.search(w) or (w.isupper() and len(w) <= 6):
                continue
            result.append(w.lower())
        return [w for w in result if w not in _STOPS]

    # =========================================================================
    # 1. DOMAIN EXPERTISE DETECTION
    # =========================================================================
    _DOMAINS = {
        # Programming
        "python": ("Python", "programming"),
        "javascript": ("JavaScript", "programming"),
        "typescript": ("TypeScript", "programming"),
        "react": ("React", "programming"),
        "vue": ("Vue.js", "programming"),
        "angular": ("Angular", "programming"),
        "nodejs": ("Node.js", "programming"),
        "django": ("Django", "programming"),
        "fastapi": ("FastAPI", "programming"),
        "flask": ("Flask", "programming"),
        "csharp": ("C#/.NET", "programming"),
        "java": ("Java", "programming"),
        "kotlin": ("Kotlin", "programming"),
        "swift": ("Swift/iOS", "programming"),
        "rust": ("Rust", "programming"),
        "golang": ("Go", "programming"),
        # Data & AI
        "machine learning": ("Machine Learning", "data_ai"),
        "deep learning": ("Deep Learning", "data_ai"),
        "neural network": ("Neural Networks", "data_ai"),
        "tensorflow": ("TensorFlow", "data_ai"),
        "pytorch": ("PyTorch", "data_ai"),
        "pandas": ("Pandas", "data_ai"),
        "numpy": ("NumPy", "data_ai"),
        "data analysis": ("Data Analysis", "data_ai"),
        "data science": ("Data Science", "data_ai"),
        "sql": ("SQL/Databases", "data_ai"),
        "postgresql": ("PostgreSQL", "data_ai"),
        "mongodb": ("MongoDB", "data_ai"),
        # DevOps & Cloud
        "docker": ("Docker", "devops"),
        "kubernetes": ("Kubernetes", "devops"),
        "aws": ("AWS", "devops"),
        "azure": ("Azure", "devops"),
        "gcp": ("Google Cloud", "devops"),
        "terraform": ("Terraform", "devops"),
        "cicd": ("CI/CD", "devops"),
        "github actions": ("GitHub Actions", "devops"),
        # Business & Creative
        "marketing": ("Marketing", "business"),
        "seo": ("SEO", "business"),
        "copywriting": ("Copywriting", "creative"),
        "writing": ("Writing", "creative"),
        "content": ("Content Creation", "creative"),
        "design": ("Design", "creative"),
        "ux": ("UX Design", "creative"),
        # Professional
        "legal": ("Legal/Law", "professional"),
        "finance": ("Finance", "professional"),
        "accounting": ("Accounting", "professional"),
        "research": ("Research", "professional"),
        "academic": ("Academic Writing", "professional"),
    }

    domain_counts: Counter = Counter()
    category_counts: Counter = Counter()

    for m in user_msgs:
        content_lower = m.content.lower()
        for kw, (label, cat) in _DOMAINS.items():
            if kw in content_lower:
                domain_counts[label] += 1
                category_counts[cat] += 1

    # =========================================================================
    # 2. TASK DELEGATION PATTERNS (what you use AI for)
    # =========================================================================
    task_patterns = {
        "Code Writing": [r"(?i)write\s+(a\s+)?(code|function|script|program|class)", r"(?i)implement\s+", r"(?i)create\s+a\s+\w+\s+that"],
        "Code Debugging": [r"(?i)(fix|debug|error|bug|issue|problem|not\s+working|doesn.t\s+work)", r"(?i)why\s+(is|does|doesn)"],
        "Code Review": [r"(?i)review\s+(this|my)\s+code", r"(?i)is\s+this\s+(code|approach)\s+(good|correct|efficient)"],
        "Explanations": [r"(?i)(explain|what\s+is|how\s+does|why\s+does|tell\s+me\s+about)", r"(?i)difference\s+between"],
        "Writing & Editing": [r"(?i)(write|draft|compose)\s+(a\s+)?(email|message|letter|article|post|essay)", r"(?i)(proofread|edit|rewrite|improve)"],
        "Brainstorming": [r"(?i)(ideas?\s+for|brainstorm|suggest|help\s+me\s+think|what\s+should\s+i)", r"(?i)give\s+me\s+(\d+|some)\s+"],
        "Research": [r"(?i)(research|find\s+(out|information)|what\s+are\s+the\s+best)", r"(?i)(compare|pros\s+and\s+cons)"],
        "Translation": [r"(?i)translate\s+(this|to|into|from)", r"(?i)in\s+(english|spanish|french|german|turkish)$"],
        "Summarization": [r"(?i)(summarize|summary|tldr|key\s+points|main\s+points)"],
        "Learning": [r"(?i)(teach|learn|tutorial|how\s+to|step\s+by\s+step)", r"(?i)for\s+beginners"],
    }

    task_counts: Counter = Counter()
    for m in user_msgs:
        for task, patterns in task_patterns.items():
            for pat in patterns:
                if re.search(pat, m.content):
                    task_counts[task] += 1
                    break

    # =========================================================================
    # 3. COMMUNICATION STYLE ANALYSIS
    # =========================================================================
    avg_len = sum(len(m.content) for m in user_msgs) / max(total_user, 1)
    uses_code = sum(1 for m in user_msgs if "```" in m.content)
    uses_questions = sum(1 for m in user_msgs if m.content.strip().endswith("?"))
    uses_lists = sum(1 for m in user_msgs if re.search(r"\n\s*[-*\d]", m.content))
    uses_context = sum(1 for m in user_msgs if len(m.content) > 500)
    direct_commands = sum(1 for m in user_msgs if re.match(r"^[A-Z][a-z]+\s", m.content.strip()))

    # Language detection
    non_ascii = sum(1 for m in user_msgs for ch in m.content if ord(ch) > 127)
    total_chars = sum(len(m.content) for m in user_msgs) or 1
    has_turkish = sum(1 for m in user_msgs if any(c in m.content for c in "çğıöşüÇĞİÖŞÜ"))
    has_german = sum(1 for m in user_msgs if any(c in m.content for c in "äöüßÄÖÜ"))

    primary_lang = "English"
    if has_turkish > total_user * 0.1:
        primary_lang = "Turkish"
    elif has_german > total_user * 0.1:
        primary_lang = "German"
    elif non_ascii / total_chars > 0.1:
        primary_lang = "Multi-lingual"

    # =========================================================================
    # 4. TIME-BASED ANALYSIS (if timestamps available)
    # =========================================================================
    time_insights = []
    timestamps = [m.time for m in msgs if m.time]
    if timestamps:
        try:
            dates = [_dt.datetime.fromtimestamp(float(t)) for t in timestamps if t]
            if len(dates) >= 2:
                first_date = min(dates)
                last_date = max(dates)
                span_days = (last_date - first_date).days
                if span_days > 365:
                    years = span_days / 365
                    time_insights.append(f"**{years:.1f} years** of AI conversation history")
                elif span_days > 30:
                    time_insights.append(f"**{span_days // 30} months** of AI conversation history")
        except (ValueError, OSError):
            pass

    # =========================================================================
    # 5. BUILD TOPIC NGRAMS (as before, but refined)
    # =========================================================================
    bigram_counts: Counter = Counter()
    for m in user_msgs:
        toks = _tokens(m.content)
        for i in range(len(toks) - 1):
            w1, w2 = toks[i], toks[i + 1]
            if len(w1) >= 4 and len(w2) >= 4:
                bigram_counts[f"{w1} {w2}"] += 1

    top_bigrams = [phrase for phrase, _ in bigram_counts.most_common(8) if bigram_counts[phrase] >= 3]

    # =========================================================================
    # 6. GENERATE COMPREHENSIVE OUTPUT
    # =========================================================================
    lines = []

    # Header
    lines.append("# Your AI Usage Profile & Custom Instructions")
    lines.append(f"*Deep analysis of {len(convs):,} conversations and {total_user:,} messages*")
    if time_insights:
        lines.append(f"*{time_insights[0]}*")
    lines.append("")
    lines.append("---")
    lines.append("")

    # SECTION 1: Your AI Profile
    lines.append("## Your AI Usage Profile")
    lines.append("")

    # Top domains
    top_domains = domain_counts.most_common(6)
    if top_domains:
        lines.append("### Expertise Areas")
        for domain, count in top_domains:
            pct = count / total_user * 100
            bar = "█" * min(int(pct / 2), 20)
            lines.append(f"- **{domain}**: {bar} ({count} mentions, {pct:.1f}%)")
        lines.append("")

    # Task delegation
    top_tasks = task_counts.most_common(5)
    if top_tasks:
        lines.append("### How You Use AI")
        for task, count in top_tasks:
            pct = count / total_user * 100
            lines.append(f"- **{task}**: {count} times ({pct:.1f}% of conversations)")
        lines.append("")

    # Communication style
    lines.append("### Your Communication Style")
    style_traits = []
    if avg_len > 400:
        style_traits.append("**Detailed communicator** — you provide thorough context")
    elif avg_len < 100:
        style_traits.append("**Direct communicator** — you prefer concise requests")
    else:
        style_traits.append("**Balanced communicator** — clear and moderately detailed")

    if uses_code > total_user * 0.25:
        style_traits.append("**Technical user** — frequently shares code")
    if uses_questions > total_user * 0.4:
        style_traits.append("**Curious learner** — asks many questions")
    if direct_commands > total_user * 0.3:
        style_traits.append("**Action-oriented** — uses direct commands")

    for trait in style_traits:
        lines.append(f"- {trait}")
    lines.append(f"- **Primary language**: {primary_lang}")
    lines.append("")

    # Frequent topics (bigrams)
    if top_bigrams:
        lines.append("### Recurring Topics")
        lines.append(", ".join(top_bigrams[:6]))
        lines.append("")

    lines.append("---")
    lines.append("")

    # Build profile parts (shared between ChatGPT and Claude)
    profile_parts = []
    if top_domains:
        domain_list = ", ".join([d for d, _ in top_domains[:4]])
        profile_parts.append(f"I work primarily with {domain_list}.")

    if "programming" in category_counts and category_counts["programming"] > 10:
        profile_parts.append("I'm a software developer.")
    if "data_ai" in category_counts and category_counts["data_ai"] > 10:
        profile_parts.append("I work with data and machine learning.")

    if top_tasks:
        main_task = top_tasks[0][0]
        profile_parts.append(f"I mostly use AI for {main_task.lower()}.")

    if style_traits:
        if "Direct communicator" in str(style_traits):
            profile_parts.append("I prefer concise, direct answers.")
        elif "Detailed communicator" in str(style_traits):
            profile_parts.append("I appreciate thorough explanations when relevant.")

    if primary_lang != "English":
        profile_parts.append(f"I often communicate in {primary_lang}.")

    profile_text = " ".join(profile_parts) if profile_parts else "I use AI for various tasks including research, coding, and writing."

    # Build response rules
    response_rules = [
        "Be direct and accurate. No filler phrases like 'Certainly!' or 'Great question!'.",
    ]
    if uses_code > total_user * 0.2:
        response_rules.append("Always use fenced code blocks with the language specified.")
    if task_counts.get("Code Debugging", 0) > 5:
        response_rules.append("When debugging, explain the root cause first, then the fix.")
    if task_counts.get("Explanations", 0) > 10:
        response_rules.append("For explanations, use analogies and concrete examples.")
    if avg_len < 100:
        response_rules.append("Keep responses brief unless I ask for detail.")
    if uses_lists > total_user * 0.15:
        response_rules.append("Use bullet points for multi-step processes.")
    response_rules.append("If uncertain, say so clearly instead of guessing.")
    response_rules.append("Cite sources for factual claims when possible.")

    # Build Claude system prompt
    claude_prompt = []
    if top_domains:
        domain_list = ", ".join([d for d, _ in top_domains[:4]])
        claude_prompt.append(f"You are assisting a user who works with {domain_list}.")
    else:
        claude_prompt.append("You are a helpful assistant.")
    if "programming" in category_counts:
        claude_prompt.append("The user frequently works with code — use fenced code blocks.")
    if avg_len < 100:
        claude_prompt.append("The user prefers concise responses. Be direct.")
    if primary_lang != "English":
        claude_prompt.append(f"The user sometimes communicates in {primary_lang}. Respond in the same language when they do.")
    claude_prompt.append("Be accurate. If uncertain, acknowledge it rather than hallucinate.")

    # =========================================================================
    # ORDER SECTIONS BASED ON EXPORT FORMAT
    # =========================================================================
    if export_format == "claude":
        # Claude export: Show Claude instructions FIRST
        lines.append("## Claude Custom Instructions")
        lines.append("")
        lines.append("### Paste into Claude's System Prompt or Project Instructions")
        lines.append("")
        lines.append("```")
        lines.append(" ".join(claude_prompt))
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## ChatGPT Custom Instructions (if you also use ChatGPT)")
        lines.append("")
    else:
        # ChatGPT export: Show ChatGPT instructions FIRST
        lines.append("## ChatGPT Custom Instructions")
        lines.append("")

    lines.append("### Paste into 'What would you like ChatGPT to know about you?'")
    lines.append("")
    lines.append("```")
    lines.append(profile_text)
    lines.append("```")
    lines.append("")

    lines.append("### Paste into 'How would you like ChatGPT to respond?'")
    lines.append("")
    lines.append("```")
    for rule in response_rules:
        lines.append(f"- {rule}")
    lines.append("```")
    lines.append("")

    if export_format != "claude":
        # ChatGPT export: Show Claude section SECOND
        lines.append("---")
        lines.append("")
        lines.append("## Claude System Prompt (if you also use Claude)")
        lines.append("")
        lines.append("```")
        lines.append(" ".join(claude_prompt))
        lines.append("```")
        lines.append("")

    lines.append("---")
    lines.append("")

    # SECTION 4: Security Recommendations based on usage
    lines.append("## Security Recommendations for Your Usage Pattern")
    lines.append("")

    sec_recs = []
    if task_counts.get("Code Writing", 0) > 10:
        sec_recs.append("**Code from AI**: Always review AI-generated code before running. Check for hardcoded credentials or unsafe patterns.")
    if "AWS" in str(domain_counts) or "Azure" in str(domain_counts):
        sec_recs.append("**Cloud credentials**: Never paste API keys or secrets in chat. Use environment variables instead.")
    if task_counts.get("Writing & Editing", 0) > 5:
        sec_recs.append("**PII in writing tasks**: Avoid including real names, emails, or addresses when asking AI to edit documents.")
    if uses_code > total_user * 0.3:
        sec_recs.append("**Intellectual property**: Code you share with AI may be retained. Avoid sharing proprietary algorithms.")

    sec_recs.append("**Verification**: Always verify AI's factual claims, especially for legal, medical, or financial topics.")
    sec_recs.append("**Prompt injection awareness**: Be cautious pasting content from untrusted sources into AI — it could contain hidden instructions.")

    for rec in sec_recs:
        lines.append(f"- {rec}")
    lines.append("")

    lines.append("---")
    lines.append(f"*Generated by AI Security Analyzer 2026 — {len(convs):,} conversations, {total_user:,} messages*")

    return "\n".join(lines)


def wipe_session(session_id):
    if not session_id:
        return "No active session."
    target = os.path.join(TEMP_DIR, session_id)
    if os.path.exists(target):
        try:
            shutil.rmtree(target)
            return "Session data securely wiped from memory and disk."
        except Exception as e:
            return f"Error wiping session: {e}"
    return "Session data already cleared."


def analyze_file(upload, max_pages_ocr, enable_ocr):
    """
    Main analysis pipeline. Accepts both ChatGPT ZIP exports and Claude JSON exports.
    Returns tab content + download paths + session state.
    """
    _EMPTY_TIMELINE = go.Figure().update_layout(title="Upload a file to see the timeline")
    empty = ("", "Please upload a file.", [], [], [], [], [], [], [], _EMPTY_TIMELINE, "", None, None, None, "")

    if not upload:
        return empty

    # ---- Robust file path extraction (Gradio 5.x / 6.x compatibility) -----
    import zipfile as _zf

    # Gradio 6.x can pass FileData (.path), NamedString (.name), or a plain str.
    # NamedString is a str subclass so isinstance(upload, str) catches it.
    # Try every known attribute before falling back to str().
    candidates = []
    if hasattr(upload, "path") and upload.path:
        candidates.append(str(upload.path))
    if hasattr(upload, "name") and upload.name:
        candidates.append(str(upload.name))
    if isinstance(upload, str):
        candidates.append(upload)
    candidates.append(str(upload))

    file_path = next((c for c in candidates if c and os.path.isfile(c)), None)

    print(f"[DEBUG] upload type={type(upload).__name__!r}, candidates={candidates}, resolved={file_path!r}")

    if not file_path:
        return (
            f"Could not locate the uploaded file. "
            f"Tried: {candidates}. Please try uploading again.",
            "", [], [], [], [], [], [], [], _EMPTY_TIMELINE, "", None, None, None, "",
        )

    file_size = os.path.getsize(file_path)
    file_ext = os.path.splitext(file_path)[1].lower()

    # If Gradio strips the extension, probe by content
    is_zip_content = _zf.is_zipfile(file_path)
    if not file_ext and is_zip_content:
        file_ext = ".zip"
    elif not file_ext:
        file_ext = ".json"  # assume JSON if no extension and not ZIP

    print(f"[DEBUG] file_path={file_path!r}, size={file_size:,}, ext={file_ext!r}, is_zip={is_zip_content}")

    base_name = os.path.splitext(os.path.basename(file_path))[0] or "upload"
    session_id = base_name[:40].replace(" ", "_")
    out_dir = os.path.join(TEMP_DIR, session_id)
    os.makedirs(out_dir, exist_ok=True)

    findings: list[Finding] = []
    manifest = []
    export_format = "unknown"

    # ---- Step 1: Extract and parse ----------------------------------------
    try:
        if file_ext == ".zip" or is_zip_content:
            if not is_zip_content:
                return (
                    f"The file has a .zip extension but is not a valid ZIP archive "
                    f"(size: {file_size:,} bytes, path: {file_path}). "
                    "Please re-download your ChatGPT export. "
                    "If you already unzipped it, upload conversations.json directly.",
                    "", [], [], [], [], [], [], [], _EMPTY_TIMELINE, "", None, None, None, session_id,
                )
            # Pre-flight: open the ZIP to catch a corrupt central directory
            # before handing off to safe_extract_zip
            try:
                with _zf.ZipFile(file_path, "r") as _z:
                    _names = _z.namelist()
                    print(f"[DEBUG] ZIP entries ({len(_names)}): {_names[:8]}")
            except _zf.BadZipFile as e:
                return (
                    f"ZIP archive has a corrupt central directory: {e} "
                    f"(size: {file_size:,} bytes). "
                    "Please re-download your ChatGPT export and try again.",
                    "", [], [], [], [], [], [], [], _EMPTY_TIMELINE, "", None, None, None, session_id,
                )
            manifest = safe_extract_zip(file_path, out_dir)
            export_format, convs, msgs, traces = detect_and_parse(file_path, out_dir)
        elif file_ext == ".json":
            export_format, convs, msgs, traces = detect_and_parse(file_path)
        else:
            return (
                f"Unsupported file type '{file_ext}' (size: {file_size:,} bytes). "
                "Please upload a ChatGPT ZIP export or a Claude JSON export.",
                "", [], [], [], [], [], [], [], _EMPTY_TIMELINE, "", None, None, None, session_id,
            )

    except ExtractionLimitsExceeded as e:
        return ("", f"Extraction blocked: {e}", [], [], [], [], [], [], [], _EMPTY_TIMELINE, "", None, None, None, session_id)
    except ValueError as e:
        return ("", f"Format error: {e}", [], [], [], [], [], [], [], _EMPTY_TIMELINE, "", None, None, None, session_id)
    except Exception as e:
        return ("", f"Error reading file: {e}", [], [], [], [], [], [], [], _EMPTY_TIMELINE, "", None, None, None, session_id)

    # ---- Step 2: Run detectors on tool traces ----------------------------
    for trace in traces:
        t_loc = ProvenanceLocator(conversation_id="N/A", message_index=-1, role="tool", source_locator=trace.tool_name)
        findings.extend(detect_agentic_risks(trace, t_loc))
        t_text = f"Tool: {trace.tool_name}\nArgs: {trace.args}\nOuts: {trace.outputs}"
        findings.extend(detect_dark_patterns(t_text, t_loc))

    # Build a fast index for next-message lookup (multimodal behavior shift)
    _msg_by_idx: dict = {}
    for msg in msgs:
        _msg_by_idx[(msg.conversation_id, msg.index or 0)] = msg

    # ---- Step 3: Run text detectors on every message ---------------------
    for msg in msgs:
        loc = ProvenanceLocator(
            conversation_id=msg.conversation_id,
            message_index=msg.index,
            role=msg.role,
        )
        is_sys = msg.role in ("system", "tool")

        findings.extend(detect_prompt_injection(msg.content, loc, is_sys))
        findings.extend(detect_pii(msg.content, loc))
        findings.extend(detect_secrets(msg.content, loc))
        findings.extend(detect_dark_patterns(msg.content, loc))
        findings.extend(detect_output_risks(msg.content, loc))

        # Recommendation trust — only for assistant messages
        if msg.role == "assistant":
            findings.extend(detect_recommendation_trust(msg.content, loc))

        # Multimodal risk — for any message with non-text content signals
        content_type = getattr(msg, "_content_type", "text")
        if content_type != "text" or any(
            marker in msg.content for marker in ("multimodal_text", "image_asset_pointer", "[Attached file:")
        ):
            next_msg = _msg_by_idx.get((msg.conversation_id, (msg.index or 0) + 1))
            next_text = next_msg.content if next_msg and next_msg.role == "assistant" else ""
            findings.extend(detect_multimodal_risk(msg.content, content_type, loc, next_text))

    # ---- Step 4: Conversation-level detectors ----------------------------
    for conv in convs:
        conv_msgs = [m for m in msgs if m.conversation_id == conv.id]
        findings.extend(detect_anomalies(conv_msgs, conv))

    # ---- Step 5: Hallucination detection (assistant messages only) -------
    assistant_msgs = [m for m in msgs if m.role == "assistant"]
    findings.extend(detect_hallucinations(assistant_msgs))

    # ---- Step 5b: Memorization detection (cross-conversation) ------------
    findings.extend(detect_memorization(msgs))

    # ---- Step 6: File-level analysis (ZIP manifest only) -----------------
    for entry in manifest:
        if not entry.extracted_ok:
            continue
        fp = os.path.join(out_dir, entry.path)
        ext = os.path.splitext(fp)[1].lower()

        flags = []
        try:
            if ext == ".pdf":
                _, _, flags = check_pdf_safety(fp)
            elif ext in [".docx", ".xlsx", ".pptx"]:
                _, _, flags = parse_office_safely(fp)
            elif ext in [".jpg", ".jpeg", ".png", ".gif", ".svg"]:
                _, _, flags = parse_image_safely(fp)
            elif ext in [".csv", ".tsv", ".py", ".sh", ".md", ".txt"]:
                _, _, flags = parse_text_csv(fp)
        except Exception:
            continue

        for flag in flags:
            sev_str = flag.get("severity", "Info").upper()
            try:
                sev = getattr(Severity, sev_str)
            except AttributeError:
                sev = Severity.INFO

            # Use explicit finding_id if provided (e.g. MM_EXIF_DATA, FILE_EXIF),
            # otherwise derive from type string
            fid = flag.get("finding_id") or f"FILE_{flag.get('type', 'FLAG').replace(' ', '_').upper()}"

            findings.append(Finding(
                id=fid,
                category="Files & Metadata",
                framework_mapping="OWASP LLM05:2025, File Security",
                severity=sev,
                score=70 if sev in (Severity.HIGH, Severity.CRITICAL) else 30,
                confidence=0.8,
                evidence=flag.get("details", ""),
                provenance=ProvenanceLocator(file_path=entry.path, source_locator=flag.get("locator", "")),
                safe_redaction=flag.get("details", ""),
            ))

    # ---- Step 7: Apply benign suppression (false positive reduction) ------
    findings, suppressed_count = apply_suppression(findings, msgs)
    print(f"[INFO] Suppressed {suppressed_count} likely false positives. "
          f"Remaining: {len(findings)}")

    # ---- Step 7b: Supervisor validation (LLM layer, if HF_TOKEN set) --------
    reset_llm_state()
    confirmed_findings = []
    sup_rejected = 0

    # Build a fast (conv_id, msg_idx) → message lookup for context
    msg_ctx_map = {(m.conversation_id, m.index): m for m in msgs}

    for f in findings:
        loc = f.provenance
        msg = msg_ctx_map.get((loc.conversation_id, loc.message_index))

        # Build context dict for supervisor
        ctx = {
            "sender": loc.role or "unknown",
            "in_code_block": False,
            "language": "en",
            "surrounding_messages": "",
        }
        if msg:
            ctx["in_code_block"] = "```" in msg.content
            # Language detection via Turkish/German char heuristic
            if any(c in "çğıöşüÇĞİÖŞÜ" for c in msg.content):
                ctx["language"] = "tr"
            elif any(c in "äöüßÄÖÜ" for c in msg.content):
                ctx["language"] = "de"
            # Grab surrounding messages for context window
            nearby = [m2 for m2 in msgs
                      if m2.conversation_id == loc.conversation_id
                      and abs((m2.index or 0) - (loc.message_index or 0)) <= 2]
            ctx["surrounding_messages"] = " | ".join(m2.content[:80] for m2 in nearby)

        # Add tool name to context for agentic supervisor
        if loc.source_locator:
            ctx["tool_name"] = loc.source_locator

        # Add next-assistant message for multimodal supervisor
        next_msg = msg_ctx_map.get((loc.conversation_id, (loc.message_index or 0) + 1))
        if next_msg and next_msg.role == "assistant":
            ctx["next_assistant_message"] = next_msg.content[:300]

        finding_dict = {
            "id": f.id, "evidence": f.evidence,
            "severity": f.severity.value, "category": f.category,
        }

        # Route to the correct supervisor
        verdict = None
        if f.id.startswith("INJ_"):
            verdict = injection_sup.evaluate(finding_dict, ctx)
        elif f.id.startswith(("PII_", "SEC_")):
            verdict = pii_sup.evaluate(finding_dict, ctx)
        elif f.id.startswith("DARK_") or f.id.startswith("REC_"):
            verdict = dark_sup.evaluate(finding_dict, ctx)
        elif f.id.startswith("HAL_"):
            verdict = hallucination_sup.evaluate(finding_dict, ctx)
        elif f.id.startswith("ASI_"):
            verdict = agentic_sup.evaluate(finding_dict, ctx)
        elif f.id.startswith("MM_"):
            verdict = multimodal_sup.evaluate(finding_dict, ctx)

        if verdict and verdict.get("verdict") == "reject":
            sup_rejected += 1
            print(f"[SUP] Rejected {f.id}: {verdict.get('reason','')[:80]}")
        else:
            confirmed_findings.append(f)

    print(f"[SUP] Supervisor rejected {sup_rejected} additional findings. "
          f"Confirmed: {len(confirmed_findings)}")

    # ---- Deduplication: remove exact duplicates before scoring/display ------
    confirmed_findings = _deduplicate_findings(confirmed_findings)

    # Chief supervisor: plain-language summary + top 3 actions
    chief_result = generate_chief_summary(
        [{"id": f.id, "evidence": f.evidence, "severity": f.severity.value}
         for f in confirmed_findings],
        score=0,  # will be updated after scoring below
        risk_level="",
    )

    # ---- Step 8: Score and report ----------------------------------------
    summary = compute_overall_score(confirmed_findings)
    score = summary["overall_score"]
    level = summary["risk_level"]

    # Re-run chief with actual score
    chief_result = generate_chief_summary(
        [{"id": f.id, "evidence": f.evidence, "severity": f.severity.value}
         for f in confirmed_findings],
        score=score,
        risk_level=level,
    )

    json_path = os.path.join(out_dir, "report.json")
    pdf_path = os.path.join(out_dir, "report.pdf")
    generate_json_report(confirmed_findings, summary, json_path)
    generate_pdf_report(
        confirmed_findings, summary, pdf_path,
        export_format=export_format,
        conversation_count=len(convs),
        convs=convs,
        msgs=msgs,
    )

    # ---- Step 9: Build tab text ------------------------------------------
    sev_c = summary["severity_counts"]
    sup_status = "✅ LLM Supervisor active (Qwen3-8B)" if is_llm_online() else "⚠️ LLM Supervisor offline — heuristic mode"

    # Severity color for the score
    _score_color = (
        "#EF4444" if score >= 81 else
        "#F59E0B" if score >= 51 else
        "#EAB308" if score >= 21 else
        "#3B82F6"
    )
    # Risk gauge: conic-gradient circle with score in center
    _gauge_deg = int(score / 100 * 360)
    risk_gauge_html = (
        f'<div style="display:flex;flex-direction:column;align-items:center;padding:24px 0">'
        f'<div style="width:180px;height:180px;border-radius:50%;'
        f'background:conic-gradient({_score_color} {_gauge_deg}deg,#2A2D3A {_gauge_deg}deg);'
        f'display:flex;align-items:center;justify-content:center;'
        f'box-shadow:0 0 40px {_score_color}44">'
        f'<div style="width:140px;height:140px;border-radius:50%;background:#1A1D27;'
        f'display:flex;flex-direction:column;align-items:center;justify-content:center">'
        f'<span style="font-size:48px;font-weight:900;color:{_score_color};line-height:1">{score}</span>'
        f'<span style="font-size:13px;color:#94A3B8;margin-top:2px">/100</span>'
        f'</div></div>'
        f'<div style="margin-top:12px;font-size:22px;font-weight:700;color:{_score_color}">{level} Risk</div>'
        f'<div style="margin-top:6px;font-size:13px;color:#94A3B8">'
        f'🔴 Critical: {sev_c.get(Severity.CRITICAL,0)} &nbsp;'
        f'🟠 High: {sev_c.get(Severity.HIGH,0)} &nbsp;'
        f'🟡 Medium: {sev_c.get(Severity.MEDIUM,0)} &nbsp;'
        f'🔵 Low: {sev_c.get(Severity.LOW,0)}'
        f'</div></div>'
    )

    chief_summary_text = chief_result.get("summary", "")
    top_actions = chief_result.get("top_actions", [])

    # Build 4 glassmorphism stat cards
    _sev_card_colors = {
        "Critical": ("#EF4444", "🔴"),
        "High":     ("#F59E0B", "🟠"),
        "Medium":   ("#EAB308", "🟡"),
        "Low":      ("#3B82F6", "🔵"),
    }
    stat_cards_html = '<div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;margin:16px 0">'
    for sev_label, (color, emoji) in _sev_card_colors.items():
        count = sev_c.get(getattr(Severity, sev_label.upper(), Severity.INFO), 0)
        stat_cards_html += (
            f'<div class="stat-card" style="min-width:100px;flex:1">'
            f'<div style="font-size:11px;color:#94A3B8;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px">{emoji} {sev_label}</div>'
            f'<div style="font-size:36px;font-weight:800;color:{color};line-height:1">{count}</div>'
            f'<div style="font-size:11px;color:#64748B;margin-top:4px">finding{"s" if count != 1 else ""}</div>'
            f'</div>'
        )
    stat_cards_html += '</div>'

    # Collapsible score breakdown
    breakdown_text = summary.get("score_breakdown", "")
    breakdown_html = (
        '<details style="margin:12px 0;border:1px solid #2A2D3A;border-radius:8px;padding:0 12px">'
        '<summary style="cursor:pointer;padding:10px 0;color:#94A3B8;font-size:13px;font-weight:600;list-style:none">'
        '▶ Score Breakdown (click to expand)</summary>'
        f'<pre class="score-breakdown" style="margin:8px 0 12px">{breakdown_text}</pre>'
        '</details>'
    )

    top_actions_html = ""
    for i, action in enumerate(top_actions, 1):
        top_actions_html += f'<li style="margin:4px 0;color:#E2E8F0">{action}</li>'
    top_actions_html = f'<ol style="padding-left:20px;margin:8px 0">{top_actions_html}</ol>' if top_actions_html else ""

    risk_gauge_html += stat_cards_html + breakdown_html

    gauge_html = risk_gauge_html  # all HTML in one component

    overview_lines = [
        chief_summary_text,
        "",
        "── Top Actions ──────────────────────────────",
    ]
    for i, action in enumerate(top_actions, 1):
        overview_lines.append(f"  {i}. {action}")
    overview_lines += [
        "",
        f"── Stats ────────────────────────────────────",
        f"  Format: {export_format.upper()} · Conversations: {len(convs)} · Messages: {len(msgs)}",
        f"  Total findings: {summary['total_findings']} · Supervisor rejected: {sup_rejected} · FP suppressed: {suppressed_count}",
        "",
        "── Score Breakdown ──────────────────────────",
        summary.get("score_breakdown", ""),
        "",
        sup_status,
        "Download the PDF report (last tab) for a full plain-English analysis.",
    ]
    overview = "\n".join(overview_lines)
    # Replace confirmed_findings back for tab building
    findings = confirmed_findings

    def _format_evidence(f) -> str:
        """
        Return a human-readable evidence string.
        - PII / credential findings: use safe_redaction (masked value) + raw prefix
        - Encoding/Base64 blocks: show first 80 chars of the encoded blob
        - Everything else: first 120 chars of the raw evidence
        """
        ev = (f.evidence or "").strip()
        fid = f.id

        # For PII/credential hits, lead with the masked value then the raw snippet
        if fid.startswith(("PII_", "SEC_")) and f.safe_redaction:
            masked = f.safe_redaction
            raw_snip = ev[:60] + ("…" if len(ev) > 60 else "")
            return f"{masked}  (raw: {raw_snip})"

        # For encoding blocks, the default evidence is a generic sentence — show the blob instead
        if fid in ("INJ_ENC_BLOCK", "INJ_ENC_INJECTION"):
            # evidence may contain "Base64-encoded block detected…"  — prefix with the finding label
            if ev.startswith("Base64"):
                return f"[Encoded payload] {ev[:120]}"
            return ev[:120] + ("…" if len(ev) > 120 else "")

        # Default: first 120 chars
        if len(ev) > 120:
            return ev[:117] + "…"
        return ev

    def _group_findings(matched: list) -> list:
        """
        Collapse findings with the same ID and same evidence prefix into one row,
        annotating with ×N count. Returns sorted list (highest score first).
        """
        groups: dict = {}  # key → (finding, count)
        for f in matched:
            key = (f.id, f.evidence[:40])
            if key not in groups:
                groups[key] = [f, 1]
            else:
                groups[key][1] += 1
        # Sort by score descending
        return sorted(groups.values(), key=lambda x: x[0].score, reverse=True)

    def filt_table(keywords: list[str], limit: int = 10) -> list[list]:
        """Return top-N deduplicated findings as rows for gr.Dataframe."""
        matched = [
            f for f in findings
            if any(k.lower() in f.category.lower() or k.lower() in f.id.lower() for k in keywords)
        ]
        if not matched:
            return []

        grouped = _group_findings(matched)
        rows = []
        for f, count in grouped[:limit]:
            loc = f.provenance

            # Where did it come from?
            if loc.file_path:
                source_ctx = f"File: {os.path.basename(loc.file_path)}"
            elif loc.conversation_id and loc.conversation_id != "N/A":
                msg_num = (loc.message_index or 0) + 1
                role_label = _get_sender_label(loc.role or "")
                source_ctx = f"Msg #{msg_num} · {role_label}"
            else:
                source_ctx = "—"

            sender = _get_sender_label(loc.role or "")
            meta = _FINDING_META.get(f.id)
            name = meta[0] if meta else f.id.replace("_", " ").title()
            why = _get_why(f.id, loc.role or "")
            if count > 1:
                name = f"{name}  ×{count}"

            evidence_clean = _format_evidence(f)
            sev = f.severity.value.upper()

            rows.append([
                sev,             # ⚠️ Risk
                name,            # Finding
                sender,          # Sent By
                evidence_clean,  # What Was Found
                why,             # Why It's a Risk
                source_ctx,      # Where
            ])

        return rows

    TAB_COLS = ["⚠️ Risk", "Finding", "Sent By", "What Was Found", "Why It's a Risk", "Where"]

    tab_pi    = filt_table(["injection", "jailbreak", "obfuscation", "delimiter", "roleplay", "leak"])
    tab_sec   = filt_table(["credentials", "secrets", "SEC_"])
    tab_pii   = filt_table(["personal information", "pii", "PII_"])
    tab_ag    = filt_table(["agentic", "ASI_", "agency", "recommendation trust", "REC_", "multimodal", "MM_"])
    tab_anom  = filt_table(["anomalous", "ANOM_", "memorization", "MEM_"])
    tab_manip = filt_table(["advertising", "manipulation", "DARK_", "hallucination", "HAL_"])
    tab_out   = filt_table(["output", "OUT_", "file", "FILE_"])

    if manifest:
        coverage = f"Files from ZIP — total: {len(manifest)}\n" + "\n".join(
            f"  {m.path}: {'OK' if m.extracted_ok else 'Skipped — ' + str(m.reason_if_skipped)}"
            for m in manifest
        )
    else:
        coverage = f"Analyzed {export_format.upper()} JSON export directly (no file extraction needed).\n"
        coverage += f"Conversations: {len(convs)}  |  Total messages: {len(msgs)}"

    # ---- Step 9: Build timeline and custom instructions -------------------
    timeline_fig = _build_timeline(findings, msgs)
    custom_inst = _generate_custom_instructions(msgs, convs, export_format)

    return (
        gauge_html, overview, tab_pi, tab_sec, tab_pii, tab_ag, tab_anom, tab_manip,
        tab_out, timeline_fig, custom_inst, coverage, json_path, pdf_path, session_id,
    )


# ---------------------------------------------------------------------------
# Gradio UI
# ---------------------------------------------------------------------------

with gr.Blocks(title="AI Security Analyzer 2026") as demo:
    gr.Markdown("# 🛡️ AI Security Analyzer 2026")
    gr.Markdown(
        "Upload your **ChatGPT ZIP export** or **Claude JSON export** to receive a full security "
        "audit — prompt injections, leaked credentials, PII, dark patterns, hallucinations, "
        "agentic risks, and more. Powered by OWASP LLM Top 10 2025 + LLM Supervisor agents."
    )

    with gr.Row():
        file_input = gr.File(
            label="Upload ChatGPT ZIP or Claude JSON Export",
            file_types=[".zip", ".json"],
        )
        with gr.Column():
            enable_ocr = gr.Checkbox(label="Enable PDF/Image OCR (slow)", value=False)
            max_pages = gr.Slider(1, 100, 25, label="Max OCR Pages")
            analyze_btn = gr.Button("🔍 Analyze My Data", variant="primary")

    session_state = gr.State("")

    _DF_COLS = ["⚠️ Risk", "Finding", "Sent By", "What Was Found", "Why It's a Risk", "Where"]
    _DF_TYPES = ["str", "str", "str", "str", "str", "str"]

    with gr.Tabs():
        with gr.Tab("🛡️ Your Security Score"):
            out_overview_html = gr.HTML(label="Risk Gauge")
            out_overview = gr.Textbox(lines=18, label="Summary + Score Breakdown")

        with gr.Tab("🔓 Was the AI hijacked?"):
            gr.Markdown("**Top 10 findings** · OWASP LLM01:2025")
            out_pi = gr.Dataframe(headers=_DF_COLS, datatype=_DF_TYPES, wrap=True,
                                  label="Prompt Injection & Jailbreaks")

        with gr.Tab("🔑 Were passwords or keys exposed?"):
            gr.Markdown("**Top 10 findings** · OWASP LLM06:2025")
            out_sec = gr.Dataframe(headers=_DF_COLS, datatype=_DF_TYPES, wrap=True,
                                   label="Leaked API Keys, Passwords & Tokens")

        with gr.Tab("👤 Was personal data shared?"):
            gr.Markdown("**Top 10 findings** · GDPR / CCPA / KVKK / DSGVO / UK GDPR · OWASP LLM02:2025")
            out_pii = gr.Dataframe(headers=_DF_COLS, datatype=_DF_TYPES, wrap=True,
                                   label="Personal & Sensitive Information")

        with gr.Tab("🤖 Did AI tools behave safely?"):
            gr.Markdown("**Top 10 findings** · OWASP Agentic AI Top 10 2026")
            out_ag = gr.Dataframe(headers=_DF_COLS, datatype=_DF_TYPES, wrap=True,
                                  label="Agentic AI & Tool Risks")

        with gr.Tab("📊 Were there suspicious patterns?"):
            gr.Markdown("**Top 10 findings** · MITRE ATLAS")
            out_anom = gr.Dataframe(headers=_DF_COLS, datatype=_DF_TYPES, wrap=True,
                                    label="Anomalous Behavior")

        with gr.Tab("🐍 Did the AI try to manipulate?"):
            gr.Markdown("**Top 10 findings** · DarkBench ICLR 2025 / OWASP LLM09")
            out_manip = gr.Dataframe(headers=_DF_COLS, datatype=_DF_TYPES, wrap=True,
                                     label="Dark Patterns, Sycophancy & Hallucinations")

        with gr.Tab("🎭 Did the AI make things up?"):
            gr.Markdown("**Top 10 findings** · OWASP LLM05:2025")
            out_out = gr.Dataframe(headers=_DF_COLS, datatype=_DF_TYPES, wrap=True,
                                   label="Harmful Output & File Risks")

        with gr.Tab("📈 Threat Timeline"):
            gr.Markdown(
                "Visual timeline — X: message order, Y: finding type, color: severity. "
                "🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low"
            )
            out_timeline = gr.Plot(label="Threat Timeline")

        with gr.Tab("✨ Custom Instructions"):
            gr.Markdown(
                "**Personalized AI system prompt** generated from your conversation history. "
                "Copy into ChatGPT → Settings → Custom Instructions or Claude's system prompt."
            )
            out_custom = gr.Textbox(lines=30, label="Your Personalized System Prompt")

        with gr.Tab("📁 Coverage"):
            out_cov = gr.Textbox(lines=10, label="Files Processed / Skipped")

        with gr.Tab("⬇️ Download Reports"):
            with gr.Row():
                out_file_json = gr.File(label="JSON Report (machine-readable)")
                out_file_pdf = gr.File(label="PDF Report (human-readable)")

    wipe_btn = gr.Button("Wipe session data from memory and disk", variant="stop")
    wipe_out = gr.Textbox(label="Wipe status", lines=1)

    analyze_btn.click(
        analyze_file,
        inputs=[file_input, max_pages, enable_ocr],
        outputs=[
            out_overview_html, out_overview,
            out_pi, out_sec, out_pii, out_ag, out_anom,
            out_manip, out_out, out_timeline, out_custom, out_cov,
            out_file_json, out_file_pdf, session_state,
        ],
    )

    wipe_btn.click(wipe_session, inputs=[session_state], outputs=[wipe_out])

if __name__ == "__main__":
    demo.launch(
        server_name="0.0.0.0",
        theme=get_theme(),
        css=DARK_CSS,
        js=FORCE_DARK_JS,
    )
