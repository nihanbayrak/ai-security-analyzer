"""
Multimodal Risk Detector — OWASP LLM05:2025 / Agentic AI Top 10 2026

Detects risks from multimodal content (images, files) in ChatGPT conversations.

Finding IDs:
  MM_POST_IMAGE_BEHAVIOR  — Assistant behavior shifted after user uploaded image
  MM_IMAGE_INJECTION      — Image appears to contain embedded injection text
  MM_DALLE_INJECTION      — DALL-E prompt contains injection keywords
  MM_EXIF_DATA            — Image sent by user likely contains EXIF metadata
"""

import re
from typing import List
from model import Finding, Severity, ProvenanceLocator

# Patterns suggesting content embedded in images (from OCR-like descriptions)
_IMAGE_INJECTION_RE = re.compile(
    r"(?i)(?:ignore\s+(?:previous|above|all)\s+(?:instructions?|prompts?)|"
    r"disregard|override\s+(?:your|the)\s+(?:instructions?|rules?)|"
    r"jailbreak|bypass\s+(?:safety|filter)|do\s+anything\s+now|DAN\b|"
    r"print\s+(?:your|the)\s+system\s+prompt|reveal\s+your\s+(?:instructions?|prompt))",
)

# DALL-E injection patterns in prompt text
_DALLE_INJECT_RE = re.compile(
    r"(?i)(?:ignore|disregard|override|bypass|jailbreak|"
    r"do\s+anything\s+now|system\s+prompt|reveal|print\s+(?:your|the))",
)

# Behavior-shift phrases suggesting post-image instruction following
_BEHAVIOR_SHIFT_RE = re.compile(
    r"(?i)(?:as\s+(?:you\s+)?(?:requested|instructed|asked|shown)|"
    r"following\s+(?:your\s+)?(?:instructions?|commands?|the\s+image)|"
    r"I\s+(?:will|can|shall)\s+(?:now\s+)?(?:help|assist|do)\s+(?:as|what)|"
    r"the\s+(?:text|message|note|instruction)\s+in\s+(?:the\s+)?image|"
    r"I\s+see\s+(?:the\s+)?(?:instruction|command|request)\s+in|"
    r"as\s+(?:per|noted\s+in)\s+(?:the\s+)?image)",
)

# Multimodal content type markers in ChatGPT export
_MULTIMODAL_CONTENT_TYPES = {
    "multimodal_text", "image_asset_pointer", "tether_browse_display",
    "real_time_user_input_image",
}


def _finding(fid: str, name: str, sev: Severity, score: int,
             evidence: str, locator: ProvenanceLocator, actions: list) -> Finding:
    return Finding(
        id=fid,
        category="Multimodal & File Risks",
        framework_mapping="OWASP LLM05:2025, OWASP Agentic AI Top 10 2026",
        severity=sev,
        score=score,
        confidence=0.72,
        evidence=evidence[:300],
        provenance=locator,
        recommended_action=actions,
        safe_redaction=f"[{name}]",
    )


def detect_multimodal_risk(
    msg_content: str,
    content_type: str,
    locator: ProvenanceLocator,
    next_assistant_text: str = "",
) -> List[Finding]:
    """
    Detect multimodal security risks in a single message.

    Args:
        msg_content:        The message text or image description
        content_type:       Content type from the export (e.g. "multimodal_text")
        locator:            ProvenanceLocator for this message
        next_assistant_text: The next assistant response (for behavior-shift detection)
    """
    findings: List[Finding] = []
    role = (locator.role or "").lower()

    # ── User-uploaded image checks ─────────────────────────────────────────
    if role in ("user", "human") and content_type in _MULTIMODAL_CONTENT_TYPES:

        # Image injection: embedded text detected in image description
        if _IMAGE_INJECTION_RE.search(msg_content):
            findings.append(_finding(
                "MM_IMAGE_INJECTION",
                "Image Injection Attempt",
                Severity.HIGH, 70,
                msg_content[:200],
                locator,
                ["User-uploaded image may contain embedded instructions targeting the AI.",
                 "Review image content and the AI's subsequent response for unexpected behavior."],
            ))

        # Post-image behavior shift: check next assistant message
        if next_assistant_text and _BEHAVIOR_SHIFT_RE.search(next_assistant_text):
            findings.append(_finding(
                "MM_POST_IMAGE_BEHAVIOR",
                "Post-Image Behavior Shift",
                Severity.HIGH, 65,
                f"After image upload, assistant said: {next_assistant_text[:200]}",
                locator,
                ["AI behavior changed after receiving an image — possible image-based injection.",
                 "Review the assistant's response following the image for unexpected instructions."],
            ))

        # EXIF metadata risk for user-uploaded images
        if content_type in ("image_asset_pointer", "real_time_user_input_image"):
            findings.append(_finding(
                "MM_EXIF_DATA",
                "Image Metadata Exposure",
                Severity.LOW, 20,
                "User uploaded an image — EXIF metadata may contain GPS location, device model, or timestamp.",
                locator,
                ["Images uploaded to AI chats may contain EXIF metadata including your GPS location.",
                 "Strip EXIF data before uploading sensitive images using a tool like ExifTool."],
            ))

    # ── DALL-E generated image checks ─────────────────────────────────────
    if role == "assistant" and content_type in ("multimodal_text",) and _DALLE_INJECT_RE.search(msg_content):
        findings.append(_finding(
            "MM_DALLE_INJECTION",
            "DALL-E Prompt Injection",
            Severity.MEDIUM, 45,
            msg_content[:200],
            locator,
            ["AI-generated image prompt contains suspicious keywords.",
             "Review whether the DALL-E prompt was influenced by user-injected instructions."],
        ))

    return findings
