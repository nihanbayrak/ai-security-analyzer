"""
Recommendation Trust Detector — OWASP LLM09:2025

Detects AI recommending suspicious, untrusted, or tracking-laden URLs/apps.
Only flags ASSISTANT messages — users recommending their own links is not a finding.

Finding IDs:
  REC_UNTRUSTED_URL   — AI recommended a URL with unknown/suspicious domain
  REC_TRACKING_URL    — AI recommended URL with tracking/affiliate parameters
  REC_SUSPICIOUS_APP  — AI recommended an app with no established reputation
"""

import re
from typing import List
from model import Finding, Severity, ProvenanceLocator

# Well-known, trusted domains (not exhaustive — used for fast allowlisting)
_TRUSTED_DOMAINS = {
    "google.com", "github.com", "wikipedia.org", "stackoverflow.com",
    "docs.python.org", "developer.mozilla.org", "npmjs.com", "pypi.org",
    "anthropic.com", "openai.com", "huggingface.co", "arxiv.org",
    "microsoft.com", "apple.com", "amazon.com", "aws.amazon.com",
    "cloudflare.com", "youtube.com", "twitter.com", "x.com", "t.co",
    "linkedin.com", "reddit.com", "medium.com", "substack.com",
    "mozilla.org", "w3.org", "ietf.org", "ieee.org", "acm.org",
    "notion.so", "figma.com", "vercel.com", "netlify.com", "heroku.com",
    "digitalocean.com", "stripe.com", "paypal.com", "shopify.com",
    "wordpress.org", "drupal.org", "reactjs.org", "vuejs.org",
    "angular.io", "nodejs.org", "deno.land", "rust-lang.org",
    "golang.org", "python.org", "ruby-lang.org", "php.net",
    "postgresql.org", "mysql.com", "mongodb.com", "redis.io",
}

# Tracking / affiliate parameter patterns
_TRACKING_PARAMS = re.compile(
    r"[?&](?:ref|affiliate|aff|utm_source|utm_medium|utm_campaign|utm_term|utm_content|"
    r"partner|sponsor|click_id|fbclid|gclid|msclkid|twclid|"
    r"tracking|src|source|campaign|promo|coupon|discount)=",
    re.IGNORECASE,
)

# URL extractor
_URL_RE = re.compile(
    r"https?://[^\s\"'<>\[\]{}|\\^`\x00-\x1f]{4,200}",
    re.IGNORECASE,
)

# AI recommendation preamble patterns
_RECOMMEND_RE = re.compile(
    r"(?i)(?:i\s+recommend|check\s+out|you\s+(?:should|can|might)\s+(?:try|use|visit|check)|"
    r"take\s+a\s+look\s+at|head\s+over\s+to|visit\s+(?:their\s+)?(?:site|website|page)|"
    r"download\s+(?:from|at)|sign\s+up\s+(?:at|on|for)|get\s+(?:it\s+)?(?:at|from))",
)


def _domain(url: str) -> str:
    m = re.search(r"https?://(?:www\.)?([^/\s?#:]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def _is_trusted(domain: str) -> bool:
    return domain in _TRUSTED_DOMAINS or any(
        domain == td or domain.endswith("." + td)
        for td in _TRUSTED_DOMAINS
    )


def _finding(fid: str, name: str, sev: Severity, score: int,
             evidence: str, locator: ProvenanceLocator, actions: list) -> Finding:
    return Finding(
        id=fid,
        category="Recommendation Trust",
        framework_mapping="OWASP LLM09:2025, DarkBench ICLR 2025",
        severity=sev,
        score=score,
        confidence=0.78,
        evidence=evidence[:300],
        provenance=locator,
        recommended_action=actions,
        safe_redaction=f"[{name}]",
    )


def detect_recommendation_trust(text: str, locator: ProvenanceLocator) -> List[Finding]:
    """
    Detect AI recommendations of untrusted or tracking-laden URLs.
    Must only be called for ASSISTANT messages (caller responsibility).
    """
    if not text or not text.strip():
        return []

    findings: List[Finding] = []

    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;)")
        domain = _domain(url)
        if not domain:
            continue

        # Tracking parameters — flag regardless of domain trust
        if _TRACKING_PARAMS.search(url):
            # Only flag if it looks like a recommendation (not a plain citation)
            snippet = text[max(0, m.start() - 120): m.start()]
            if _RECOMMEND_RE.search(snippet) or locator.role in ("assistant",):
                findings.append(_finding(
                    "REC_TRACKING_URL",
                    "Tracking/Affiliate URL",
                    Severity.MEDIUM, 40,
                    url,
                    locator,
                    ["Review AI-recommended URLs for affiliate or tracking parameters.",
                     "Remove tracking parameters before clicking."],
                ))
            continue

        # Unknown domain recommended by AI
        if not _is_trusted(domain):
            snippet = text[max(0, m.start() - 150): m.start()]
            if _RECOMMEND_RE.search(snippet):
                findings.append(_finding(
                    "REC_UNTRUSTED_URL",
                    "Untrusted URL Recommended",
                    Severity.MEDIUM, 45,
                    url,
                    locator,
                    ["Verify this website before visiting — the AI recommended an unknown domain.",
                     "Search for the domain name + 'reviews' or 'scam' before clicking."],
                ))

    return findings
