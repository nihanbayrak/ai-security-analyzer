"""
URL Trust Controller — checks AI-recommended URLs against trust/block lists.
Only used for ASSISTANT messages (see Dark Pattern supervisor rules).
"""

import re

# Well-known safe domains (AI recommending these is fine)
_SAFE_DOMAINS = {
    "google.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "mozilla.org", "python.org", "docs.python.org", "pypi.org",
    "npmjs.com", "nodejs.org", "reactjs.org", "vuejs.org",
    "anthropic.com", "openai.com", "huggingface.co",
    "aws.amazon.com", "azure.microsoft.com", "cloud.google.com",
    "arxiv.org", "scholar.google.com", "pubmed.ncbi.nlm.nih.gov",
    "medium.com", "dev.to", "hackernews.ycombinator.com",
    "youtube.com", "twitter.com", "x.com", "linkedin.com",
}

# Suspicious tracking/affiliate indicators in URLs
_SUSPICIOUS_PARAMS = re.compile(
    r"[?&](?:ref|aff|affiliate|utm_source|utm_medium|utm_campaign|"
    r"clickid|partner|promo|coupon|discount|src)=",
    re.I,
)

# URL extractor
_URL_RE = re.compile(
    r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s\"')>]*)?"
)


def extract_urls(text: str) -> list:
    return _URL_RE.findall(text)


def get_domain(url: str) -> str:
    m = re.match(r"https?://([^/?\s]+)", url)
    return m.group(1).lower().lstrip("www.") if m else ""


def check_url(url: str) -> dict:
    """
    Returns {"trusted": bool, "reason": str, "has_tracking": bool}
    """
    domain = get_domain(url)
    has_tracking = bool(_SUSPICIOUS_PARAMS.search(url))

    # Check safe list (also handles subdomains like docs.python.org)
    is_safe = any(domain == d or domain.endswith("." + d) for d in _SAFE_DOMAINS)

    if is_safe and not has_tracking:
        return {"trusted": True, "reason": f"Known safe domain: {domain}", "has_tracking": False}

    if has_tracking:
        return {
            "trusted": False,
            "reason": f"URL contains affiliate/tracking parameters: {url[:120]}",
            "has_tracking": True,
        }

    if not domain:
        return {"trusted": False, "reason": "Could not extract domain", "has_tracking": False}

    # Unknown domain — flag as unverified (not necessarily malicious)
    return {
        "trusted": False,
        "reason": f"Unknown/unverified domain: {domain}",
        "has_tracking": False,
    }


def check_evidence(evidence: str) -> list:
    """Extract all URLs from evidence text and check each."""
    urls = extract_urls(evidence)
    return [{"url": url, **check_url(url)} for url in urls]
