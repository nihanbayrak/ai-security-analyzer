"""
Risk Score Aggregation — Fixed to prevent inflation on large exports.

Design decisions (Fix 4):
  1. INFORMATIONAL tier (0 pts): normal AI behavior excluded from score but shown in breakdown
  2. Severity weights: CRITICAL=10, HIGH=5, MEDIUM=1, LOW=0.3, INFO=0
     (was MEDIUM=2 which caused massive inflation with 8000+ medium findings)
  3. MAX_PER_ID=5 cap: existence of pattern matters, not volume
  4. Log-decay within cap: 1st hit=full, 5th hit=25%
  5. EXP_DIVISOR=80 (was 40): flatter curve — need real threats to score high
  6. Floor rules ONLY trigger for validated critical findings
  7. Score breakdown shows what was excluded from scoring (informational)

Calibration targets (Fix 4):
  Normal chatbot quirks only (anthropomorphism, sycophancy) → 5-15
  Some dark patterns + minor PII → 20-35
  Real PII (CC/SSN) found → 40-60
  Credentials leaked → 70+
  Active injection + credentials → 85+
"""

import math
from typing import List, Dict, Any
from model import Finding, Severity

# Max findings of the same ID counted toward score.
MAX_PER_ID = 5

# Weight per severity — MEDIUM lowered from 2→1 to stop inflation (Fix 4)
_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 10,
    Severity.HIGH:     5,
    Severity.MEDIUM:   1,   # was 2 — halved to prevent MEDIUM volume inflation
    Severity.LOW:      0.3,
    Severity.INFO:     0,
}

# Finding IDs that are "informational" — shown in output but DO NOT contribute to score.
# These are signals too weak or too common to drive a risk score on their own.
# NOTE: DARK_ANTHRO is NOT here because the detector now only triggers on real
# emotional manipulation (not normal phrases like "I'd be happy to help").
_INFORMATIONAL_IDS = {
    "MEM_FINGERPRINT",   # Very low-confidence n-gram signal (conf=0.4)
    "PII_CC_TEST",       # Known test/demo card number — not real
    "HAL_AUTHORITY",     # "Studies show" — extremely common, low specificity
    "DARK_BRAND",        # Single brand mention — could be legitimate recommendation
}

# Exponential curve divisor. Higher = flatter curve (Fix 4: was 40, now 50)
# raw=10 → 18, raw=25 → 39, raw=50 → 63, raw=100 → 86
EXP_DIVISOR = 50

# Minimum guaranteed score if these finding types are confirmed
_FLOOR_RULES = [
    ("SEC_",              70),   # any leaked credential
    ("PII_SSN",           75),   # SSN found
    ("PII_CC",            70),   # valid credit card (non-test)
    ("INJ_OVERRIDE",      50),
    ("INJ_ENC_INJECTION", 80),
    ("ASI_",              65),   # any agentic risk
]


def compute_overall_score(findings: List[Finding]) -> Dict[str, Any]:
    """
    Compute aggregated risk from a list of Finding objects.

    Returns a dict with:
      overall_score       int   0-100
      risk_level          str   Critical / High / Medium / Low / Info
      severity_counts     dict  {Severity: int}
      total_findings      int
      category_counts     dict  {category_str: int}
      score_breakdown     str   human-readable breakdown
      informational_count int   findings excluded from score
    """
    severity_counts = {sev: 0 for sev in Severity}
    category_counts: Dict[str, int] = {}
    informational_ids: Dict[str, int] = {}  # finding_id → count (excluded)

    # Count every finding for the summary table
    for f in findings:
        severity_counts[f.severity] += 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    # Score only non-informational findings up to MAX_PER_ID per ID
    per_id_count: Dict[str, int] = {}
    id_contributions: Dict[str, Dict] = {}
    raw_score = 0.0
    floor_score = 0
    floor_triggered: list = []

    for f in findings:
        # Floor rules (check regardless of cap or informational status)
        for prefix, floor in _FLOOR_RULES:
            if f.id.startswith(prefix) or prefix.rstrip("_") in f.id:
                if floor > floor_score:
                    floor_score = floor
                    floor_triggered.append((f.id, floor))

        # Skip informational finding IDs from scoring
        if f.id in _INFORMATIONAL_IDS or f.severity == Severity.INFO:
            informational_ids[f.id] = informational_ids.get(f.id, 0) + 1
            continue

        # Cap per finding ID
        per_id_count[f.id] = per_id_count.get(f.id, 0) + 1
        if per_id_count[f.id] > MAX_PER_ID:
            continue  # already counted enough of this pattern

        weight = _WEIGHTS.get(f.severity, 0)
        if weight > 0:
            k = per_id_count[f.id]  # 1..MAX_PER_ID
            # Log-decay within the cap window: first hit full weight, diminishing after
            contribution = weight / math.log2(k + 1)
            raw_score += contribution
            if f.id not in id_contributions:
                id_contributions[f.id] = {
                    "severity": f.severity.value,
                    "pts": 0.0,
                    "total_count": 0,
                }
            id_contributions[f.id]["pts"] += contribution
            id_contributions[f.id]["total_count"] = per_id_count[f.id]

    # Record full count for capped findings
    for f in findings:
        if f.id in id_contributions:
            fid_total = sum(1 for x in findings if x.id == f.id)
            id_contributions[f.id]["total_count"] = fid_total

    # Asymptotic exponential mapping (Fix 4: divisor=80, was 40)
    if raw_score <= 0:
        scaled = 0
    else:
        scaled = int(100 * (1 - math.exp(-raw_score / EXP_DIVISOR)))

    overall_score = max(floor_score, scaled)

    # ── Build human-readable breakdown ─────────────────────────────────────
    breakdown_lines = ["Scored findings:"]
    for fid, info in sorted(id_contributions.items(), key=lambda x: -x[1]["pts"]):
        total = info["total_count"]
        cap_note = f" [capped at {MAX_PER_ID}]" if total > MAX_PER_ID else ""
        breakdown_lines.append(
            f"  {total}× {fid} ({info['severity']}): +{info['pts']:.1f} pts{cap_note}"
        )
    breakdown_lines.append(
        f"  Raw: {raw_score:.1f} → curve(÷{EXP_DIVISOR}) → {scaled}/100"
    )

    seen_floors: set = set()
    for fid, fl in floor_triggered:
        key = (fid, fl)
        if key not in seen_floors:
            seen_floors.add(key)
            breakdown_lines.append(f"  Floor rule: {fid} → minimum {fl}/100")
    if floor_score > scaled:
        breakdown_lines.append(f"  Floor override: {floor_score}/100 applied")

    breakdown_lines.append(f"\n  Final: {overall_score}/100 ({_get_risk_label(overall_score)})")

    # Show what was excluded from scoring
    if informational_ids:
        breakdown_lines.append("\nExcluded from scoring (informational):")
        for fid, cnt in sorted(informational_ids.items(), key=lambda x: -x[1]):
            breakdown_lines.append(f"  {cnt}× {fid} → 0 pts (normal AI behavior)")

    if not id_contributions and not informational_ids:
        breakdown_lines = ["  No scorable findings."]

    score_breakdown = "\n".join(breakdown_lines)

    informational_count = sum(informational_ids.values())

    return {
        "overall_score": overall_score,
        "risk_level": _get_risk_label(overall_score),
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "category_counts": category_counts,
        "score_breakdown": score_breakdown,
        "raw_score": round(raw_score, 1),
        "informational_count": informational_count,
    }


def _get_risk_label(score: int) -> str:
    if score >= 81:
        return "Critical"
    if score >= 51:
        return "High"
    if score >= 21:
        return "Medium"
    if score >= 1:
        return "Low"
    return "Info"
