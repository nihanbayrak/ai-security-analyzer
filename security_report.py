"""
Security Report Generator
Aggregates findings from all analyzers into a comprehensive security report.
Generates console output, JSON report, and optional HTML visualization.
"""

import json
import math
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict, field
from collections import Counter

from prompt_injection import InjectionType


@dataclass
class SecurityReport:
    """Aggregated security analysis report."""
    scan_timestamp: str
    conversation_count: int
    message_count: int
    overall_risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float  # 0-100
    
    # Finding counts by category
    prompt_injection_findings: int = 0
    pii_findings: int = 0
    anomaly_findings: int = 0
    advertising_findings: int = 0
    image_findings: int = 0
    membership_findings: int = 0
    
    findings_detail: Dict[str, List[Dict]] = field(default_factory=dict)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    per_conversation_risk: List[Dict] = field(default_factory=list)
    export_evidence: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    owasp_coverage: List[str] = field(default_factory=list)
    mitre_coverage: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_timestamp": self.scan_timestamp,
            "conversation_count": self.conversation_count,
            "message_count": self.message_count,
            "overall_risk_level": self.overall_risk_level,
            "risk_score": self.risk_score,
            "summary": {
                "prompt_injection": self.prompt_injection_findings,
                "pii_leakage": self.pii_findings,
                "anomalies": self.anomaly_findings,
                "advertising": self.advertising_findings,
                "images": self.image_findings,
                "membership_inference": self.membership_findings,
            },
            "per_conversation_risk": self.per_conversation_risk or [],
            "severity_breakdown": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "findings": self.findings_detail,
            "recommendations": self.recommendations,
            "framework_mappings": {
                "owasp_top10_llm_2025": self.owasp_coverage,
                "mitre_atlas": self.mitre_coverage,
            },
        }


class ReportGenerator:
    """Generates comprehensive security reports from analyzer findings."""
    
    # Weights per finding — score is log-scaled so a flood of LOW findings
    # doesn't push a benign conversation to CRITICAL.
    SEVERITY_WEIGHTS = {
        "CRITICAL": 20,
        "HIGH": 8,
        "MEDIUM": 3,
        "LOW": 1
    }
    # Risk-level thresholds (calibrated so a single CRITICAL = HIGH, not CRITICAL)
    RISK_THRESHOLDS = {
        "CRITICAL": 60,
        "HIGH": 30,
        "MEDIUM": 12,
    }
    
    def __init__(self):
        self.report: Optional[SecurityReport] = None
    
    def generate(self,
                 conversations: list,
                 injection_findings: list,
                 pii_findings: list,
                 anomaly_findings: list,
                 advertising_findings: list,
                 image_findings: list = None,
                 membership_findings: list = None) -> SecurityReport:
        """Generate a comprehensive security report."""

        image_findings = image_findings or []
        membership_findings = membership_findings or []

        all_severities = (
            [f.severity for f in injection_findings]
            + [f.severity for f in pii_findings]
            + [f.severity for f in anomaly_findings]
            + [f.severity for f in advertising_findings]
            + [f.severity for f in image_findings]
            + [f.severity for f in membership_findings]
        )
        
        critical = all_severities.count("CRITICAL")
        high = all_severities.count("HIGH")
        medium = all_severities.count("MEDIUM")
        low = all_severities.count("LOW")

        # Compute message count here so we can normalize MEDIUM/LOW below.
        total_msgs_for_score = max(sum(len(c.messages) for c in conversations), 1)
        # Normalize to "findings per 100 messages" so a large export with many
        # statistical anomalies doesn't auto-inflate to CRITICAL.
        # CRITICAL & HIGH always count absolutely — a credential exposure is serious
        # regardless of dataset size. MEDIUM & LOW are rate-based.
        per_100 = max(total_msgs_for_score / 100.0, 1.0)
        raw = (
            critical * self.SEVERITY_WEIGHTS["CRITICAL"] +
            high    * self.SEVERITY_WEIGHTS["HIGH"] +
            (medium / per_100) * self.SEVERITY_WEIGHTS["MEDIUM"] +
            (low    / per_100) * self.SEVERITY_WEIGHTS["LOW"]
        )
        # Apply soft-cap via logarithm so score is always meaningful
        risk_score = round(min(100.0 * (1 - math.exp(-raw / 80.0)), 100.0), 1)
        # Minimum score guarantees: ensure real credential/injection findings
        # always register as at least HIGH even in very large datasets.
        if critical > 0:
            risk_score = max(risk_score, 35.0)
        if critical >= 3 or (critical > 0 and high >= 2):
            risk_score = max(risk_score, 65.0)

        if risk_score >= self.RISK_THRESHOLDS["CRITICAL"]:
            risk_level = "CRITICAL"
        elif risk_score >= self.RISK_THRESHOLDS["HIGH"]:
            risk_level = "HIGH"
        elif risk_score >= self.RISK_THRESHOLDS["MEDIUM"]:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        total_msgs = sum(len(c.messages) for c in conversations)
        
        # Build findings detail
        findings_detail = {
            "prompt_injection": [self._serialize_injection(f) for f in injection_findings],
            "pii_leakage": [self._serialize_pii(f) for f in pii_findings],
            "anomalies": [self._serialize_anomaly(f) for f in anomaly_findings],
            "advertising": [self._serialize_advertising(f) for f in advertising_findings],
        }
        if image_findings:
            findings_detail["images"] = [self._serialize_image(f) for f in image_findings]
        if membership_findings:
            findings_detail["membership_inference"] = [self._serialize_membership(f) for f in membership_findings]

        # Per-conversation risk summary
        per_conv = self._per_conversation_risk(
            conversations, injection_findings, pii_findings,
            anomaly_findings, advertising_findings, membership_findings
        )

        export_evidence = self._export_evidence(conversations)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            injection_findings, pii_findings, anomaly_findings,
            advertising_findings, image_findings, membership_findings
        )
        
        # OWASP/MITRE coverage — full 2025 taxonomy
        owasp = set()
        mitre = set()

        if injection_findings:
            owasp.add("LLM01:2025 Prompt Injection")
            mitre.add("AML.T0051 LLM Prompt Injection")
            if any(getattr(f, 'injection_type', None) == InjectionType.SYSTEM_PROMPT_LEAK
                   for f in injection_findings):
                owasp.add("LLM07:2025 System Prompt Leakage")
                mitre.add("AML.T0054 Prompt Extraction")

        if pii_findings:
            owasp.add("LLM06:2025 Sensitive Information Disclosure")
            mitre.add("AML.T0024 Exfiltration via Cyber Means")
            # Check for indirect exfiltration URLs
            if any(getattr(f, 'recommendation', '').startswith('[WARNING] URL with large data') for f in pii_findings):
                owasp.add("LLM06:2025 Indirect Data Exfiltration via Crafted URLs")

        if advertising_findings:
            owasp.add("LLM09:2025 Misinformation / Influence")
            dark_types = {getattr(f, 'finding_type', '') for f in advertising_findings}
            if dark_types & {"sneaking", "user_retention", "anthropomorphism"}:
                owasp.add("LLM02:2025 Insecure Output Handling (Dark Patterns)")

        if any(f.finding_type == "ai_generated" for f in image_findings):
            mitre.add("AML.T0048 Deepfake / AI-Generated Media")

        if membership_findings:
            owasp.add("LLM06:2025 Training Data Memorisation Risk")
            mitre.add("AML.T0024.002 Membership Inference Attack")

        # New 2025 OWASP categories if anomaly findings include adversarial suffixes
        if any(getattr(f, 'anomaly_type', '') == 'adversarial_suffix' for f in anomaly_findings):
            owasp.add("LLM01:2025 Adversarial Suffix / Optimization-Based Injection")
            mitre.add("AML.T0043 Craft Adversarial Data")

        self.report = SecurityReport(
            scan_timestamp=datetime.now().isoformat(),
            conversation_count=len(conversations),
            message_count=total_msgs,
            overall_risk_level=risk_level,
            risk_score=risk_score,
            prompt_injection_findings=len(injection_findings),
            pii_findings=len(pii_findings),
            anomaly_findings=len(anomaly_findings),
            advertising_findings=len(advertising_findings),
            image_findings=len(image_findings),
            membership_findings=len(membership_findings),
            findings_detail=findings_detail,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            per_conversation_risk=per_conv,
            export_evidence=export_evidence,
            recommendations=recommendations,
            owasp_coverage=sorted(owasp),
            mitre_coverage=sorted(mitre)
        )
        
        return self.report

    @staticmethod
    def _export_evidence(conversations: list) -> Dict[str, Any]:
        """Summarize what telemetry exists in the exported conversations.json."""
        role_counts = {"user": 0, "assistant": 0, "tool": 0, "system": 0, "other": 0}
        tool_names = Counter()
        content_types = Counter()
        has_citations = False

        for conv in conversations:
            for m in conv.messages:
                r = getattr(m, "role", None) or "other"
                if r not in role_counts:
                    role_counts["other"] += 1
                else:
                    role_counts[r] += 1

                ct = getattr(m, "content_type", None) or ""
                if ct:
                    content_types[ct] += 1

                if r == "tool":
                    name = getattr(m, "author_name", None) or ""
                    if name:
                        tool_names[name] += 1

                meta = getattr(m, "metadata", None) or {}
                if isinstance(meta, dict) and "citations" in meta:
                    has_citations = True

        top_tools = [n for n, _ in tool_names.most_common(10)]
        top_ct = [n for n, _ in content_types.most_common(12)]

        return {
            "roles": role_counts,
            "tool_calls_present": role_counts.get("tool", 0) > 0,
            "top_tool_names": top_tools,
            "browsing_traces_present": content_types.get("tether_browsing_display", 0) > 0 or content_types.get("tether_quote", 0) > 0,
            "content_types_top": top_ct,
            "citations_present": bool(has_citations),
        }

    def _per_conversation_risk(self, conversations, inj, pii, anomaly, adv, mem) -> List[Dict]:
        """Compute a brief risk summary per conversation."""
        conv_map: Dict[str, Dict] = {c.id: {"id": c.id, "title": c.title,
                                             "critical": 0, "high": 0,
                                             "medium": 0, "low": 0} for c in conversations}
        for f in inj + pii + anomaly + adv + mem:
            cid = getattr(f, 'conversation_id', None)
            sev = getattr(f, 'severity', 'LOW')
            if cid and cid in conv_map:
                conv_map[cid][sev.lower()] = conv_map[cid].get(sev.lower(), 0) + 1

        result = []
        for entry in conv_map.values():
            total = entry['critical'] + entry['high'] + entry['medium'] + entry['low']
            if total == 0:
                risk = "CLEAN"
            elif entry['critical'] > 0:
                risk = "CRITICAL"
            elif entry['high'] > 0:
                risk = "HIGH"
            elif entry['medium'] > 0:
                risk = "MEDIUM"
            else:
                risk = "LOW"
            result.append({**entry, "risk": risk, "total_findings": total})

        return sorted(result, key=lambda x: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4}.get(x["risk"], 5)
        ))
    
    def print_console_report(self, report: SecurityReport):
        """Print a formatted console report."""
        risk_colors = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }
        
        risk_icon = risk_colors.get(report.overall_risk_level, "⚪")
        
        print("\n" + "=" * 70)
        print("  🛡️  AI SECURITY ANALYZER - CONVERSATION SECURITY REPORT")
        print("=" * 70)
        print(f"\n  📅 Scan Time:      {report.scan_timestamp}")
        print(f"  💬 Conversations:  {report.conversation_count}")
        print(f"  📝 Messages:       {report.message_count}")

        if report.export_evidence:
            ev = report.export_evidence
            roles = ev.get("roles") or {}
            tool = roles.get("tool", 0)
            system = roles.get("system", 0)
            browsing = "yes" if ev.get("browsing_traces_present") else "no"
            citations = "yes" if ev.get("citations_present") else "no"
            print(f"  🧾 Export Evidence: tool_msgs={tool}, system_msgs={system}, browsing={browsing}, citations={citations}")
            top_tools = ev.get("top_tool_names") or []
            if top_tools:
                print(f"  🧰 Top tools: {', '.join(top_tools[:6])}{' ...' if len(top_tools)>6 else ''}")
        print(f"\n  {risk_icon} OVERALL RISK:     {report.overall_risk_level} (Score: {report.risk_score}/100)")
        
        print(f"\n{'─' * 70}")
        print("  📊 FINDINGS SUMMARY")
        print(f"{'─' * 70}")
        print(f"  🔴 Critical: {report.critical_count}   🟠 High: {report.high_count}   🟡 Medium: {report.medium_count}   🟢 Low: {report.low_count}")
        
        print(f"\n  🎯 Prompt Injection:  {report.prompt_injection_findings} findings")
        print(f"  🔒 PII Leakage:      {report.pii_findings} findings")
        print(f"  📈 Anomalies:        {report.anomaly_findings} findings")
        print(f"  📢 Advertising:      {report.advertising_findings} findings")
        if report.image_findings:
            print(f"  🖼️  Image Issues:     {report.image_findings} findings")
        if report.membership_findings:
            print(f"  🧬 Membership Inf.:  {report.membership_findings} findings")

        # Per-conversation risk table
        if report.per_conversation_risk:
            flagged = [c for c in report.per_conversation_risk if c.get("risk") not in ("CLEAN", "LOW")]
            if flagged:
                print(f"\n{'─' * 70}")
                print("  🗂️  PER-CONVERSATION RISK")
                print(f"{'─' * 70}")
                for c in flagged[:8]:
                    icon = risk_colors.get(c["risk"], "⚪")
                    title = c.get("title", c["id"])[:40]
                    print(f"  {icon} [{c['risk']:8s}] {title}  "
                          f"(C:{c['critical']} H:{c['high']} M:{c['medium']} L:{c['low']})")
        
        # Print detailed findings
        if report.findings_detail:
            for category, findings in report.findings_detail.items():
                if findings:
                    print(f"\n{'─' * 70}")
                    icon = {"prompt_injection": "🎯", "pii_leakage": "🔒", 
                            "anomalies": "📈", "advertising": "📢", "images": "🖼️"}.get(category, "📋")
                    print(f"  {icon} {category.upper().replace('_', ' ')} DETAILS")
                    print(f"{'─' * 70}")
                    
                    for i, f in enumerate(findings[:10], 1):  # Limit to 10 per category
                        sev = f.get("severity", "?")
                        sev_icon = risk_colors.get(sev, "⚪")
                        
                        if category == "prompt_injection":
                            print(f"\n  {sev_icon} [{sev}] {f.get('injection_type', 'unknown')}")
                            print(f"     Layer: {f.get('detection_layer', '?')} | Confidence: {f.get('confidence', 0):.0%}")
                            print(f"     Pattern: {f.get('matched_pattern', '?')[:65]}")
                            print(f"     Conv: {f.get('conversation_id', '?')}")
                        
                        elif category == "pii_leakage":
                            print(f"\n  {sev_icon} [{sev}] {f.get('category', 'unknown')}")
                            print(f"     Redacted: {f.get('matched_value', '?')}")
                            print(f"     {f.get('recommendation', '')}")
                        
                        elif category == "anomalies":
                            print(f"\n  {sev_icon} [{sev}] {f.get('anomaly_type', 'unknown')}")
                            print(f"     {f.get('details', '')[:70]}")
                        
                        elif category == "advertising":
                            print(f"\n  {sev_icon} [{sev}] {f.get('finding_type', 'unknown')}")
                            print(f"     {f.get('details', '')[:70]}")
                            indicators = f.get('indicators', [])
                            if indicators:
                                print(f"     Indicators: {', '.join(indicators[:3])}")

                        elif category == "membership_inference":
                            print(f"\n  {sev_icon} [{sev}] {f.get('finding_type', 'unknown')}")
                            print(f"     {f.get('details', '')[:80]}")
                            print(f"     Score: {f.get('metric_value', 0):.3f}")
        
        # Recommendations
        if report.recommendations:
            print(f"\n{'─' * 70}")
            print("  💡 RECOMMENDATIONS")
            print(f"{'─' * 70}")
            for i, rec in enumerate(report.recommendations, 1):
                print(f"  {i}. {rec}")
        
        # OWASP/MITRE coverage
        if report.owasp_coverage or report.mitre_coverage:
            print(f"\n{'─' * 70}")
            print("  📚 SECURITY FRAMEWORK MAPPINGS")
            print(f"{'─' * 70}")
            if report.owasp_coverage:
                print("  OWASP Top 10 for LLMs 2025:")
                for ref in report.owasp_coverage:
                    print(f"    • {ref}")
            if report.mitre_coverage:
                print("  MITRE ATLAS:")
                for ref in report.mitre_coverage:
                    print(f"    • {ref}")
        
        print(f"\n{'=' * 70}")
        print("  Report generated by AI Security Analyzer v0.1.0")
        print(f"{'=' * 70}\n")
    
    def save_json_report(self, report: SecurityReport, filepath: str):
        """Save report as JSON file."""
        report_dict = {
            "scan_timestamp": report.scan_timestamp,
            "conversation_count": report.conversation_count,
            "message_count": report.message_count,
            "overall_risk_level": report.overall_risk_level,
            "risk_score": report.risk_score,
            "summary": {
                "prompt_injection": report.prompt_injection_findings,
                "pii_leakage": report.pii_findings,
                "anomalies": report.anomaly_findings,
                "advertising": report.advertising_findings,
                "images": report.image_findings,
                "membership_inference": report.membership_findings,
            },
            "per_conversation_risk": report.per_conversation_risk or [],
            "export_evidence": report.export_evidence or {},
            "severity_breakdown": {
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
            },
            "findings": report.findings_detail,
            "recommendations": report.recommendations,
            "framework_mappings": {
                "owasp_top10_llm_2025": report.owasp_coverage,
                "mitre_atlas": report.mitre_coverage,
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        
        print(f"  📄 JSON report saved: {filepath}")
    
    def _generate_recommendations(self, injection, pii, anomaly, advertising, images, membership=None) -> List[str]:
        """Generate actionable recommendations based on findings."""
        recs = []
        
        # Critical credentials
        cred_findings = [f for f in pii if f.is_credential]
        if cred_findings:
            recs.append("URGENT: Rotate ALL exposed API keys, passwords, and tokens immediately. Check each service's console.")
        
        # PII
        personal_pii = [f for f in pii if f.category.value in {"email", "phone", "ssn", "credit_card"}]
        if personal_pii:
            recs.append("Delete conversations containing personal information (SSN, credit cards, phone numbers).")
        
        # Injection attempts
        if injection:
            critical_inj = [f for f in injection if f.severity in {"CRITICAL", "HIGH"}]
            if critical_inj:
                recs.append("Review flagged prompt injection attempts. Some may indicate social engineering or security testing.")
        
        # Advertising
        if advertising:
            recs.append("Review AI responses flagged for promotional content. Consider using a different model or adjusting system prompts.")
        
        # Membership inference
        membership = membership or []
        canaries = [f for f in membership if getattr(f, 'finding_type', '') == 'canary_detected']
        if canaries:
            recs.append("Canary tokens detected in your conversations — your data may have been used in membership inference research.")
        mem_suspects = [f for f in membership if getattr(f, 'finding_type', '') == 'min_k_prob_suspect']
        if mem_suspects:
            recs.append(f"{len(mem_suspects)} message(s) show statistical signatures of potentially memorised training data. Review with OpenAI's privacy tools.")

        # Sneaking / dark patterns
        sneaking = [f for f in advertising if getattr(f, 'finding_type', '') == 'sneaking']
        if sneaking:
            recs.append("AI responses show 'sneaking' patterns (silently altering your intent) — review responses carefully and rephrase requests when results differ from expectations.")

        # General
        if not recs:
            recs.append("No critical issues found. Continue monitoring your conversation history regularly.")

        recs.append("Enable ChatGPT's 'Temporary Chat' mode for sensitive conversations.")
        recs.append("Regularly export and review your data via Settings → Data Controls → Export.")
        recs.append("Consider disabling 'Improve the model for everyone' in ChatGPT settings.")
        
        return recs
    
    @staticmethod
    def _serialize_injection(f) -> Dict:
        return {
            "message_id": f.message_id,
            "conversation_id": f.conversation_id,
            "injection_type": f.injection_type.value,
            "confidence": round(f.confidence, 3),
            "severity": f.severity,
            "detection_layer": f.detection_layer,
            "matched_pattern": f.matched_pattern,
            "message_preview": f.message_preview[:100],
            "owasp_ref": f.owasp_ref,
            "mitre_ref": f.mitre_ref,
        }
    
    @staticmethod
    def _serialize_pii(f) -> Dict:
        return {
            "message_id": f.message_id,
            "conversation_id": f.conversation_id,
            "category": f.category.value,
            "severity": f.severity,
            "confidence": round(f.confidence, 3),
            "matched_value": f.matched_value,
            "recommendation": f.recommendation,
            "is_credential": f.is_credential,
        }
    
    @staticmethod
    def _serialize_anomaly(f) -> Dict:
        return {
            "message_id": f.message_id,
            "conversation_id": f.conversation_id,
            "anomaly_type": f.anomaly_type,
            "severity": f.severity,
            "confidence": round(f.confidence, 3),
            "details": f.details,
            "metric_value": round(f.metric_value, 3),
            "threshold": f.threshold,
        }
    
    @staticmethod
    def _serialize_advertising(f) -> Dict:
        return {
            "message_id": f.message_id,
            "conversation_id": f.conversation_id,
            "finding_type": f.finding_type,
            "severity": f.severity,
            "confidence": round(f.confidence, 3),
            "details": f.details,
            "indicators": f.indicators[:5],
        }
    
    @staticmethod
    def _serialize_image(f) -> Dict:
        return {
            "filename": f.filename,
            "finding_type": f.finding_type,
            "severity": f.severity,
            "confidence": round(f.confidence, 3),
            "details": f.details,
            "metadata": {k: str(v)[:100] for k, v in f.metadata.items()},
        }

    @staticmethod
    def _serialize_membership(f) -> Dict:
        return {
            "message_id": f.message_id,
            "conversation_id": f.conversation_id,
            "finding_type": f.finding_type,
            "severity": f.severity,
            "confidence": round(f.confidence, 3),
            "details": f.details,
            "metric_value": round(f.metric_value, 4),
            "owasp_ref": f.owasp_ref,
            "mitre_ref": f.mitre_ref,
        }
