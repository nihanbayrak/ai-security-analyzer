#!/usr/bin/env python3
"""
🛡️ AI Security Analyzer v0.1.0
Analyze your ChatGPT conversation history for security threats.

Usage:
    python main.py /path/to/conversations.json
    python main.py /path/to/conversations.json --output report.json
    python main.py /path/to/conversations.json --no-transformer

Detects:
  🎯 Prompt Injection (OWASP LLM01:2025)
  🔒 PII & Credential Leakage (OWASP LLM06:2025)
  📈 Conversation Anomalies (MITRE ATLAS)
  📢 Advertising & Dark Patterns (DarkBench/ICLR 2025)
  🖼️ Image Metadata Risks
"""

import argparse

from chatgpt_export import ChatGPTExportParser
from prompt_injection import PromptInjectionDetector
from pii_detector import PIIDetector
from anomaly_detector import ConversationAnomalyDetector
from advertising_detector import AdvertisingDetector
from image_analyzer import ImageMetadataAnalyzer
from membership_inference import MembershipInferenceAnalyzer
from security_report import ReportGenerator


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🛡️  AI SECURITY ANALYZER v0.1.0                           ║
║   ChatGPT Conversation History Security Scanner              ║
║                                                              ║
║   Detects: Prompt Injection | PII Leakage | Anomalies        ║
║           Advertising/Bias | Image Metadata Risks            ║
║                                                              ║
║   OWASP Top 10 LLM 2025 | MITRE ATLAS Coverage              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ Scan ChatGPT conversations for security threats"
    )
    parser.add_argument(
        "conversations_file",
        help="Path to conversations.json OR the extracted ChatGPT export folder containing it"
    )
    parser.add_argument("--output", "-o", help="Save JSON report to file", default=None)
    parser.add_argument("--no-transformer", action="store_true", help="Skip ML model (regex-only, fast)")
    parser.add_argument("--use-presidio", action="store_true", help="Use Presidio for enhanced PII")
    
    parser.add_argument("--images-dir", help="Directory with exported images", default=None)
    parser.add_argument("--max-conversations", "-n", type=int, default=None)
    args = parser.parse_args()

    export_root = args.conversations_file
    if not os.path.exists(export_root):
        print(f"❌ File/folder not found: {export_root}")
        sys.exit(1)

    # Allow passing the extracted export folder (recommended) instead of the file
    if os.path.isdir(export_root):
        conv_path = os.path.join(export_root, "conversations.json")
        if not os.path.exists(conv_path):
            print(f"❌ conversations.json not found in folder: {export_root}")
            sys.exit(1)
    else:
        conv_path = export_root

    print_banner()

    # ═══════════════════════════════════════════════════════════
    # STEP 1: Parse ChatGPT Export
    # ═══════════════════════════════════════════════════════════
    print("📂 Step 1/7: Parsing ChatGPT export...")
    try:
        export_parser = ChatGPTExportParser(conv_path)
        conversations_all = export_parser.parse()
        stats_all = export_parser.get_stats()

        conversations = conversations_all
        if args.max_conversations:
            conversations = conversations_all[:args.max_conversations]
            # Recompute stats for the subset we will analyze
            export_parser.conversations = conversations
            stats = export_parser.get_stats()
            print(f"   ✅ Export: {stats_all['total_conversations']} conversations, {stats_all['total_messages']} messages")
            print(f"   🔎 Analyzing first {stats['total_conversations']} conversations ({stats['total_messages']} messages) due to --max-conversations")
        else:
            stats = stats_all
            print(f"   ✅ {stats['total_conversations']} conversations, {stats['total_messages']} messages")

        # Models can be very long in real exports; show first N.
        models = stats_all.get("models_used", []) or ["unknown"]
        print(f"   📋 Models (sample): {', '.join(models[:10])}{' ...' if len(models) > 10 else ''}")

        # Evidence should reflect the whole export (not just the subset),
        # so use stats_all for evidence signals.
        role_counts = stats_all.get("role_counts") or {}
        if role_counts:
            print(f"   🧾 Roles: user={role_counts.get('user',0)} assistant={role_counts.get('assistant',0)} tool={role_counts.get('tool',0)} system={role_counts.get('system',0)}")
        content_types = set(stats_all.get("content_types") or [])
        if {"tether_browsing_display", "tether_quote"} & content_types:
            print("   🌐 Evidence: browsing traces detected in export (tether_browsing_display/quote)")
        tool_names = stats_all.get("tool_names") or []
        if tool_names:
            print(f"   🧰 Tools seen: {', '.join(tool_names[:8])}{' ...' if len(tool_names)>8 else ''}")
    except Exception as e:
        print(f"   ❌ Parse failed: {e}")
        sys.exit(1)

    # ═══════════════════════════════════════════════════════════
    # STEP 2: Prompt Injection Detection
    # ═══════════════════════════════════════════════════════════
    print("\n🎯 Step 2/7: Scanning for prompt injection attacks...")
    inj_detector = PromptInjectionDetector(
        use_transformer=not args.no_transformer,
        use_perplexity=False
    )

    all_injection = []
    for conv in conversations:
        for msg in conv.user_messages:
            findings = inj_detector.analyze_message(msg.content, msg.id, conv.id)
            all_injection.extend(findings)
        # Multi-turn escalation
        escalation = inj_detector.detect_multi_turn_escalation(conv.messages)
        for f in escalation:
            f.conversation_id = conv.id
        all_injection.extend(escalation)

    # Deduplicate by (message_id, injection_type, layer) keeping highest confidence
    seen_keys = {}
    for f in all_injection:
        key = (f.message_id, f.injection_type, f.detection_layer)
        if key not in seen_keys or f.confidence > seen_keys[key].confidence:
            seen_keys[key] = f
    all_injection = list(seen_keys.values())

    crit_inj = sum(1 for f in all_injection if f.severity in ("CRITICAL", "HIGH"))
    print(f"   ✅ {len(all_injection)} findings ({crit_inj} critical/high)")

    # ═══════════════════════════════════════════════════════════
    # STEP 3: PII & Data Leakage Detection
    # ═══════════════════════════════════════════════════════════
    print("\n🔒 Step 3/7: Scanning for PII & credential leakage...")
    pii_detector = PIIDetector(use_presidio=args.use_presidio)

    all_pii = []
    for conv in conversations:
        for msg in conv.messages:
            findings = pii_detector.analyze_message(msg.content, msg.id, conv.id, msg.role)
            all_pii.extend(findings)

    cred_count = sum(1 for f in all_pii if f.is_credential)
    print(f"   ✅ {len(all_pii)} findings ({cred_count} credentials exposed)")

    # ═══════════════════════════════════════════════════════════
    # STEP 4: Anomaly Detection
    # ═══════════════════════════════════════════════════════════
    print("\n📈 Step 4/7: Analyzing conversation anomalies...")
    anomaly_detector = ConversationAnomalyDetector()

    all_anomalies = []
    for conv in conversations:
        findings = anomaly_detector.analyze_conversation(conv.messages, conv.id)
        all_anomalies.extend(findings)

    print(f"   ✅ {len(all_anomalies)} anomalies detected")

    # ═══════════════════════════════════════════════════════════
    # STEP 5: Advertising & Influence Detection
    # ═══════════════════════════════════════════════════════════
    print("\n📢 Step 5/7: Scanning for advertising & influence patterns...")
    ad_detector = AdvertisingDetector()

    all_advertising = []
    for conv in conversations:
        for msg in conv.assistant_messages:
            findings = ad_detector.analyze_message(msg.content, msg.id, conv.id, msg.role)
            all_advertising.extend(findings)

    print(f"   ✅ {len(all_advertising)} findings")

    # ═══════════════════════════════════════════════════════════
    # STEP 6: Image Analysis (if dir provided)
    # ═══════════════════════════════════════════════════════════
    print("\n🖼️  Step 6/7: Image metadata analysis...")
    img_analyzer = ImageMetadataAnalyzer()
    all_image_findings = []

    if args.images_dir and os.path.isdir(args.images_dir):
        all_image_findings = img_analyzer.analyze_conversation_images(args.images_dir)
        print(f"   ✅ {len(all_image_findings)} image findings")
    else:
        print("   ⏭️  No images directory provided (use --images-dir)")

    # ═══════════════════════════════════════════════════════════
    # STEP 7: Membership Inference
    # ═══════════════════════════════════════════════════════════
    print("\n🧬 Step 7/7: Membership inference analysis...")
    mi_analyzer = MembershipInferenceAnalyzer()
    all_membership = []

    for conv in conversations:
        findings = mi_analyzer.analyze_conversation(conv.messages, conv.id)
        all_membership.extend(findings)

    # Cross-conversation verbatim check
    all_membership.extend(mi_analyzer.cross_conversation_verbatim(conversations))
    print(f"   ✅ {len(all_membership)} membership inference findings")

    # ═══════════════════════════════════════════════════════════
    # GENERATE REPORT
    # ═══════════════════════════════════════════════════════════
    print("\n📊 Generating security report...")
    report_gen = ReportGenerator()
    report = report_gen.generate(
        conversations=conversations,
        injection_findings=all_injection,
        pii_findings=all_pii,
        anomaly_findings=all_anomalies,
        advertising_findings=all_advertising,
        image_findings=all_image_findings,
        membership_findings=all_membership
    )

    report_gen.print_console_report(report)

    if args.output:
        report_gen.save_json_report(report, args.output)
        print(f"\n📄 Full report saved to: {args.output}")

    return report


if __name__ == "__main__":
    main()
