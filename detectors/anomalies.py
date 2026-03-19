import math
from typing import List
from model import Finding, Severity, ProvenanceLocator, Conversation, Message

def shannon_entropy(data: str) -> float:
    if not data: return 0.0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def detect_anomalies(messages: List[Message], conv: Conversation) -> List[Finding]:
    """Detects message length z-score anomalies and high entropy."""
    findings = []
    
    if not messages: return findings
    
    lengths = [len(m.content) for m in messages if m.content]
    if not lengths: return findings
    
    mean_len = sum(lengths) / len(lengths)
    variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
    std_dev = math.sqrt(variance)
    
    for m in messages:
        # Z-score length anomaly
        if std_dev > 0:
            z_score = abs(len(m.content) - mean_len) / std_dev
            if z_score > 3:
                findings.append(Finding(
                    id="ANOM_LEN_01",
                    category="Anomalous Behavior",
                    framework_mapping="MITRE ATLAS",
                    severity=Severity.LOW,
                    score=30,
                    confidence=0.8,
                    evidence=f"Message length ({len(m.content)} chars) is {z_score:.1f} std devs above mean.",
                    provenance=ProvenanceLocator(conversation_id=conv.id, message_index=m.index, role=m.role),
                    recommended_action=["Review for context window stuffing or extraction payload"]
                ))
        
        # Entropy anomaly
        ent = shannon_entropy(m.content)
        if ent > 4.5:
             findings.append(Finding(
                id="ANOM_ENT_01",
                category="Anomalous Behavior",
                framework_mapping="MITRE ATLAS",
                severity=Severity.MEDIUM,
                score=50,
                confidence=0.7,
                evidence=f"High entropy message: {ent:.2f} bits/char",
                provenance=ProvenanceLocator(conversation_id=conv.id, message_index=m.index, role=m.role),
                recommended_action=["Review for encoded payload or encrypted data exfiltration"]
            ))

    return findings
