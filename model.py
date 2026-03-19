from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum

class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class Conversation:
    id: str
    title: str
    timestamps: Dict[str, Any] = field(default_factory=dict)
    language_stats: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Message:
    id: str
    conversation_id: str
    index: int
    role: str
    content: str
    time: Optional[float] = None
    tool_refs: List[str] = field(default_factory=list)
    attachment_refs: List[str] = field(default_factory=list)

@dataclass
class Attachment:
    id: str
    file_path: str
    type: str # mime_type or extracted extension
    sha256: str
    derived_text_sources: List[str] = field(default_factory=list) # e.g. ["exif", "ocr"]
    linked_messages: List[str] = field(default_factory=list) # message IDs

@dataclass
class ToolTrace:
    id: str
    tool_name: str
    args: Dict[str, Any]
    outputs: Any
    timestamps: Dict[str, Any] = field(default_factory=dict)
    linked_messages: List[str] = field(default_factory=list) # message IDs

@dataclass
class ProvenanceLocator:
    conversation_id: Optional[str] = None
    message_index: Optional[int] = None
    role: Optional[str] = None
    file_path: Optional[str] = None
    source_locator: Optional[str] = None # e.g., "Page 1", "EXIF.UserComment", "Line 42"

@dataclass
class Finding:
    id: str
    category: str
    framework_mapping: str # e.g., "OWASP LLM01:2025"
    severity: Severity
    score: int # 0-100
    confidence: float # 0.0 - 1.0
    evidence: str # snippet
    provenance: ProvenanceLocator
    recommended_action: List[str] = field(default_factory=list)
    safe_redaction: Optional[str] = None # masked evidence

@dataclass
class ManifestEntry:
    path: str
    sha256: str
    size: int
    mime_type: Optional[str]
    extracted_ok: bool
    reason_if_skipped: Optional[str]
