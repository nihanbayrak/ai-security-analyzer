"""
ChatGPT Conversation Export Parser
Parses the tree-based conversations.json from ChatGPT data export.
Handles branching conversations, extracts metadata, and flattens to linear format.
"""

import json
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


@dataclass
class Message:
    """Represents a single message in a conversation."""
    id: str
    role: str  # user, assistant, system, tool
    content: str
    content_type: str  # text, multimodal_text, code, execution_output
    timestamp: Optional[float] = None
    model_slug: Optional[str] = None
    author_name: Optional[str] = None  # dalle.text2im, browser, python
    has_image: bool = False
    raw_parts: List[Any] = field(default_factory=list)
    raw_content: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def datetime(self) -> Optional[datetime]:
        if self.timestamp:
            return datetime.fromtimestamp(self.timestamp)
        return None

    @property
    def word_count(self) -> int:
        return len(self.content.split())


@dataclass
class Conversation:
    """Represents a full conversation with metadata."""
    id: str
    title: str
    create_time: Optional[float]
    update_time: Optional[float]
    messages: List[Message] = field(default_factory=list)
    
    @property
    def create_datetime(self) -> Optional[datetime]:
        if self.create_time:
            return datetime.fromtimestamp(self.create_time)
        return None
    
    @property
    def duration_seconds(self) -> Optional[float]:
        if self.messages and len(self.messages) >= 2:
            first = self.messages[0].timestamp
            last = self.messages[-1].timestamp
            if first and last:
                return last - first
        return None

    @property
    def user_messages(self) -> List[Message]:
        return [m for m in self.messages if m.role == "user"]

    @property
    def assistant_messages(self) -> List[Message]:
        return [m for m in self.messages if m.role == "assistant"]

    @property
    def models_used(self) -> set:
        return {m.model_slug for m in self.messages if m.model_slug}


class ChatGPTExportParser:
    """
    Parses ChatGPT data export conversations.json.
    
    The export uses a tree structure (mapping) where each message node
    has parent/children references. This parser traverses the tree
    from current_node backward to reconstruct linear conversation flow.
    """
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.conversations: List[Conversation] = []
        self._raw_data = None
    
    def parse(self) -> List[Conversation]:
        """Parse the conversations.json file and return list of Conversations."""
        with open(self.filepath, 'r', encoding='utf-8') as f:
            self._raw_data = json.load(f)
        
        self.conversations = []
        for conv_data in self._raw_data:
            conv = self._parse_conversation(conv_data)
            if conv and conv.messages:
                self.conversations.append(conv)
        
        return self.conversations
    
    def _parse_conversation(self, data: dict) -> Optional[Conversation]:
        """Parse a single conversation from the export data."""
        mapping = data.get("mapping", {})
        current_node = data.get("current_node")
        
        if not mapping:
            return None
        
        # Traverse tree from current_node backward via parent links
        messages = self._traverse_tree(mapping, current_node)
        
        conv = Conversation(
            id=data.get("conversation_id", "unknown"),
            title=data.get("title", "Untitled"),
            create_time=data.get("create_time"),
            update_time=data.get("update_time"),
            messages=messages
        )
        return conv
    
    def _traverse_tree(self, mapping: dict, current_node: Optional[str]) -> List[Message]:
        """
        Traverse the conversation tree backward from current_node.
        Returns messages in chronological order.
        """
        if not current_node or current_node not in mapping:
            # Fallback: collect all messages sorted by timestamp
            return self._fallback_collect(mapping)
        
        messages = []
        node_id = current_node
        visited = set()
        
        while node_id and node_id in mapping and node_id not in visited:
            visited.add(node_id)
            node = mapping[node_id]
            msg = self._extract_message(node)
            if msg:
                # Many real exports contain tool/browsing records whose useful
                # payload lives in metadata or non-`parts` content fields. Keep
                # tool/system messages even if `content` is sparse.
                if msg.content.strip() or msg.role in ("tool", "system"):
                    messages.append(msg)
            node_id = node.get("parent")
        
        messages.reverse()  # Chronological order
        return messages
    
    def _fallback_collect(self, mapping: dict) -> List[Message]:
        """Fallback: collect all messages and sort by timestamp."""
        messages = []
        for node in mapping.values():
            msg = self._extract_message(node)
            if msg:
                if msg.content.strip() or msg.role in ("tool", "system"):
                    messages.append(msg)
        messages.sort(key=lambda m: m.timestamp or 0)
        return messages
    
    def _extract_message(self, node: dict) -> Optional[Message]:
        """Extract a Message from a mapping node."""
        msg_data = node.get("message")
        if not msg_data:
            return None
        
        author = msg_data.get("author", {})
        content_data = msg_data.get("content", {}) or {}
        metadata = msg_data.get("metadata", {}) or {}
        
        # Extract text content from multiple export variants.
        #
        # Newer exports frequently store tool/browsing content in fields like:
        #   - content.text (execution_output)
        #   - content.summary / content.result / content.assets / content.tether_id (browsing + tools)
        # and omit content.parts entirely.
        parts = content_data.get("parts")
        text_parts: List[str] = []

        has_image = False
        if isinstance(metadata.get("attachments"), list) and metadata.get("attachments"):
            has_image = True

        if isinstance(parts, list):
            for part in parts:
                if isinstance(part, str):
                    text_parts.append(part)
                elif isinstance(part, dict):
                    # Multimodal content (images, etc.)
                    if part.get("content_type") == "image_asset_pointer":
                        has_image = True
                        text_parts.append("[IMAGE]")
                    elif "text" in part and isinstance(part["text"], str):
                        text_parts.append(part["text"])
                    else:
                        # Fallback: stringify compactly for preservation
                        text_parts.append(str(part))
        else:
            # Common alternative shape: single text field
            if isinstance(content_data.get("text"), str):
                text_parts.append(content_data["text"])

            # Browsing/tool result fields (often dict/list)
            for k in ("summary", "result"):
                if k in content_data:
                    v = content_data.get(k)
                    if isinstance(v, str) and v.strip():
                        text_parts.append(v)
                    elif v is not None:
                        text_parts.append(str(v))

            # Some tool records keep the actual command in metadata
            if isinstance(metadata.get("command"), str) and metadata["command"].strip():
                text_parts.append(f"[TOOL_COMMAND] {metadata['command']}")

        content = "\n".join([t for t in text_parts if isinstance(t, str) and t.strip()])
        
        # Keep tool/system messages even if content is sparse; metadata may still be valuable.
        return Message(
            id=msg_data.get("id", node.get("id", "unknown")),
            role=author.get("role", "unknown"),
            content=content,
            content_type=content_data.get("content_type", "text"),
            timestamp=msg_data.get("create_time"),
            model_slug=metadata.get("model_slug"),
            author_name=author.get("name"),
            has_image=has_image,
            raw_parts=parts if isinstance(parts, list) else [],
            raw_content=content_data,
            metadata=metadata
        )
    
    def get_stats(self) -> dict:
        """Return summary statistics of parsed conversations."""
        if not self.conversations:
            return {}
        
        total_msgs = sum(len(c.messages) for c in self.conversations)
        user_msgs = sum(len(c.user_messages) for c in self.conversations)
        assistant_msgs = sum(len(c.assistant_messages) for c in self.conversations)
        all_models = set()
        role_counts: Dict[str, int] = {"user": 0, "assistant": 0, "tool": 0, "system": 0, "other": 0}
        tool_names = set()
        content_types = set()
        for c in self.conversations:
            all_models.update(c.models_used)
            for m in c.messages:
                r = m.role or "other"
                if r not in role_counts:
                    role_counts["other"] += 1
                else:
                    role_counts[r] += 1
                if r == "tool" and m.author_name:
                    tool_names.add(m.author_name)
                if m.content_type:
                    content_types.add(m.content_type)
        
        return {
            "total_conversations": len(self.conversations),
            "total_messages": total_msgs,
            "user_messages": user_msgs,
            "assistant_messages": assistant_msgs,
            "models_used": list(all_models),
            "role_counts": role_counts,
            "tool_names": sorted(list(tool_names))[:50],
            "content_types": sorted(list(content_types))[:50],
            "date_range": {
                "earliest": min((c.create_time for c in self.conversations if c.create_time), default=None),
                "latest": max((c.update_time for c in self.conversations if c.update_time), default=None)
            }
        }


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample/conversations.json"
    parser = ChatGPTExportParser(path)
    convos = parser.parse()
    stats = parser.get_stats()
    print(f"\n📊 Export Stats:")
    print(f"   Conversations: {stats['total_conversations']}")
    print(f"   Total Messages: {stats['total_messages']}")
    print(f"   User Messages: {stats['user_messages']}")
    print(f"   Assistant Messages: {stats['assistant_messages']}")
    print(f"   Models Used: {', '.join(stats['models_used'])}")
    for conv in convos:
        print(f"\n💬 [{conv.id}] {conv.title}")
        for msg in conv.messages:
            preview = msg.content[:80].replace('\n', ' ')
            print(f"   {'👤' if msg.role == 'user' else '🤖'} {preview}...")
