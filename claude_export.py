"""
Claude Conversation Export Parser
Parses conversations.json from Claude's data export (claude.ai → Settings → Export Data).

Claude export format (per conversation):
  {
    "uuid": "...",
    "name": "Conversation Title",
    "summary": "",
    "created_at": "2025-03-15T22:19:51.206484Z",
    "updated_at": "2025-03-22T10:28:27.312016Z",
    "account": {"uuid": "..."},
    "chat_messages": [
      {
        "uuid": "...",
        "text": "message text",
        "content": [
          {"start_timestamp": "...", "stop_timestamp": "...",
           "type": "text", "text": "message text", "citations": []}
        ],
        "sender": "human",   # "human" or "assistant"
        "created_at": "...",
        "updated_at": "...",
        "attachments": [],
        "files": []
      }
    ]
  }
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional

from chatgpt_export import Message, Conversation


def _parse_iso(ts: Optional[str]) -> Optional[float]:
    """Convert an ISO-8601 timestamp string to a Unix float, or None.
    Works with stdlib only — handles the trailing 'Z' that Python < 3.11
    fromisoformat() rejects.
    """
    if not ts:
        return None
    try:
        # Replace 'Z' with '+00:00' for universal fromisoformat() compat
        normalized = ts.rstrip("Z") + "+00:00" if ts.endswith("Z") else ts
        return datetime.fromisoformat(normalized).timestamp()
    except Exception:
        return None


class ClaudeExportParser:
    """
    Parses Claude data export conversations.json.

    Returns the same Conversation / Message dataclass objects used by
    ChatGPTExportParser so the rest of the pipeline is unchanged.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.conversations: List[Conversation] = []
        self._raw_data = None

    def parse(self) -> List[Conversation]:
        """Parse the file and return a list of Conversation objects."""
        import json
        with open(self.filepath, "r", encoding="utf-8") as f:
            self._raw_data = json.load(f)

        self.conversations = []
        for conv_data in self._raw_data:
            conv = self._parse_conversation(conv_data)
            if conv and conv.messages:
                self.conversations.append(conv)

        return self.conversations

    def _parse_conversation(self, data: dict) -> Optional[Conversation]:
        chat_messages = data.get("chat_messages", [])
        if not chat_messages:
            return None

        messages = []
        for cm in chat_messages:
            msg = self._parse_message(cm)
            if msg:
                messages.append(msg)

        conv = Conversation(
            id=data.get("uuid", "unknown"),
            title=data.get("name", "Untitled"),
            create_time=_parse_iso(data.get("created_at")),
            update_time=_parse_iso(data.get("updated_at")),
            messages=messages,
        )
        return conv

    def _parse_message(self, cm: dict) -> Optional[Message]:
        sender = cm.get("sender", "")
        # Claude uses "human" for user messages
        role = "user" if sender == "human" else "assistant"

        # Prefer the top-level "text" field; fall back to content blocks
        text = cm.get("text", "") or ""
        if not text.strip():
            content_blocks = cm.get("content", [])
            parts = [
                block.get("text", "")
                for block in content_blocks
                if isinstance(block, dict) and block.get("type") == "text"
            ]
            text = "\n".join(p for p in parts if p.strip())

        # Skip empty messages (e.g., tool stubs without text)
        if not text.strip():
            return None

        timestamp = _parse_iso(cm.get("created_at"))

        has_image = bool(cm.get("attachments") or cm.get("files"))

        return Message(
            id=cm.get("uuid", "unknown"),
            role=role,
            content=text,
            content_type="text",
            timestamp=timestamp,
            model_slug=None,          # Claude export doesn't include model slug
            author_name=None,
            has_image=has_image,
            raw_parts=[],
            raw_content={},
            metadata={},
        )

    def get_stats(self) -> dict:
        """Return summary statistics (mirrors ChatGPTExportParser.get_stats)."""
        if not self.conversations:
            return {}
        total_msgs = sum(len(c.messages) for c in self.conversations)
        return {
            "total_conversations": len(self.conversations),
            "total_messages": total_msgs,
            "user_messages": sum(len(c.user_messages) for c in self.conversations),
            "assistant_messages": sum(
                len(c.assistant_messages) for c in self.conversations
            ),
        }


def detect_format(filepath: str) -> str:
    """
    Inspect the first conversation entry and return:
      'claude'  — Claude data export (has 'chat_messages' + 'uuid')
      'chatgpt' — ChatGPT data export (has 'mapping' + 'current_node')
      'unknown' — neither pattern matched
    """
    import json
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list) or not data:
        return "unknown"

    first = data[0]
    if isinstance(first, dict):
        if "chat_messages" in first and "uuid" in first:
            return "claude"
        if "mapping" in first or "current_node" in first:
            return "chatgpt"

    return "unknown"
