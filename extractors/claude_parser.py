import json
import os
from typing import List, Tuple
from datetime import datetime, timezone
from model import Conversation, Message, ToolTrace


def _parse_timestamp(ts_str: str) -> float:
    """Parse ISO 8601 timestamp to Unix epoch."""
    if not ts_str:
        return 0.0
    try:
        # Handle both 'Z' suffix and '+00:00' offset
        normalized = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).timestamp()
    except Exception:
        return 0.0


def parse_claude_json(file_path: str) -> Tuple[List[Conversation], List[Message], List[ToolTrace]]:
    """
    Parses a Claude JSON export into unified Conversation, Message, and ToolTrace lists.

    Claude export structure:
    [
      {
        "uuid": "conv-uuid",
        "name": "Conversation Title",
        "chat_messages": [
          {
            "uuid": "msg-uuid",
            "text": "message content",
            "sender": "human" | "assistant",
            "created_at": "2024-01-01T00:00:00.000Z",
            "updated_at": "2024-01-01T00:00:00.000Z",
            "attachments": [
              {
                "file_name": "file.pdf",
                "extracted_content": "text content..."
              }
            ]
          }
        ]
      }
    ]
    """
    conversations: List[Conversation] = []
    messages: List[Message] = []
    traces: List[ToolTrace] = []

    if not os.path.exists(file_path):
        return conversations, messages, traces

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[Claude Parser] Error reading file: {e}")
        return conversations, messages, traces

    # Handle wrapper dicts: {"conversations": [...], "account": {...}}
    if isinstance(data, dict):
        for wrapper_key in ("conversations", "data", "chats"):
            if wrapper_key in data and isinstance(data[wrapper_key], list):
                data = data[wrapper_key]
                break
        else:
            # Single conversation object — wrap in list
            data = [data]

    if not isinstance(data, list):
        print("[Claude Parser] Unexpected top-level structure (not a list or dict)")
        return conversations, messages, traces

    for conv_data in data:
        if not isinstance(conv_data, dict):
            continue

        conv_id = conv_data.get("uuid", f"conv_{len(conversations)}")
        title = conv_data.get("name", "Untitled Conversation")
        chat_messages = conv_data.get("chat_messages", [])

        # Infer timestamps from messages if available
        create_time = 0.0
        update_time = 0.0
        if chat_messages:
            create_time = _parse_timestamp(chat_messages[0].get("created_at", ""))
            update_time = _parse_timestamp(chat_messages[-1].get("updated_at", ""))

        conv = Conversation(
            id=conv_id,
            title=title,
            timestamps={"create": create_time, "update": update_time},
        )
        conversations.append(conv)

        for idx, msg_data in enumerate(chat_messages):
            if not isinstance(msg_data, dict):
                continue

            sender = msg_data.get("sender", "unknown")
            # Claude uses "human" and "assistant"; normalize to tool-standard roles
            role = "user" if sender == "human" else "assistant" if sender == "assistant" else sender

            content = msg_data.get("text", "") or ""

            # Append extracted attachment content inline
            for att in msg_data.get("attachments", []):
                extracted = att.get("extracted_content", "")
                fname = att.get("file_name", "attachment")
                if extracted:
                    content += f"\n\n[Attached file: {fname}]\n{extracted}"

            msg_id = msg_data.get("uuid", f"{conv_id}_msg_{idx}")
            time_val = _parse_timestamp(msg_data.get("created_at", ""))

            msg = Message(
                id=msg_id,
                conversation_id=conv_id,
                index=idx,
                role=role,
                content=content,
                time=time_val if time_val else None,
            )
            messages.append(msg)

    return conversations, messages, traces
