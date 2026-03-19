"""
Format dispatcher — single entry point for all LLM export formats.

Usage:
    fmt, convs, msgs, traces = detect_and_parse("/path/to/file.zip")
    fmt, convs, msgs, traces = detect_and_parse("/path/to/claude_export.json")

Supported formats:
  - ChatGPT ZIP export  (.zip containing conversations.json)
  - ChatGPT JSON export (.json with "mapping" key)
  - Claude JSON export  (.json with "chat_messages" key)
"""

import json
import os
import tempfile
import zipfile
from typing import List, Tuple
from model import Conversation, Message, ToolTrace


def detect_and_parse(
    file_path: str,
    out_dir: str = None,
) -> Tuple[str, List[Conversation], List[Message], List[ToolTrace]]:
    """
    Auto-detect export format and parse to unified lists.

    Returns:
        (format_name, conversations, messages, traces)
        format_name: "chatgpt" | "claude"
    """
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    if ext == ".zip":
        return _handle_chatgpt_zip(file_path, out_dir)

    if ext == ".json":
        return _handle_json_file(file_path)

    raise ValueError(
        f"Unsupported file type '{ext}'. "
        "Please upload a ChatGPT ZIP export or a Claude JSON export."
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sniff_zip_format(zip_path: str, out_dir: str) -> tuple:
    """
    Return (conv_json_path, fmt) where fmt is "claude" or "chatgpt".
    Extracts conversations.json to a temp dir if out_dir doesn't have it.
    """
    # Prefer already-extracted out_dir
    if out_dir and os.path.exists(out_dir):
        conv_json = os.path.join(out_dir, "conversations.json")
        if os.path.exists(conv_json):
            return conv_json, _sniff_json_format(conv_json)

    # Peek inside the ZIP
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        conv_name = next((n for n in names if n.endswith("conversations.json")), None)
        if not conv_name:
            raise ValueError(
                "No conversations.json found inside the ZIP. "
                "Please upload a ChatGPT or Claude data export ZIP."
            )
        tmp = tempfile.mkdtemp()
        zf.extract(conv_name, tmp)
        conv_path = os.path.join(tmp, conv_name)
        return conv_path, _sniff_json_format(conv_path)


def _sniff_json_format(json_path: str) -> str:
    """
    Read the first conversation object and return "claude" or "chatgpt".

    Claude signals  : has 'chat_messages', OR has 'uuid' + 'sender' in messages
    ChatGPT signals : has 'mapping' key (tree structure)
    """
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return "chatgpt"  # fallback

    if isinstance(data, dict):
        for k in ("conversations", "data", "chats"):
            if k in data and isinstance(data[k], list):
                data = data[k]
                break
        else:
            data = [data]

    if not isinstance(data, list) or not data:
        return "chatgpt"

    first = data[0] if isinstance(data[0], dict) else {}

    # Claude: explicit chat_messages array
    if "chat_messages" in first:
        return "claude"

    # Claude: uuid present, no mapping (tree structure), has sender in nested msgs
    if "uuid" in first and "mapping" not in first:
        msgs_sample = first.get("messages", first.get("chat_messages", []))
        if any(isinstance(m, dict) and "sender" in m for m in msgs_sample[:3]):
            return "claude"
        # Even without messages sample, uuid + no mapping = likely Claude
        return "claude"

    # ChatGPT: unique tree-based mapping key
    if "mapping" in first:
        return "chatgpt"

    return "chatgpt"


def _handle_chatgpt_zip(zip_path: str, out_dir: str) -> Tuple[str, List[Conversation], List[Message], List[ToolTrace]]:
    """Extract ZIP, sniff format, then dispatch to the correct parser."""
    conv_path, fmt = _sniff_zip_format(zip_path, out_dir)

    if fmt == "claude":
        from extractors.claude_parser import parse_claude_json
        convs, msgs, traces = parse_claude_json(conv_path)
        return "claude", convs, msgs, traces

    from extractors.json_html import parse_conversations_json
    convs, msgs, traces = parse_conversations_json(conv_path)
    return "chatgpt", convs, msgs, traces


def _handle_json_file(json_path: str) -> Tuple[str, List[Conversation], List[Message], List[ToolTrace]]:
    """
    Inspect JSON structure to route to the correct parser.

    Detection strategy (most-specific first):
      Claude   → has 'chat_messages' key at conv level, OR 'sender' field in messages
                 OR wrapped in {"conversations": [...]} with 'chat_messages' inside
      ChatGPT  → has 'mapping' key (unique tree structure) at conv level
    """
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise ValueError(f"Could not read JSON file: {e}")

    # ---- Handle wrapper dicts (e.g. {"conversations": [...], "account": {...}}) ----
    if isinstance(data, dict):
        # Try common wrapper keys
        for wrapper_key in ("conversations", "data", "chats"):
            if wrapper_key in data and isinstance(data[wrapper_key], list):
                data = data[wrapper_key]
                break
        else:
            # Single-conversation dict — wrap it
            data = [data]

    if not isinstance(data, list) or not data:
        raise ValueError("Empty or unrecognised JSON structure.")

    first = data[0] if isinstance(data[0], dict) else {}

    # ---- Claude detection (check most specific signals) ----------------------
    # Signal 1: conversations have 'chat_messages'
    if "chat_messages" in first:
        from extractors.claude_parser import parse_claude_json
        convs, msgs, traces = parse_claude_json(json_path)
        return "claude", convs, msgs, traces

    # Signal 2: 'sender' field (Claude uses "human"/"assistant", not "role")
    messages_sample = first.get("messages", first.get("chat_messages", []))
    if not messages_sample and isinstance(first.get("uuid"), str):
        # Look one level deeper if top-level has uuid but no messages yet
        pass
    if any(
        isinstance(m, dict) and "sender" in m
        for item in data[:5]
        for m in item.get("chat_messages", item.get("messages", []))[:3]
    ):
        from extractors.claude_parser import parse_claude_json
        convs, msgs, traces = parse_claude_json(json_path)
        return "claude", convs, msgs, traces

    # Signal 3: Claude-specific top-level fields (uuid + no mapping)
    has_claude_uuid = "uuid" in first and "mapping" not in first
    has_claude_name = "name" in first or "title" not in first
    if has_claude_uuid and has_claude_name and "chat_messages" not in first:
        # Could be a Claude export where chat_messages is present but empty, or
        # a newer format — try Claude parser; it handles empty chats gracefully
        from extractors.claude_parser import parse_claude_json
        convs, msgs, traces = parse_claude_json(json_path)
        if convs:  # if we got conversations, it parsed successfully
            return "claude", convs, msgs, traces

    # ---- ChatGPT detection (requires 'mapping' — the unique tree structure) --
    if "mapping" in first:
        from extractors.json_html import parse_conversations_json
        convs, msgs, traces = parse_conversations_json(json_path)
        return "chatgpt", convs, msgs, traces

    # ---- Last resort: try both and return whichever yields more messages -----
    try:
        from extractors.claude_parser import parse_claude_json
        c_convs, c_msgs, c_traces = parse_claude_json(json_path)
        if c_msgs:
            return "claude", c_convs, c_msgs, c_traces
    except Exception:
        pass

    try:
        from extractors.json_html import parse_conversations_json
        g_convs, g_msgs, g_traces = parse_conversations_json(json_path)
        if g_msgs:
            return "chatgpt", g_convs, g_msgs, g_traces
    except Exception:
        pass

    raise ValueError(
        "Could not identify the export format. "
        "Expected a ChatGPT export (contains 'mapping' key) "
        "or a Claude export (contains 'chat_messages' key). "
        "Please check the file is a valid AI chat export."
    )
