import json
from typing import List, Dict, Any, Tuple
import os
from model import Conversation, Message, ToolTrace

def parse_conversations_json(file_path: str) -> Tuple[List[Conversation], List[Message], List[ToolTrace]]:
    """
    Robustly parses ChatGPT conversations.json and returns a list of Conversation, Message, and ToolTrace models.
    """
    conversations = []
    messages = []
    traces = []
    
    if not os.path.exists(file_path):
        return conversations, messages, traces

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error parsing json: {e}")
        return conversations, messages, traces

    if not isinstance(data, list):
        data = [data] # handle unexpected top-level dicts
        
    for conv_data in data:
        conv_id = conv_data.get("conversation_id") or conv_data.get("id", "unknown")
        title = conv_data.get("title", "Untitled")
        
        create_time = conv_data.get("create_time", 0)
        update_time = conv_data.get("update_time", 0)
        
        conv = Conversation(
            id=conv_id, 
            title=title, 
            timestamps={"create": create_time, "update": update_time}
        )
        conversations.append(conv)
        
        mapping = conv_data.get("mapping", {})
        idx = 0
        for node_id, node_data in mapping.items():
            if not isinstance(node_data, dict):
                continue
            message_data = node_data.get("message")
            if not message_data:
                continue
                
            author = message_data.get("author", {})
            role = author.get("role", "unknown")
            # Enrich tool roles with the tool's actual name so the UI can
            # display "AI Tool (Web Browser)" instead of the generic "Tool call"
            if role == "tool":
                tool_name = author.get("name", "")
                if tool_name:
                    role = f"tool:{tool_name}"
            
            content_data = message_data.get("content", {})
            content_type = content_data.get("content_type", "text")
            
            parts = content_data.get("parts", [])
            content_text = ""
            if parts and isinstance(parts, list):
                # Filter out dicts (like multi-modal image refs) and join strings
                text_parts = [str(p) for p in parts if isinstance(p, (str, int, float))]
                content_text = "\n".join(text_parts)
                
            msg_id = message_data.get("id", str(idx))
            time = message_data.get("create_time", None)
            
            msg = Message(
                id=msg_id,
                conversation_id=conv_id,
                index=idx,
                role=role,
                content=content_text,
                time=time
            )
            messages.append(msg)
            
            if role == "tool" or "tool" in content_type:
                tool_name = author.get("name", "unknown_tool")
                args = {}
                if isinstance(parts, list) and len(parts) > 0 and isinstance(parts[0], dict):
                    args = parts[0]
                elif isinstance(parts, list):
                    args = {"data": "\n".join(str(p) for p in parts)}
                    
                traces.append(ToolTrace(
                    id=f"trace_{msg_id}",
                    tool_name=tool_name,
                    args=args,
                    outputs={"text": content_text},
                    linked_messages=[msg_id]
                ))
                
            idx += 1
            
    return conversations, messages, traces

def parse_chat_html(file_path: str) -> Dict[str, Any]:
    """Fallback parser for chat.html if needed."""
    # To be implemented if necessary, currently focuses on json.
    return {}
