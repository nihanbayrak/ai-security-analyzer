from typing import Dict, Any, List, Tuple
import os

INVISIBLE_CHARS = [
    '\u200b', # Zero width space
    '\u200c', # Zero width non-joiner
    '\u200d', # Zero width joiner
    '\u200e', # Left-to-right mark
    '\u200f', # Right-to-left mark
    '\u202a', # Left-to-right embedding
    '\u202b', # Right-to-left embedding
    '\u202c', # Pop directional formatting
    '\u202d', # Left-to-right override
    '\u202e', # Right-to-left override
]

def parse_text_csv(file_path: str) -> Tuple[List[Dict[str, str]], Dict[str, Any], List[Dict[str, Any]]]:
    """
    Extracts text, normalizes it, and detects CSV formula injection / invisible chars.
    """
    text_chunks = []
    metadata = {}
    security_flags = []
    
    if not os.path.exists(file_path):
        return text_chunks, metadata, security_flags

    ext = os.path.splitext(file_path)[1].lower()
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            
            suspect_csv_chars = ('=', '+', '-', '@')
            
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                    
                # Check for invisible chars
                for char in INVISIBLE_CHARS:
                    if char in line:
                        security_flags.append({
                            "type": "Invisible Unicode", 
                            "severity": "Medium", 
                            "locator": f"Line {i+1}", 
                            "details": f"Invisible character U+{ord(char):04X} detected."
                        })
                        break # Flag once per line
                        
                # Check CSV injection if CSV
                if ext in ('.csv', '.tsv'):
                    # Basic check: any field starting with suspect char
                    fields = line.split(',') if ext == '.csv' else line.split('\t')
                    for field in fields:
                        field = field.strip(' "\'')
                        if field and field.startswith(suspect_csv_chars):
                            security_flags.append({
                                "type": "CSV Formula Injection", 
                                "severity": "High", 
                                "locator": f"Line {i+1}", 
                                "details": f"Cell starts with dangerous character: {field[0]}"
                            })
                            break
                            
            content = "".join(lines)
            text_chunks.append({"source": "Text/CSV", "locator": "Full File", "text": content[:100000]}) # limit size
            
    except Exception as e:
         security_flags.append({"type": "Parse Error", "severity": "Low", "locator": "File Level", "details": str(e)})

    return text_chunks, metadata, security_flags
