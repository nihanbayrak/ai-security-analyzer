from typing import Dict, Any, List, Tuple
import os

def check_pdf_safety(file_path: str) -> Tuple[List[str], Dict[str, Any], List[Dict[str, Any]]]:
    """
    Safely parses a PDF to extract text, metadata, and security flags (e.g. JS presence, hidden layers).
    Returns (extracted_text_chunks, metadata, security_flags).
    
    Uses PyPDF2 if available, otherwise falls back to basic binary scanning.
    """
    text_chunks = []
    metadata = {}
    security_flags = []
    
    if not os.path.exists(file_path):
        return text_chunks, metadata, security_flags
        
    try:
        import PyPDF2
        with open(file_path, "rb") as f:
            try:
                reader = PyPDF2.PdfReader(f)
                if reader.is_encrypted:
                    security_flags.append({"type": "Encrypted PDF", "severity": "Medium", "locator": "File Level", "details": "PDF is encrypted and cannot be fully analyzed."})
                    return text_chunks, metadata, security_flags
                    
                meta = reader.metadata
                if meta:
                    for k, v in meta.items():
                        metadata[k] = str(v)
                        
                for i, page in enumerate(reader.pages):
                    text = page.extract_text()
                    if text:
                        text_chunks.append({"source": "page", "locator": f"Page {i+1}", "text": text})
                        
                    # basic safety check for JS
                    if "/OpenAction" in page or "/JavaScript" in page or "/JS" in page:
                        security_flags.append({"type": "Suspicious Object", "severity": "High", "locator": f"Page {i+1}", "details": "JavaScript or OpenAction found in PDF."})
            except Exception as e:
                 security_flags.append({"type": "Parse Error", "severity": "Medium", "locator": "File Level", "details": str(e)})
    except ImportError:
        # Fallback binary scan
        with open(file_path, "rb") as f:
            content = f.read(1000000) # scan first 1MB
            if b"/JavaScript" in content or b"/JS" in content or b"/OpenAction" in content:
                security_flags.append({"type": "Suspicious Object", "severity": "High", "locator": "Binary Level", "details": "JavaScript or OpenAction found in PDF binary."})
            
            # stub text extraction
            text_chunks.append({"source": "binary", "locator": "Raw", "text": "Install PyPDF2 for full PDF text extraction."})

    return text_chunks, metadata, security_flags
