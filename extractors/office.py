from typing import Dict, Any, List, Tuple
import os
import zipfile
import re

def parse_office_safely(file_path: str) -> Tuple[List[Dict[str, str]], Dict[str, Any], List[Dict[str, Any]]]:
    """
    Treats modern Office files (.docx, .xlsx, .pptx) as ZIP archives and parses their XML safely.
    Checks for macros (vbaProject.bin), external links, and extracts basic text.
    """
    text_chunks = []
    metadata = {}
    security_flags = []
    
    if not os.path.exists(file_path):
        return text_chunks, metadata, security_flags
        
    if not zipfile.is_zipfile(file_path):
        security_flags.append({"type": "Format Error", "severity": "Medium", "locator": "File Level", "details": "Not a valid ZIP/Office file."})
        return text_chunks, metadata, security_flags
        
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            file_list = z.namelist()
            
            # Check for macros
            if any("vbaProject.bin" in name for name in file_list):
                 security_flags.append({"type": "Macro Detected", "severity": "High", "locator": "vbaProject.bin", "details": "Office document contains VBA macros."})
                 
            # Extract basic text from docx
            if "word/document.xml" in file_list:
                xml_content = z.read("word/document.xml").decode("utf-8", errors="ignore")
                # simple regex to extract text between XML tags
                text = re.sub(r'<[^>]+>', ' ', xml_content)
                # clear extra spaces
                text = re.sub(r'\s+', ' ', text).strip()
                if text:
                     text_chunks.append({"source": "XML", "locator": "word/document.xml", "text": text})
                     
            # Example metadata parsing
            if "docProps/core.xml" in file_list:
                core_xml = z.read("docProps/core.xml").decode("utf-8", errors="ignore")
                creator = re.search(r'<dc:creator>(.*?)</dc:creator>', core_xml)
                if creator:
                    metadata["creator"] = creator.group(1)
                    
            # Check for external links/OLE
            for name in file_list:
                if name.endswith(".rels"):
                    rels_data = z.read(name).decode("utf-8", errors="ignore")
                    if 'TargetMode="External"' in rels_data:
                         security_flags.append({"type": "External Link", "severity": "Low", "locator": name, "details": "Document contains external OLE/Template links."})
                         
    except Exception as e:
         security_flags.append({"type": "Parse Error", "severity": "Medium", "locator": "File Level", "details": str(e)})

    return text_chunks, metadata, security_flags
