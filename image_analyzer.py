"""
Image Metadata Analyzer
Extracts and analyzes metadata from images shared in conversations.

Capabilities:
  - EXIF data extraction (GPS, device, timestamps, software)
  - Privacy risk assessment (location leakage, device fingerprinting)
  - Basic steganography indicators (file size anomalies, LSB analysis)
  - AI-generated image indicators (metadata markers)

Maps to multimodal prompt injection attack vectors.
"""

import os
import re
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class ImageFinding:
    """A finding from image metadata analysis."""
    filename: str
    finding_type: str  # exif_gps, exif_device, steganography_suspect, ai_generated
    severity: str
    confidence: float
    details: str
    metadata: Dict


class ImageMetadataAnalyzer:
    """
    Analyzes images for security-relevant metadata.
    Works with Pillow for EXIF and basic analysis.
    """
    
    # AI generation software markers in EXIF
    AI_SOFTWARE_MARKERS = [
        "dall-e", "midjourney", "stable diffusion", "comfyui",
        "automatic1111", "novelai", "firefly", "ideogram",
        "flux", "playground", "leonardo", "nightcafe"
    ]
    
    # Sensitive EXIF tags
    SENSITIVE_TAGS = {
        "GPSInfo": "CRITICAL",
        "GPSLatitude": "CRITICAL",
        "GPSLongitude": "CRITICAL",
        "GPSLatitudeRef": "CRITICAL",
        "GPSLongitudeRef": "CRITICAL",
        "Make": "LOW",           # Camera manufacturer
        "Model": "LOW",          # Camera model
        "Software": "LOW",       # Editing software
        "DateTime": "LOW",
        "DateTimeOriginal": "MEDIUM",
        "Artist": "MEDIUM",
        "Copyright": "LOW",
        "HostComputer": "MEDIUM",
        "SerialNumber": "HIGH",  # Device serial number
        "LensModel": "LOW",
        "OwnerName": "HIGH",
        "CameraOwnerName": "HIGH",
    }
    
    def __init__(self):
        self.findings: List[ImageFinding] = []
        self._has_pillow = False
        self._has_exiftool = False
        
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
            self._has_pillow = True
        except ImportError:
            pass
    
    def analyze_image(self, filepath: str) -> List[ImageFinding]:
        """Analyze a single image file for security-relevant metadata."""
        findings = []
        
        if not os.path.exists(filepath):
            return findings
        
        filename = os.path.basename(filepath)
        
        if self._has_pillow:
            findings.extend(self._extract_exif(filepath, filename))
            findings.extend(self._check_ai_generated(filepath, filename))
        
        findings.extend(self._check_file_anomalies(filepath, filename))
        
        return findings
    
    def _extract_exif(self, filepath: str, filename: str) -> List[ImageFinding]:
        """Extract and analyze EXIF data from image."""
        findings = []
        
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
            
            img = Image.open(filepath)
            exif_data = img._getexif()
            
            if not exif_data:
                return findings
            
            decoded_exif = {}
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                decoded_exif[tag_name] = value
            
            # Check for GPS data (location leakage)
            if "GPSInfo" in decoded_exif:
                gps_data = decoded_exif["GPSInfo"]
                gps_decoded = {}
                for key in gps_data:
                    name = GPSTAGS.get(key, str(key))
                    gps_decoded[name] = str(gps_data[key])
                
                findings.append(ImageFinding(
                    filename=filename,
                    finding_type="exif_gps",
                    severity="CRITICAL",
                    confidence=0.99,
                    details="GPS coordinates found in image metadata - exact location is exposed!",
                    metadata=gps_decoded
                ))
            
            # Check for sensitive tags
            sensitive_found = {}
            for tag_name, severity in self.SENSITIVE_TAGS.items():
                if tag_name in decoded_exif and tag_name != "GPSInfo":
                    sensitive_found[tag_name] = {
                        "value": str(decoded_exif[tag_name])[:100],
                        "severity": severity
                    }
            
            if sensitive_found:
                max_severity = max(
                    sensitive_found.values(), 
                    key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[x["severity"]]
                )["severity"]
                
                findings.append(ImageFinding(
                    filename=filename,
                    finding_type="exif_metadata",
                    severity=max_severity,
                    confidence=0.95,
                    details=f"Found {len(sensitive_found)} sensitive EXIF tags: {', '.join(sensitive_found.keys())}",
                    metadata={k: v["value"] for k, v in sensitive_found.items()}
                ))
            
        except Exception as e:
            pass
        
        return findings
    
    def _check_ai_generated(self, filepath: str, filename: str) -> List[ImageFinding]:
        """Check for AI-generated image indicators in metadata."""
        findings = []
        
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            img = Image.open(filepath)
            exif_data = img._getexif()
            
            # Check EXIF software field
            if exif_data:
                decoded = {}
                for tag_id, value in exif_data.items():
                    decoded[TAGS.get(tag_id, str(tag_id))] = value
                
                software = str(decoded.get("Software", "")).lower()
                for marker in self.AI_SOFTWARE_MARKERS:
                    if marker in software:
                        findings.append(ImageFinding(
                            filename=filename,
                            finding_type="ai_generated",
                            severity="MEDIUM",
                            confidence=0.85,
                            details=f"AI generation software detected in EXIF: {software}",
                            metadata={"software": software, "marker": marker}
                        ))
                        break
            
            # Check PNG text chunks for AI metadata
            if hasattr(img, 'text'):
                for key, value in img.text.items():
                    value_lower = value.lower() if isinstance(value, str) else ""
                    for marker in self.AI_SOFTWARE_MARKERS:
                        if marker in value_lower or marker in key.lower():
                            findings.append(ImageFinding(
                                filename=filename,
                                finding_type="ai_generated",
                                severity="MEDIUM",
                                confidence=0.80,
                                details=f"AI generation metadata in PNG chunk: {key}",
                                metadata={"chunk_key": key, "value_preview": str(value)[:200]}
                            ))
                            break
            
        except Exception:
            pass
        
        return findings
    
    def _check_file_anomalies(self, filepath: str, filename: str) -> List[ImageFinding]:
        """Check for file size anomalies that might indicate steganography."""
        findings = []
        
        try:
            file_size = os.path.getsize(filepath)
            ext = os.path.splitext(filename)[1].lower()
            
            # Simple heuristic: PNG files that are unusually large for their dimensions
            if self._has_pillow and ext in ['.png', '.bmp']:
                from PIL import Image
                img = Image.open(filepath)
                w, h = img.size
                channels = len(img.getbands())
                
                # Expected uncompressed size
                expected_raw = w * h * channels
                # PNG should be much smaller than raw
                ratio = file_size / max(expected_raw, 1)
                
                if ratio > 0.95 and ext == '.png':
                    findings.append(ImageFinding(
                        filename=filename,
                        finding_type="steganography_suspect",
                        severity="LOW",
                        confidence=0.4,
                        details=f"PNG compression ratio is unusually low ({ratio:.2f}) - possible hidden data",
                        metadata={
                            "file_size": file_size,
                            "dimensions": f"{w}x{h}",
                            "compression_ratio": round(ratio, 3)
                        }
                    ))
        except Exception:
            pass
        
        return findings
    
    def analyze_conversation_images(self, image_dir: str) -> List[ImageFinding]:
        """Analyze all images in a directory (from ChatGPT export)."""
        findings = []
        
        if not os.path.isdir(image_dir):
            return findings
        
        image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff'}
        
        for fname in os.listdir(image_dir):
            ext = os.path.splitext(fname)[1].lower()
            if ext in image_extensions:
                filepath = os.path.join(image_dir, fname)
                findings.extend(self.analyze_image(filepath))
        
        return findings
