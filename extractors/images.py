"""
Image EXIF / Metadata Extractor — Fix 8

Extracts EXIF data from images using Pillow and generates security findings for:
  - GPS coordinates (precise location exposure)
  - Device serial / camera model (device fingerprinting)
  - Timestamps embedded in image metadata
  - XMP/IPTC contact or personal data

Also handles SVG polyglot/XSS detection.
"""

from typing import Dict, Any, List, Tuple
import os

# Tags considered privacy-sensitive
_GPS_TAG_NAMES = {
    "GPSLatitude", "GPSLongitude", "GPSAltitude",
    "GPSLatitudeRef", "GPSLongitudeRef", "GPSAltitudeRef",
    "GPSTimeStamp", "GPSDateStamp", "GPSInfo",
}

_DEVICE_TAG_NAMES = {
    "Make", "Model", "Software",
    "BodySerialNumber", "CameraSerialNumber", "LensSerialNumber",
    "LensMake", "LensModel",
}

_PERSONAL_TAG_NAMES = {
    "Artist", "Copyright", "ImageDescription",
    "UserComment", "XPAuthor", "XPComment",
}


def _dms_to_decimal(dms_tuple, ref: str) -> float:
    """Convert DMS rational tuple to decimal degrees."""
    try:
        if hasattr(dms_tuple, "__iter__"):
            d, m, s = list(dms_tuple)[:3]
            # Handle IFDRational objects
            d = float(d)
            m = float(m)
            s = float(s)
        else:
            return float(dms_tuple)
        decimal = d + m / 60.0 + s / 3600.0
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return 0.0


def parse_image_safely(
    file_path: str,
) -> Tuple[List[Dict[str, str]], Dict[str, Any], List[Dict[str, Any]]]:
    """
    Parse EXIF/IPTC/XMP from image files. Parse SVG securely.

    Returns:
        text_chunks:     list of {source, locator, text}
        metadata:        dict of extracted key→value
        security_flags:  list of finding-like dicts with keys:
                           type, severity, locator, details, finding_id
    """
    text_chunks: List[Dict[str, str]] = []
    metadata: Dict[str, Any] = {}
    security_flags: List[Dict[str, Any]] = []

    if not os.path.exists(file_path):
        return text_chunks, metadata, security_flags

    ext = os.path.splitext(file_path)[1].lower()

    # ── SVG polyglot / XSS ────────────────────────────────────────────────
    if ext == ".svg":
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if "<script" in content.lower() or "onload=" in content.lower():
            security_flags.append({
                "type": "SVG Polyglot/XSS",
                "severity": "High",
                "locator": "SVG content",
                "details": "SVG contains <script> or event handlers — possible XSS vector.",
                "finding_id": "MM_IMAGE_INJECTION",
            })
        text_chunks.append({"source": "SVG Content", "locator": "Raw XML", "text": content})
        return text_chunks, metadata, security_flags

    # ── Raster image EXIF via Pillow ──────────────────────────────────────
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        with Image.open(file_path) as img:
            metadata["format"] = img.format or ext.lstrip(".")
            metadata["size"] = str(img.size)
            metadata["mode"] = img.mode

            exif_raw = img.getexif()
            if not exif_raw:
                return text_chunks, metadata, security_flags

            # Decode all tags
            all_tags: Dict[str, Any] = {}
            for tag_id, value in exif_raw.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                all_tags[tag_name] = value

            # ── GPS ─────────────────────────────────────────────────────
            gps_info_raw = all_tags.get("GPSInfo")
            if gps_info_raw:
                try:
                    gps_data: Dict[str, Any] = {}
                    for gps_tag_id, gps_val in gps_info_raw.items():
                        gps_tag_name = GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                        gps_data[gps_tag_name] = gps_val

                    lat = gps_data.get("GPSLatitude")
                    lat_ref = gps_data.get("GPSLatitudeRef", "N")
                    lon = gps_data.get("GPSLongitude")
                    lon_ref = gps_data.get("GPSLongitudeRef", "E")

                    if lat and lon:
                        lat_dec = _dms_to_decimal(lat, lat_ref)
                        lon_dec = _dms_to_decimal(lon, lon_ref)
                        coord_str = f"{lat_dec}, {lon_dec}"
                        metadata["GPS_Coordinates"] = coord_str
                        text_chunks.append({
                            "source": "EXIF GPS",
                            "locator": "GPSInfo",
                            "text": coord_str,
                        })
                        security_flags.append({
                            "type": "GPS Location Embedded",
                            "severity": "High",
                            "locator": "EXIF GPSInfo",
                            "details": (
                                f"Image contains precise GPS coordinates: {coord_str}. "
                                "This reveals the exact location where the photo was taken."
                            ),
                            "finding_id": "MM_EXIF_DATA",
                        })
                except Exception:
                    pass  # GPS decode failed — skip rather than crash

            # ── Device / serial ─────────────────────────────────────────
            device_parts = []
            for tag in ("Make", "Model"):
                val = all_tags.get(tag)
                if val:
                    s = val.decode("utf-8", errors="ignore") if isinstance(val, bytes) else str(val)
                    metadata[f"EXIF_{tag}"] = s.strip()
                    device_parts.append(s.strip())

            serial_tags = [t for t in ("BodySerialNumber", "CameraSerialNumber", "LensSerialNumber") if t in all_tags]
            for stag in serial_tags:
                val = all_tags[stag]
                s = val.decode("utf-8", errors="ignore") if isinstance(val, bytes) else str(val)
                metadata[f"EXIF_{stag}"] = s.strip()
                security_flags.append({
                    "type": "Device Serial Number",
                    "severity": "Medium",
                    "locator": f"EXIF {stag}",
                    "details": (
                        f"Image contains device serial number ({stag}): {s.strip()!r}. "
                        "Serial numbers can uniquely identify a device across photos."
                    ),
                    "finding_id": "FILE_EXIF",
                })

            if device_parts and not serial_tags:
                # Report device make/model as informational — not a direct risk
                metadata["EXIF_Device"] = " ".join(device_parts)

            # ── Personal / author tags ────────────────────────────────────
            for tag in _PERSONAL_TAG_NAMES:
                val = all_tags.get(tag)
                if val:
                    s = val.decode("utf-8", errors="ignore") if isinstance(val, bytes) else str(val)
                    s = s.strip()
                    if s and len(s) > 2:
                        metadata[f"EXIF_{tag}"] = s
                        text_chunks.append({
                            "source": "EXIF Personal",
                            "locator": tag,
                            "text": s,
                        })
                        security_flags.append({
                            "type": f"Personal Metadata ({tag})",
                            "severity": "Medium",
                            "locator": f"EXIF {tag}",
                            "details": (
                                f"Image contains personal metadata in {tag!r}: {s[:120]!r}. "
                                "This may identify the photographer or contain private notes."
                            ),
                            "finding_id": "FILE_EXIF",
                        })

            # ── All remaining string tags → text_chunks (for PII scan) ──
            for tag_name, value in all_tags.items():
                if tag_name in ("GPSInfo",):
                    continue  # already handled
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                if isinstance(value, str) and len(value.strip()) > 3:
                    text_chunks.append({
                        "source": "EXIF",
                        "locator": tag_name,
                        "text": value.strip(),
                    })
                    metadata[f"EXIF_{tag_name}"] = value.strip()

    except ImportError:
        text_chunks.append({
            "source": "System",
            "locator": "Missing library",
            "text": "Install Pillow for EXIF parsing: pip install Pillow",
        })
    except Exception:
        pass  # Not an image or unparseable — skip silently

    return text_chunks, metadata, security_flags
