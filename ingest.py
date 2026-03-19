import os
import shutil
import zipfile
import hashlib
import mimetypes
from typing import List, Dict, Optional
import dataclasses
from model import ManifestEntry

class ExtractionLimitsExceeded(Exception):
    pass

def safe_extract_zip(
    zip_path: str, 
    out_dir: str, 
    max_total_uncompressed_bytes: int = 1536 * 1024 * 1024, # 1.5 GB
    max_files: int = 8000,
    max_single_file_bytes: int = 200 * 1024 * 1024, # 200 MB
) -> List[ManifestEntry]:
    """
    Safely extracts a zip file bounding extraction by size, file count, and path traversal (zip slip).
    Returns a manifest of processed files.
    """
    manifest: List[ManifestEntry] = []
    
    total_uncompressed_bytes = 0
    extracted_files_count = 0
    
    # Ensure output directory exists and is empty or created securely
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as archive:
            for zip_info in archive.infolist():
                
                # Skip directories
                if zip_info.is_dir():
                    continue
                
                # Update counts and check limits
                extracted_files_count += 1
                if extracted_files_count > max_files:
                    raise ExtractionLimitsExceeded(f"Exceeded maximum file limit of {max_files}.")
                
                expected_size = zip_info.file_size
                if expected_size > max_single_file_bytes:
                    manifest.append(ManifestEntry(
                        path=zip_info.filename,
                        sha256="",
                        size=expected_size,
                        mime_type=None,
                        extracted_ok=False,
                        reason_if_skipped=f"File exceeds maximum single file size ({max_single_file_bytes} bytes)."
                    ))
                    continue
                
                total_uncompressed_bytes += expected_size
                if total_uncompressed_bytes > max_total_uncompressed_bytes:
                    raise ExtractionLimitsExceeded(f"Exceeded maximum total uncompressed size of {max_total_uncompressed_bytes} bytes.")
                
                # Zip-slip protection: resolve path and check it's within out_dir
                target_path = os.path.abspath(os.path.join(out_dir, zip_info.filename))
                if not target_path.startswith(out_dir):
                    manifest.append(ManifestEntry(
                        path=zip_info.filename,
                        sha256="",
                        size=expected_size,
                        mime_type=None,
                        extracted_ok=False,
                        reason_if_skipped="Path traversal attempted (zip-slip)."
                    ))
                    continue
                
                # Check for symlinks and reject them
                # ZipFile doesn't natively expose symlink easily without checking external_attr,
                # but we can reject files that are marked as symlinks
                # high 16 bits of external_attr: 0xA000 indicates symlink on unix
                if (zip_info.external_attr >> 16) & 0xA000 == 0xA000:
                    manifest.append(ManifestEntry(
                        path=zip_info.filename,
                        sha256="",
                        size=expected_size,
                        mime_type=None,
                        extracted_ok=False,
                        reason_if_skipped="Symlink rejected."
                    ))
                    continue
                
                # Extract file safely, tracking hash
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                hasher = hashlib.sha256()
                extracted_size = 0
                
                with archive.open(zip_info.filename) as source, open(target_path, "wb") as target:
                    while True:
                        chunk = source.read(8192)
                        if not chunk:
                            break
                        extracted_size += len(chunk)
                        # Re-check size in case compression lie (zip bomb)
                        if extracted_size > max_single_file_bytes or (total_uncompressed_bytes - expected_size + extracted_size) > max_total_uncompressed_bytes:
                            source.close()
                            target.close()
                            os.remove(target_path)
                            raise ExtractionLimitsExceeded("Zip bomb detected (compression ratio attack).")
                        
                        hasher.update(chunk)
                        target.write(chunk)
                
                mime_type, _ = mimetypes.guess_type(target_path)
                manifest.append(ManifestEntry(
                    path=zip_info.filename,
                    sha256=hasher.hexdigest(),
                    size=extracted_size,
                    mime_type=mime_type,
                    extracted_ok=True,
                    reason_if_skipped=None
                ))

    except zipfile.BadZipFile:
        raise ValueError("Invalid zip file.")
        
    return manifest
