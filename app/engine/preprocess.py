# app/engine/preprocess.py
"""
Preprocessing / Deobfuscation module.
Handles: NFKC normalization, zero-width removal, mixed-script detection,
base64 decoding, URL percent-decoding.
"""

import re
import unicodedata
import base64
from urllib.parse import unquote
from typing import Dict, Any, List, Tuple

from app.engine.confusables import normalize_confusables, detect_confusables

# Zero-width and invisible Unicode characters to strip
ZERO_WIDTH_CHARS = frozenset([
    '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', '\u00ad', '\u034f',
    '\u061c', '\u115f', '\u1160', '\u17b4', '\u17b5', '\u180e',
    '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005',
    '\u2006', '\u2007', '\u2008', '\u2009', '\u200a',
    '\u2028', '\u2029', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
    '\u2062', '\u2063', '\u2064',
])

# Script detection patterns
CYRILLIC_PATTERN = re.compile(r'[\u0400-\u04FF]')
GREEK_PATTERN = re.compile(r'[\u0370-\u03FF]')
LATIN_PATTERN = re.compile(r'[a-zA-Z]')

# Base64 detection (at least 20 chars, valid base64 alphabet)
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

# URL encoding pattern (at least 3 encoded chars)
URL_ENCODED_PATTERN = re.compile(r'(?:%[0-9A-Fa-f]{2}){3,}')


def remove_zero_width(text: str) -> str:
    """Remove all zero-width and invisible characters."""
    return ''.join(c for c in text if c not in ZERO_WIDTH_CHARS)


def normalize_unicode(text: str) -> str:
    """Apply NFKC normalization to handle homoglyphs."""
    return unicodedata.normalize('NFKC', text)


def detect_mixed_script(text: str) -> Tuple[bool, List[str]]:
    """Detect if text contains mixed scripts (Latin + Cyrillic/Greek)."""
    scripts = []
    has_latin = bool(LATIN_PATTERN.search(text))
    has_cyrillic = bool(CYRILLIC_PATTERN.search(text))
    has_greek = bool(GREEK_PATTERN.search(text))

    if has_latin:
        scripts.append('latin')
    if has_cyrillic:
        scripts.append('cyrillic')
    if has_greek:
        scripts.append('greek')

    is_mixed = has_latin and (has_cyrillic or has_greek)
    return is_mixed, scripts


def safe_base64_decode(blob: str, max_len: int = 500) -> str | None:
    """Attempt to decode a base64 blob safely."""
    try:
        padded = blob + '=' * (4 - len(blob) % 4) if len(blob) % 4 else blob
        decoded = base64.b64decode(padded, validate=True)
        text = decoded.decode('utf-8', errors='strict')
        printable_ratio = sum(1 for c in text if c.isprintable() or c.isspace()) / max(len(text), 1)
        if printable_ratio > 0.8 and len(text) <= max_len:
            return text
    except Exception:
        pass
    return None


def decode_url_encoding(text: str) -> str:
    """Decode URL percent-encoding."""
    try:
        return unquote(text)
    except Exception:
        return text


def extract_decoded_layers(text: str) -> List[Dict[str, str]]:
    """Find and decode obfuscated content (base64, URL-encoded)."""
    layers = []

    for match in BASE64_PATTERN.finditer(text):
        blob = match.group()
        decoded = safe_base64_decode(blob)
        if decoded:
            layers.append({
                'type': 'base64',
                'original': blob[:50] + '...' if len(blob) > 50 else blob,
                'decoded': decoded
            })

    for match in URL_ENCODED_PATTERN.finditer(text):
        segment = match.group()
        decoded = decode_url_encoding(segment)
        if decoded != segment:
            layers.append({
                'type': 'url_encoded',
                'original': segment[:50] + '...' if len(segment) > 50 else segment,
                'decoded': decoded
            })

    return layers


def preprocess(text: str) -> Dict[str, Any]:
    """
    Main preprocessing function.
    Returns: clean_text, decoded_layers, obfuscation_flags
    """
    # Step 1: Remove zero-width characters
    no_zw = remove_zero_width(text)
    zw_removed = len(text) != len(no_zw)

    # Step 2: Detect confusables BEFORE normalization to catch all obfuscation
    # (NFKC normalizes some like superscripts/math, but we still want to flag them)
    confusables_info = detect_confusables(no_zw)
    
    # Step 3: Apply NFKC normalization (handles fullwidth, some math symbols, etc.)
    nfkc_text = normalize_unicode(no_zw)
    
    # Step 4: Normalize remaining confusables (Cyrillic, Greek, etc. that NFKC misses)
    clean_text = normalize_confusables(nfkc_text)
    
    # Detect mixed scripts on original text
    is_mixed, scripts = detect_mixed_script(text)
    
    # Extract decoded layers from original text
    decoded_layers = extract_decoded_layers(text)

    obfuscation_flags = {
        'zero_width_removed': zw_removed,
        'mixed_script': is_mixed,
        'scripts_detected': scripts,
        'base64_detected': any(l['type'] == 'base64' for l in decoded_layers),
        'url_encoded_detected': any(l['type'] == 'url_encoded' for l in decoded_layers),
        'confusables_detected': confusables_info['has_confusables'],
        'confusables_count': confusables_info['count'],
        'confusables_categories': confusables_info['categories'],
    }

    return {
        'clean_text': clean_text,
        'decoded_layers': decoded_layers,
        'obfuscation_flags': obfuscation_flags,
        'confusables_info': confusables_info,
    }

