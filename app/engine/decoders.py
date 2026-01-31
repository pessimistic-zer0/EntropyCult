# app/engine/decoders.py
"""
Encoding decoders for obfuscated payloads.
Handles: hex escapes, HTML entities, Unicode escapes, nested encodings.
"""

import re
import base64
import html
from urllib.parse import unquote
from typing import Dict, List, Optional, Tuple

# Detection patterns
HEX_ESCAPE_PATTERN = re.compile(r'(?:\\x[0-9A-Fa-f]{2})+')
UNICODE_ESCAPE_PATTERN = re.compile(r'(?:\\u[0-9A-Fa-f]{4})+')
HTML_ENTITY_PATTERN = re.compile(r'(?:&#\d+;|&#x[0-9A-Fa-f]+;|&[a-zA-Z]+;)+')
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
URL_ENCODED_PATTERN = re.compile(r'(?:%[0-9A-Fa-f]{2}){3,}')

# Raw hex pattern (without backslash escapes, for direct \xNN in strings)
RAW_HEX_PATTERN = re.compile(r'(?:\\x[0-9A-Fa-f]{2})+')


def decode_hex_escapes(text: str) -> Tuple[str, bool]:
    """
    Decode hex escape sequences like \\x69\\x67\\x6e.
    Returns: (decoded_text, was_modified)
    """
    def replace_hex(match: re.Match) -> str:
        hex_str = match.group()
        try:
            # Split into individual \xNN sequences
            parts = re.findall(r'\\x([0-9A-Fa-f]{2})', hex_str)
            decoded = bytes(int(h, 16) for h in parts).decode('utf-8', errors='replace')
            return decoded
        except Exception:
            return hex_str
    
    result = HEX_ESCAPE_PATTERN.sub(replace_hex, text)
    return result, result != text


def decode_unicode_escapes(text: str) -> Tuple[str, bool]:
    """
    Decode Unicode escape sequences like \\u0069\\u0067.
    Returns: (decoded_text, was_modified)
    """
    def replace_unicode(match: re.Match) -> str:
        uni_str = match.group()
        try:
            # Split into individual \uNNNN sequences
            parts = re.findall(r'\\u([0-9A-Fa-f]{4})', uni_str)
            decoded = ''.join(chr(int(h, 16)) for h in parts)
            return decoded
        except Exception:
            return uni_str
    
    result = UNICODE_ESCAPE_PATTERN.sub(replace_unicode, text)
    return result, result != text


def decode_html_entities(text: str) -> Tuple[str, bool]:
    """
    Decode HTML entities like &#105; or &lt;.
    Returns: (decoded_text, was_modified)
    """
    try:
        result = html.unescape(text)
        return result, result != text
    except Exception:
        return text, False


def safe_base64_decode(blob: str, max_len: int = 500) -> Optional[str]:
    """
    Attempt to decode a base64 blob safely.
    Returns decoded text if valid, None otherwise.
    """
    try:
        # Add padding if needed
        padded = blob + '=' * (4 - len(blob) % 4) if len(blob) % 4 else blob
        decoded = base64.b64decode(padded, validate=True)
        text = decoded.decode('utf-8', errors='strict')
        
        # Check if result is mostly printable
        printable_ratio = sum(1 for c in text if c.isprintable() or c.isspace()) / max(len(text), 1)
        if printable_ratio > 0.8 and len(text) <= max_len:
            return text
    except Exception:
        pass
    return None


def decode_url_encoding(text: str) -> Tuple[str, bool]:
    """
    Decode URL percent-encoding.
    Returns: (decoded_text, was_modified)
    """
    try:
        result = unquote(text)
        return result, result != text
    except Exception:
        return text, False


def decode_single_pass(text: str) -> Tuple[str, List[Dict[str, str]]]:
    """
    Perform a single pass of all decoders.
    Returns: (decoded_text, list of decoder_info dicts)
    """
    current = text
    decoded_info = []
    
    # Try each decoder in order
    decoders = [
        ('hex_escape', decode_hex_escapes),
        ('unicode_escape', decode_unicode_escapes),
        ('html_entity', decode_html_entities),
        ('url_encoded', lambda t: decode_url_encoding(t)),
    ]
    
    for decoder_name, decoder_func in decoders:
        result, was_modified = decoder_func(current)
        if was_modified:
            decoded_info.append({
                'type': decoder_name,
                'original': current[:100] + '...' if len(current) > 100 else current,
                'decoded': result[:200] + '...' if len(result) > 200 else result,
            })
            current = result
    
    # Check for base64 blobs
    for match in BASE64_PATTERN.finditer(current):
        blob = match.group()
        decoded = safe_base64_decode(blob)
        if decoded:
            decoded_info.append({
                'type': 'base64',
                'original': blob[:50] + '...' if len(blob) > 50 else blob,
                'decoded': decoded[:200] + '...' if len(decoded) > 200 else decoded,
            })
            # Replace the blob in current text for further processing
            current = current.replace(blob, decoded, 1)
    
    return current, decoded_info


def decode_recursive(text: str, max_depth: int = 3) -> Tuple[str, List[Dict[str, str]]]:
    """
    Recursively decode nested encodings up to max_depth.
    Returns: (fully_decoded_text, list of all decode layers)
    """
    all_layers = []
    current = text
    
    for depth in range(max_depth):
        decoded, layers = decode_single_pass(current)
        
        if not layers:
            # No more decoding possible
            break
        
        # Add depth info to layers
        for layer in layers:
            layer['depth'] = depth + 1
        
        all_layers.extend(layers)
        current = decoded
        
        # Stop if nothing changed
        if current == text:
            break
    
    return current, all_layers


def extract_decoded_content(text: str, max_depth: int = 3) -> Dict[str, any]:
    """
    Main entry point for decoding obfuscated content.
    Returns dict with decoded text and all layers of encoding found.
    """
    decoded_text, layers = decode_recursive(text, max_depth)
    
    # Collect unique encoding types found
    encoding_types = list(set(layer['type'] for layer in layers))
    
    return {
        'decoded_text': decoded_text,
        'layers': layers,
        'encoding_types': encoding_types,
        'depth': max(layer.get('depth', 0) for layer in layers) if layers else 0,
        'was_encoded': len(layers) > 0,
    }


def detect_encoding_types(text: str) -> List[str]:
    """
    Quick check to detect what encoding types are present in text.
    Does not decode, just detects.
    """
    found = []
    
    if HEX_ESCAPE_PATTERN.search(text):
        found.append('hex_escape')
    if UNICODE_ESCAPE_PATTERN.search(text):
        found.append('unicode_escape')
    if HTML_ENTITY_PATTERN.search(text):
        found.append('html_entity')
    if BASE64_PATTERN.search(text):
        found.append('base64')
    if URL_ENCODED_PATTERN.search(text):
        found.append('url_encoded')
    
    return found
