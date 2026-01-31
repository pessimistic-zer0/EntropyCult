# app/engine/preprocess.py
"""
Preprocessing / Deobfuscation module.
Handles: NFKC normalization, zero-width removal, mixed-script detection,
recursive encoding decoding, whitespace normalization, content extraction.
"""

import re
import unicodedata
from typing import Dict, Any, List, Tuple

from app.engine.confusables import normalize_confusables, detect_confusables
from app.engine.decoders import extract_decoded_content, decode_recursive
from app.engine.content_extraction import extract_all_hidden_content, get_content_for_scanning

# Zero-width and invisible Unicode characters to strip
ZERO_WIDTH_CHARS = frozenset([
    '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', '\u00ad', '\u034f',
    '\u061c', '\u115f', '\u1160', '\u17b4', '\u17b5', '\u180e',
])

# Dangerous control characters that can manipulate text display
DANGEROUS_CONTROL_CHARS = frozenset([
    '\x08',  # Backspace
    '\x7f',  # Delete
    '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',  # Control chars
    '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15',
    '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f',
])

# Bidirectional control characters (RTL override, isolates, etc.)
BIDI_CONTROL_CHARS = frozenset([
    '\u200e', '\u200f',  # LRM, RLM
    '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',  # Bidi overrides
    '\u2066', '\u2067', '\u2068', '\u2069',  # Bidi isolates
    '\u2028', '\u2029',  # Line/paragraph separators
])

# Unicode whitespace characters to normalize to standard space
UNICODE_WHITESPACE = frozenset([
    '\u00a0',  # NBSP
    '\u1680',  # Ogham space
    '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005',  # En/em spaces
    '\u2006', '\u2007', '\u2008', '\u2009', '\u200a',  # Various thin spaces
    '\u2028', '\u2029',  # Line/para separator
    '\u202f',  # Narrow no-break space
    '\u205f',  # Medium mathematical space
    '\u3000',  # Ideographic space
    '\u2062', '\u2063', '\u2064',  # Invisible operators
])

# All characters to remove completely
CHARS_TO_REMOVE = ZERO_WIDTH_CHARS | DANGEROUS_CONTROL_CHARS | BIDI_CONTROL_CHARS

# Script detection patterns
CYRILLIC_PATTERN = re.compile(r'[\u0400-\u04FF]')
GREEK_PATTERN = re.compile(r'[\u0370-\u03FF]')
LATIN_PATTERN = re.compile(r'[a-zA-Z]')


def remove_dangerous_chars(text: str) -> Tuple[str, Dict[str, int]]:
    """Remove zero-width, control, and bidi characters. Track what was removed."""
    removed_counts = {
        'zero_width': 0,
        'control': 0,
        'bidi': 0,
    }
    result = []
    
    for char in text:
        if char in ZERO_WIDTH_CHARS:
            removed_counts['zero_width'] += 1
        elif char in DANGEROUS_CONTROL_CHARS:
            removed_counts['control'] += 1
        elif char in BIDI_CONTROL_CHARS:
            removed_counts['bidi'] += 1
        else:
            result.append(char)
    
    return ''.join(result), removed_counts


def normalize_whitespace(text: str) -> Tuple[str, int]:
    """Normalize all Unicode whitespace to standard ASCII space."""
    result = []
    normalized_count = 0
    for char in text:
        if char in UNICODE_WHITESPACE:
            result.append(' ')
            normalized_count += 1
        elif char == '\t':
            result.append(' ')  # Tab to space
            normalized_count += 1
        elif char == '\v':
            result.append(' ')  # Vertical tab to space
            normalized_count += 1
        elif char == '\f':
            result.append(' ')  # Form feed to space
            normalized_count += 1
        else:
            result.append(char)
    return ''.join(result), normalized_count


def strip_combining_marks(text: str) -> Tuple[str, int]:
    """
    Remove combining marks (diacritics) that could disguise text.
    Preserves legitimate diacritics by only removing suspicious overlay marks.
    """
    # Only strip combining marks that are commonly used for obfuscation
    SUSPICIOUS_COMBINING = {
        '\u0336', '\u0337', '\u0338',  # Strikethrough/overlays
        '\u0334', '\u0335',  # Tilde/short stroke overlay
        '\u0340', '\u0341',  # Grave/acute tone marks
        '\u0343', '\u0344',  # Combining marks
        '\u034f',  # Combining grapheme joiner
    }
    
    result = []
    removed = 0
    for char in text:
        if char in SUSPICIOUS_COMBINING:
            removed += 1
        elif unicodedata.category(char) == 'Mn' and ord(char) > 0x036F:
            # Remove combining marks above the common diacritics range
            # but be conservative - only unusual ranges
            if 0x1AB0 <= ord(char) <= 0x1AFF or 0x1DC0 <= ord(char) <= 0x1DFF:
                removed += 1
            else:
                result.append(char)
        else:
            result.append(char)
    
    return ''.join(result), removed


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



def preprocess(text: str, extract_hidden: bool = True) -> Dict[str, Any]:
    """
    Main preprocessing function.
    
    Pipeline:
    1. Remove dangerous characters (zero-width, control, bidi)
    2. Normalize whitespace
    3. Strip suspicious combining marks
    4. Detect confusables (before NFKC)
    5. Apply NFKC normalization
    6. Normalize remaining confusables (Cyrillic, Greek, etc.)
    7. Recursively decode encoded content
    8. Extract hidden content from structured formats
    
    Returns: clean_text, decoded_layers, obfuscation_flags, additional_content
    """
    # Step 1: Remove dangerous characters
    sanitized, removed_counts = remove_dangerous_chars(text)
    
    # Step 2: Normalize whitespace
    ws_normalized, ws_normalized_count = normalize_whitespace(sanitized)
    
    # Step 3: Strip suspicious combining marks
    no_combining, combining_removed = strip_combining_marks(ws_normalized)
    
    # Step 4: Detect confusables BEFORE normalization
    confusables_info = detect_confusables(no_combining)
    
    # Step 5: Apply NFKC normalization
    nfkc_text = normalize_unicode(no_combining)
    
    # Step 6: Normalize remaining confusables
    clean_text = normalize_confusables(nfkc_text)
    
    # Step 7: Recursively decode encoded content (on original and cleaned)
    # Decode from original to catch all encoded payloads
    decoded_result = extract_decoded_content(text, max_depth=3)
    
    # Also decode the cleaned text in case encoding was revealed after normalization
    decoded_clean = extract_decoded_content(clean_text, max_depth=3)
    
    # Merge decoded layers
    all_decoded_layers = decoded_result['layers'] + [
        {**layer, 'source': 'post_normalization'} 
        for layer in decoded_clean['layers']
        if layer not in decoded_result['layers']
    ]
    
    # Step 8: Extract hidden content from structured formats
    hidden_content = {}
    additional_texts = []
    if extract_hidden:
        hidden_content = extract_all_hidden_content(text)
        additional_texts = hidden_content.get('all_content', [])
        
        # Also extract from decoded content
        for layer in all_decoded_layers:
            if 'decoded' in layer:
                layer_hidden = extract_all_hidden_content(layer['decoded'])
                additional_texts.extend(layer_hidden.get('all_content', []))
    
    # Detect mixed scripts
    is_mixed, scripts = detect_mixed_script(text)
    
    # Compile obfuscation flags
    obfuscation_flags = {
        # Character removal
        'zero_width_removed': removed_counts['zero_width'] > 0,
        'zero_width_count': removed_counts['zero_width'],
        'control_chars_removed': removed_counts['control'] > 0,
        'control_chars_count': removed_counts['control'],
        'bidi_removed': removed_counts['bidi'] > 0,
        'bidi_count': removed_counts['bidi'],
        'whitespace_normalized': ws_normalized_count > 0,
        'whitespace_normalized_count': ws_normalized_count,
        'combining_marks_removed': combining_removed > 0,
        'combining_marks_count': combining_removed,
        
        # Script detection
        'mixed_script': is_mixed,
        'scripts_detected': scripts,
        
        # Encoding detection
        'encoding_detected': decoded_result['was_encoded'],
        'encoding_types': decoded_result['encoding_types'],
        'encoding_depth': decoded_result['depth'],
        
        # Confusables
        'confusables_detected': confusables_info['has_confusables'],
        'confusables_count': confusables_info['count'],
        'confusables_categories': confusables_info['categories'],
        
        # Hidden content
        'hidden_content_detected': len(additional_texts) > 0,
        'hidden_content_count': len(additional_texts),
    }
    
    # Collect all text to scan (clean + decoded + hidden)
    texts_to_scan = [clean_text]
    
    # Add decoded content to scan list
    if decoded_result['was_encoded']:
        texts_to_scan.append(decoded_result['decoded_text'])
    
    # Add hidden content
    texts_to_scan.extend(additional_texts)
    
    return {
        'clean_text': clean_text,
        'decoded_layers': all_decoded_layers,
        'obfuscation_flags': obfuscation_flags,
        'confusables_info': confusables_info,
        'hidden_content': hidden_content,
        'texts_to_scan': texts_to_scan,
        'fully_decoded_text': decoded_result['decoded_text'] if decoded_result['was_encoded'] else clean_text,
    }


# Keep backward compatibility
def remove_zero_width(text: str) -> str:
    """Remove all zero-width and invisible characters. (Legacy wrapper)"""
    result, _ = remove_dangerous_chars(text)
    return result


def extract_decoded_layers(text: str) -> List[Dict[str, str]]:
    """Extract decoded layers. (Legacy wrapper for backward compatibility)"""
    result = extract_decoded_content(text, max_depth=3)
    return result['layers']
