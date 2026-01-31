# app/engine/confusables.py
"""
Unicode confusables detection and normalization.
Handles homoglyph attacks that bypass NFKC normalization.
Uses Unicode Consortium's confusables data via confusable_homoglyphs library.
"""

import re
import unicodedata
from typing import Dict, List, Tuple, Set

# Try to import confusable_homoglyphs library
try:
    from confusable_homoglyphs import confusables
    HAS_CONFUSABLES_LIB = True
except ImportError:
    HAS_CONFUSABLES_LIB = False

# Fallback mapping for critical confusable characters
# These are the most commonly abused homoglyphs for prompt injection
CRITICAL_CONFUSABLES: Dict[str, str] = {
    # Cyrillic → Latin
    '\u0430': 'a',  # Cyrillic small а
    '\u0435': 'e',  # Cyrillic small е
    '\u043e': 'o',  # Cyrillic small о
    '\u0440': 'p',  # Cyrillic small р
    '\u0441': 'c',  # Cyrillic small с
    '\u0443': 'y',  # Cyrillic small у
    '\u0445': 'x',  # Cyrillic small х
    '\u0456': 'i',  # Cyrillic small і
    '\u04cf': 'l',  # Cyrillic small palochka
    '\u0410': 'A',  # Cyrillic capital А
    '\u0412': 'B',  # Cyrillic capital В
    '\u0415': 'E',  # Cyrillic capital Е
    '\u041a': 'K',  # Cyrillic capital К
    '\u041c': 'M',  # Cyrillic capital М
    '\u041d': 'H',  # Cyrillic capital Н
    '\u041e': 'O',  # Cyrillic capital О
    '\u0420': 'P',  # Cyrillic capital Р
    '\u0421': 'C',  # Cyrillic capital С
    '\u0422': 'T',  # Cyrillic capital Т
    '\u0425': 'X',  # Cyrillic capital Х
    
    # Greek → Latin
    '\u03b1': 'a',  # Greek small alpha
    '\u03b5': 'e',  # Greek small epsilon
    '\u03bf': 'o',  # Greek small omicron
    '\u03c1': 'p',  # Greek small rho
    '\u03c5': 'u',  # Greek small upsilon
    '\u0391': 'A',  # Greek capital Alpha
    '\u0392': 'B',  # Greek capital Beta
    '\u0395': 'E',  # Greek capital Epsilon
    '\u0397': 'H',  # Greek capital Eta
    '\u0399': 'I',  # Greek capital Iota
    '\u039a': 'K',  # Greek capital Kappa
    '\u039c': 'M',  # Greek capital Mu
    '\u039d': 'N',  # Greek capital Nu
    '\u039f': 'O',  # Greek capital Omicron
    '\u03a1': 'P',  # Greek capital Rho
    '\u03a4': 'T',  # Greek capital Tau
    '\u03a7': 'X',  # Greek capital Chi
    '\u03a5': 'Y',  # Greek capital Upsilon
    '\u0396': 'Z',  # Greek capital Zeta
    
    # Modifier letters → Latin
    '\u1d43': 'a',  # modifier letter small a
    '\u1d47': 'b',  # modifier letter small b
    '\u1d9c': 'c',  # modifier letter small c
    '\u1d48': 'd',  # modifier letter small d
    '\u1d49': 'e',  # modifier letter small e
    '\u1da0': 'f',  # modifier letter small f
    '\u1d4d': 'g',  # modifier letter small g (ᵍ)
    '\u02b0': 'h',  # modifier letter small h
    '\u2071': 'i',  # superscript latin small letter i
    '\u02b2': 'j',  # modifier letter small j
    '\u1d4f': 'k',  # modifier letter small k
    '\u02e1': 'l',  # modifier letter small l
    '\u1d50': 'm',  # modifier letter small m
    '\u207f': 'n',  # superscript latin small letter n
    '\u1d52': 'o',  # modifier letter small o
    '\u1d56': 'p',  # modifier letter small p (ᵖ)
    '\u02b3': 'r',  # modifier letter small r
    '\u02e2': 's',  # modifier letter small s
    '\u1d57': 't',  # modifier letter small t
    '\u1d58': 'u',  # modifier letter small u
    '\u1d5b': 'v',  # modifier letter small v
    '\u02b7': 'w',  # modifier letter small w
    '\u02e3': 'x',  # modifier letter small x
    '\u02b8': 'y',  # modifier letter small y
    '\u1dbb': 'z',  # modifier letter small z
    
    # Subscript letters → Latin
    '\u2090': 'a',  # subscript a
    '\u2091': 'e',  # subscript e
    '\u1d62': 'i',  # subscript i (ᵢ)
    '\u2092': 'o',  # subscript o
    '\u1d63': 'r',  # subscript r (ᵣ)
    '\u1d64': 'u',  # subscript u (ᵤ)
    '\u1d65': 'v',  # subscript v (ᵥ)
    '\u2093': 'x',  # subscript x
    '\u2099': 'n',  # subscript n (ₙ)
    '\u209a': 'p',  # subscript p
    '\u209b': 's',  # subscript s (ₛ)
    '\u209c': 't',  # subscript t
    
    # Superscript digits and special
    '\u00b9': '1',  # superscript 1
    '\u00b2': '2',  # superscript 2
    '\u00b3': '3',  # superscript 3
    '\u2070': '0',  # superscript 0
    '\u2074': '4',  # superscript 4
    '\u2075': '5',  # superscript 5
    '\u2076': '6',  # superscript 6
    '\u2077': '7',  # superscript 7
    '\u2078': '8',  # superscript 8
    '\u2079': '9',  # superscript 9
}


def _build_math_alphanumeric_map() -> Dict[str, str]:
    """
    Build mapping for Mathematical Alphanumeric Symbols (U+1D400-1D7FF).
    These are NOT normalized by NFKC and are commonly used in attacks.
    """
    mapping = {}
    
    # Mathematical ranges: (start_offset, target_start, count)
    # Each block maps to A-Z or a-z or 0-9
    math_ranges = [
        # Bold
        (0x1D400, 'A', 26),  # Bold capitals
        (0x1D41A, 'a', 26),  # Bold lowercase
        # Italic
        (0x1D434, 'A', 26),  # Italic capitals
        (0x1D44E, 'a', 26),  # Italic lowercase
        # Bold Italic
        (0x1D468, 'A', 26),  # Bold Italic capitals
        (0x1D482, 'a', 26),  # Bold Italic lowercase
        # Script
        (0x1D49C, 'A', 26),  # Script capitals
        (0x1D4B6, 'a', 26),  # Script lowercase
        # Bold Script
        (0x1D4D0, 'A', 26),  # Bold Script capitals
        (0x1D4EA, 'a', 26),  # Bold Script lowercase
        # Fraktur
        (0x1D504, 'A', 26),  # Fraktur capitals
        (0x1D51E, 'a', 26),  # Fraktur lowercase
        # Double-struck
        (0x1D538, 'A', 26),  # Double-struck capitals
        (0x1D552, 'a', 26),  # Double-struck lowercase
        # Bold Fraktur
        (0x1D56C, 'A', 26),  # Bold Fraktur capitals
        (0x1D586, 'a', 26),  # Bold Fraktur lowercase
        # Sans-serif
        (0x1D5A0, 'A', 26),  # Sans-serif capitals
        (0x1D5BA, 'a', 26),  # Sans-serif lowercase
        # Sans-serif Bold
        (0x1D5D4, 'A', 26),  # Sans-serif Bold capitals
        (0x1D5EE, 'a', 26),  # Sans-serif Bold lowercase
        # Sans-serif Italic
        (0x1D608, 'A', 26),  # Sans-serif Italic capitals
        (0x1D622, 'a', 26),  # Sans-serif Italic lowercase
        # Sans-serif Bold Italic
        (0x1D63C, 'A', 26),  # Sans-serif Bold Italic capitals
        (0x1D656, 'a', 26),  # Sans-serif Bold Italic lowercase
        # Monospace
        (0x1D670, 'A', 26),  # Monospace capitals
        (0x1D68A, 'a', 26),  # Monospace lowercase
        # Bold digits
        (0x1D7CE, '0', 10),  # Bold digits
        # Double-struck digits
        (0x1D7D8, '0', 10),  # Double-struck digits
        # Sans-serif digits
        (0x1D7E2, '0', 10),  # Sans-serif digits
        # Sans-serif Bold digits
        (0x1D7EC, '0', 10),  # Sans-serif Bold digits
        # Monospace digits
        (0x1D7F6, '0', 10),  # Monospace digits
    ]
    
    for start, target_start, count in math_ranges:
        for i in range(count):
            try:
                source_char = chr(start + i)
                target_char = chr(ord(target_start) + i)
                mapping[source_char] = target_char
            except (ValueError, OverflowError):
                continue
    
    return mapping


# Build full confusables map
MATH_ALPHANUMERIC_MAP = _build_math_alphanumeric_map()
FULL_CONFUSABLES_MAP = {**CRITICAL_CONFUSABLES, **MATH_ALPHANUMERIC_MAP}


def normalize_confusables(text: str) -> str:
    """
    Normalize confusable Unicode characters to their ASCII equivalents.
    This catches homoglyphs that NFKC normalization misses.
    
    Args:
        text: Input text potentially containing confusable characters
        
    Returns:
        Text with confusable characters replaced with ASCII equivalents
    """
    if HAS_CONFUSABLES_LIB:
        # Use the library for comprehensive coverage
        result = []
        for char in text:
            # Check if character is confusable with Latin
            if char in FULL_CONFUSABLES_MAP:
                result.append(FULL_CONFUSABLES_MAP[char])
            else:
                # Try to get skeleton (canonical form) from library
                try:
                    skel = confusables.is_confusable(char, preferred_aliases=['LATIN'])
                    if skel and len(skel) > 0:
                        # Get the first confusable's target character
                        homoglyphs = skel[0].get('homoglyphs', [])
                        if homoglyphs:
                            # Use the Latin equivalent
                            for h in homoglyphs:
                                if 'LATIN' in h.get('n', '').upper():
                                    result.append(h.get('c', char))
                                    break
                            else:
                                result.append(char)
                        else:
                            result.append(char)
                    else:
                        result.append(char)
                except Exception:
                    result.append(char)
        return ''.join(result)
    else:
        # Fallback: use our built-in mapping
        return ''.join(FULL_CONFUSABLES_MAP.get(c, c) for c in text)


def detect_confusables(text: str) -> Dict[str, any]:
    """
    Detect confusable characters in text without modifying it.
    This detects BOTH:
    - Characters in our confusables map (Cyrillic, Greek, etc.)
    - Characters that NFKC normalizes differently (superscripts, fullwidth, math)
    
    Args:
        text: Input text to analyze
        
    Returns:
        Dictionary with:
        - has_confusables: bool
        - confusable_chars: list of (original, replacement, position)
        - categories: set of detected confusable categories
    """
    confusable_chars = []
    categories: Set[str] = set()
    
    for i, char in enumerate(text):
        # Check our confusables map
        if char in FULL_CONFUSABLES_MAP:
            replacement = FULL_CONFUSABLES_MAP[char]
            confusable_chars.append({
                'original': char,
                'replacement': replacement,
                'position': i,
                'codepoint': f'U+{ord(char):04X}'
            })
            
            # Categorize the confusable
            cp = ord(char)
            if 0x0400 <= cp <= 0x04FF:
                categories.add('cyrillic')
            elif 0x0370 <= cp <= 0x03FF:
                categories.add('greek')
            elif 0x1D400 <= cp <= 0x1D7FF:
                categories.add('math_alphanumeric')
            elif char in CRITICAL_CONFUSABLES:
                # Check modifier/subscript ranges
                if 0x1D43 <= cp <= 0x1DBB or 0x02B0 <= cp <= 0x02E3:
                    categories.add('modifier_letters')
                elif 0x2070 <= cp <= 0x209C:
                    categories.add('subscript_superscript')
                else:
                    categories.add('other')
        else:
            # Also check if NFKC normalizes this character differently
            # This catches fullwidth, superscripts, math symbols, etc.
            nfkc_char = unicodedata.normalize('NFKC', char)
            if nfkc_char != char:
                confusable_chars.append({
                    'original': char,
                    'replacement': nfkc_char,
                    'position': i,
                    'codepoint': f'U+{ord(char):04X}'
                })
                
                # Categorize based on character range
                cp = ord(char)
                if 0xFF00 <= cp <= 0xFFEF:
                    categories.add('fullwidth')
                elif 0x1D400 <= cp <= 0x1D7FF:
                    categories.add('math_alphanumeric')
                elif 0x2070 <= cp <= 0x209C or cp in (0x00B2, 0x00B3, 0x00B9):
                    categories.add('subscript_superscript')
                elif 0x1D00 <= cp <= 0x1DBF or 0x02B0 <= cp <= 0x02FF:
                    categories.add('modifier_letters')
                else:
                    categories.add('nfkc_normalized')
    
    # Also check using library if available and we didn't find anything
    if HAS_CONFUSABLES_LIB and not confusable_chars:
        try:
            result = confusables.is_confusable(text, preferred_aliases=['LATIN'])
            if result:
                for item in result:
                    char = item.get('character', '')
                    if char and char not in [c['original'] for c in confusable_chars]:
                        confusable_chars.append({
                            'original': char,
                            'replacement': '?',
                            'position': text.find(char),
                            'codepoint': f'U+{ord(char):04X}'
                        })
                        categories.add('library_detected')
        except Exception:
            pass
    
    return {
        'has_confusables': len(confusable_chars) > 0,
        'confusable_chars': confusable_chars,
        'categories': list(categories),
        'count': len(confusable_chars)
    }


def get_confusable_skeleton(text: str) -> str:
    """
    Get the 'skeleton' of a string - a canonical form for comparison.
    Two strings that look alike should have the same skeleton.
    
    This applies: NFKC normalization + confusables normalization + lowercase
    """
    # First apply NFKC
    nfkc = unicodedata.normalize('NFKC', text)
    # Then normalize confusables
    normalized = normalize_confusables(nfkc)
    # Return lowercase for comparison
    return normalized.lower()


def is_confusable_with(text1: str, text2: str) -> bool:
    """
    Check if two strings are confusable (look visually similar).
    
    Args:
        text1: First string
        text2: Second string
        
    Returns:
        True if the strings have the same skeleton (are confusable)
    """
    return get_confusable_skeleton(text1) == get_confusable_skeleton(text2)
