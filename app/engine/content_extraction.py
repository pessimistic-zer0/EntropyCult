# app/engine/content_extraction.py
"""
Content extraction from structured formats.
Handles: HTML comments, markdown code blocks, JSON strings, XML CDATA, links.
"""

import re
import json
from typing import Dict, List, Any, Optional

# Patterns for content extraction
HTML_COMMENT_PATTERN = re.compile(r'<!--\s*(.*?)\s*-->', re.DOTALL)
MARKDOWN_CODE_BLOCK_PATTERN = re.compile(r'```(?:\w*\n)?(.*?)```', re.DOTALL)
MARKDOWN_INLINE_CODE_PATTERN = re.compile(r'`([^`]+)`')
MARKDOWN_LINK_PATTERN = re.compile(r'\[([^\]]*)\]\(([^)]+)\)')
CDATA_PATTERN = re.compile(r'<!\[CDATA\[(.*?)\]\]>', re.DOTALL)
LATEX_TEXT_PATTERN = re.compile(r'\$\\text\{([^}]+)\}\$')
LATEX_MATHTEXT_PATTERN = re.compile(r'\$[^$]+\$')

# JSON detection pattern (simple heuristic)
JSON_OBJECT_PATTERN = re.compile(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}')
JSON_ARRAY_PATTERN = re.compile(r'\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\]')


def extract_html_comments(text: str) -> List[Dict[str, str]]:
    """
    Extract content from HTML comments.
    Returns list of {content, position} dicts.
    """
    results = []
    for match in HTML_COMMENT_PATTERN.finditer(text):
        content = match.group(1).strip()
        if content:
            results.append({
                'type': 'html_comment',
                'content': content,
                'position': match.start(),
                'original': match.group()[:100],
            })
    return results


def extract_code_blocks(text: str) -> List[Dict[str, str]]:
    """
    Extract content from markdown code blocks.
    Returns list of {content, position} dicts.
    """
    results = []
    
    # Fenced code blocks
    for match in MARKDOWN_CODE_BLOCK_PATTERN.finditer(text):
        content = match.group(1).strip()
        if content:
            results.append({
                'type': 'code_block',
                'content': content,
                'position': match.start(),
                'original': match.group()[:100],
            })
    
    # Inline code (less suspicious but still check)
    for match in MARKDOWN_INLINE_CODE_PATTERN.finditer(text):
        content = match.group(1).strip()
        if content and len(content) > 10:  # Skip very short inline code
            results.append({
                'type': 'inline_code',
                'content': content,
                'position': match.start(),
                'original': match.group()[:100],
            })
    
    return results


def extract_link_urls(text: str) -> List[Dict[str, str]]:
    """
    Extract URLs from markdown links.
    Checks for suspicious protocols/content.
    """
    results = []
    for match in MARKDOWN_LINK_PATTERN.finditer(text):
        link_text = match.group(1)
        url = match.group(2)
        
        results.append({
            'type': 'markdown_link',
            'link_text': link_text,
            'url': url,
            'position': match.start(),
            'original': match.group()[:100],
        })
    
    return results


def extract_cdata(text: str) -> List[Dict[str, str]]:
    """
    Extract content from XML CDATA sections.
    """
    results = []
    for match in CDATA_PATTERN.finditer(text):
        content = match.group(1).strip()
        if content:
            results.append({
                'type': 'cdata',
                'content': content,
                'position': match.start(),
                'original': match.group()[:100],
            })
    return results


def extract_latex_text(text: str) -> List[Dict[str, str]]:
    """
    Extract text content from LaTeX commands.
    """
    results = []
    for match in LATEX_TEXT_PATTERN.finditer(text):
        content = match.group(1).strip()
        if content:
            results.append({
                'type': 'latex_text',
                'content': content,
                'position': match.start(),
                'original': match.group()[:100],
            })
    return results


def extract_json_strings(text: str) -> List[Dict[str, Any]]:
    """
    Extract string values from JSON objects/arrays.
    """
    results = []
    
    def extract_strings_from_value(value: Any, path: str = '') -> List[str]:
        """Recursively extract all string values from a JSON structure."""
        strings = []
        if isinstance(value, str):
            if len(value) > 5:  # Skip very short strings
                strings.append(value)
        elif isinstance(value, dict):
            for k, v in value.items():
                strings.extend(extract_strings_from_value(v, f'{path}.{k}'))
        elif isinstance(value, list):
            for i, v in enumerate(value):
                strings.extend(extract_strings_from_value(v, f'{path}[{i}]'))
        return strings
    
    # Try to find and parse JSON objects
    for pattern in [JSON_OBJECT_PATTERN, JSON_ARRAY_PATTERN]:
        for match in pattern.finditer(text):
            json_str = match.group()
            try:
                parsed = json.loads(json_str)
                strings = extract_strings_from_value(parsed)
                if strings:
                    results.append({
                        'type': 'json_strings',
                        'strings': strings,
                        'position': match.start(),
                        'original': json_str[:100] + '...' if len(json_str) > 100 else json_str,
                    })
            except json.JSONDecodeError:
                continue
    
    return results


def extract_all_hidden_content(text: str) -> Dict[str, Any]:
    """
    Main entry point: extract all hidden/embedded content from text.
    Returns dict with all extracted content by type.
    """
    extractions = {
        'html_comments': extract_html_comments(text),
        'code_blocks': extract_code_blocks(text),
        'links': extract_link_urls(text),
        'cdata': extract_cdata(text),
        'latex': extract_latex_text(text),
        'json': extract_json_strings(text),
    }
    
    # Collect all content for scanning
    all_content = []
    for category, items in extractions.items():
        for item in items:
            if 'content' in item:
                all_content.append(item['content'])
            elif 'strings' in item:
                all_content.extend(item['strings'])
            elif 'url' in item:
                all_content.append(item['url'])
    
    return {
        'extractions': extractions,
        'all_content': all_content,
        'has_hidden_content': len(all_content) > 0,
        'extraction_count': len(all_content),
    }


def get_content_for_scanning(text: str) -> List[str]:
    """
    Get a list of all extracted content strings for signal scanning.
    Includes the original text plus all extracted hidden content.
    """
    result = extract_all_hidden_content(text)
    return [text] + result['all_content']
