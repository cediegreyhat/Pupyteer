"""Cobalt Strike Malleable C2 Profile Parser.

Parses CS profile syntax into a normalized dictionary structure
that can be consumed by the converter module to produce Pupyteer's
native YAML profile format.

Supported CS syntax:
  - Global set directives: sleeptime, jitter, useragent, maxdns, dns_idle, etc.
  - http-config, http-get, http-post, http-stager blocks
  - client / server sub-blocks
  - metadata / output / id sub-blocks with encoding chains
  - https-certificate block
  - header, parameter, prepend, append directives
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


class CSParseError(Exception):
    """Raised when a Cobalt Strike profile cannot be parsed."""


# Tokenizer patterns
_TOKEN_COMMENT = re.compile(r"#.*$", re.MULTILINE)
_TOKEN_KW = re.compile(r"""
    \b(set|header|parameter|prepend|append|print|base64|base64url|netbios|
    netbiosu|mask|uri-append|string|stringw|strrep)\b
""", re.VERBOSE)
_TOKEN_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*")
_TOKEN_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_TOKEN_SEMI = re.compile(r";")
_TOKEN_LBRACE = re.compile(r"\{")
_TOKEN_RBRACE = re.compile(r"\}")


def _tokenize(text: str) -> List[str]:
    """Tokenize a CS profile into a flat list of tokens."""
    tokens: List[str] = []
    pos = 0
    length = len(text)
    while pos < length:
        # Skip whitespace
        if text[pos] in " \t\r\n":
            pos += 1
            continue
        # Skip comments
        m = _TOKEN_COMMENT.match(text, pos)
        if m:
            pos = m.end()
            continue
        # Quoted string
        m = _TOKEN_STRING.match(text, pos)
        if m:
            tokens.append(m.group(0))
            pos = m.end()
            continue
        # Punctuation
        if text[pos] == "{":
            tokens.append("{")
            pos += 1
            continue
        if text[pos] == "}":
            tokens.append("}")
            pos += 1
            continue
        if text[pos] == ";":
            tokens.append(";")
            pos += 1
            continue
        # Keyword or identifier
        m = _TOKEN_KW.match(text, pos)
        if m:
            tokens.append(m.group(0))
            pos = m.end()
            continue
        m = _TOKEN_IDENT.match(text, pos)
        if m:
            tokens.append(m.group(0))
            pos = m.end()
            continue
        raise CSParseError(f"Unexpected character at position {pos}: {text[pos]!r}")
    return tokens


def _unquote(s: str) -> str:
    """Remove outer quotes and unescape a CS string literal."""
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        inner = s[1:-1]
        # Unescape \\ and \"
        result = []
        i = 0
        while i < len(inner):
            if inner[i] == "\\" and i + 1 < len(inner):
                nxt = inner[i + 1]
                if nxt == "n":
                    result.append("\n")
                elif nxt == "t":
                    result.append("\t")
                elif nxt == "r":
                    result.append("\r")
                else:
                    result.append(nxt)
                i += 2
            else:
                result.append(inner[i])
                i += 1
        return "".join(result)
    return s


def _parse_value(tokens: List[str], pos: int) -> Tuple[Any, int]:
    """Parse a single value token (string or keyword/ident)."""
    if pos >= len(tokens):
        raise CSParseError("Unexpected end of tokens")
    tok = tokens[pos]
    if tok.startswith('"'):
        return _unquote(tok), pos + 1
    return tok, pos + 1


def parse_cs_string(content: str) -> Dict[str, Any]:
    """Parse a Cobalt Strike profile from a string.

    Args:
        content: CS profile text.

    Returns:
        Normalized dict with parsed profile data.
    """
    tokens = _tokenize(content)
    profile: Dict[str, Any] = {
        "set": {},
        "http-config": {},
        "http-get": {},
        "http-post": {},
        "http-stager": {},
        "https-certificate": {},
        "dns-beacon": {},
        "stage": {},
        "process-inject": {},
        "post-ex": {},
    }
    _parse_top_level(tokens, profile)
    return profile


def parse_cs_file(path: str) -> Dict[str, Any]:
    """Parse a Cobalt Strike profile from a file.

    Args:
        path: Path to .profile file.

    Returns:
        Normalized dict with parsed profile data.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    return parse_cs_string(content)


# ─── Block definitions ──────────────────────────────────────────────────

_TOP_LEVEL_BLOCKS = {
    "http-config",
    "http-get",
    "http-post",
    "http-stager",
    "https-certificate",
    "dns-beacon",
    "stage",
    "process-inject",
    "post-ex",
}

_BLOCK_WITH_CLIENT_SERVER = {"http-get", "http-post", "http-stager"}

_set_directives_top = {
    "sleeptime", "jitter", "useragent", "maxdns", "dns_idle", "dns_sleep",
    "dns_max_txt", "dns_stager_prepend", "dns_stager_subhost", "dns_ttl",
    "sample_name", "host_stage", "tcp_port", "tcp_frame_header",
    "pipename", "pipename_stager", "smb_frame_header", "ssh_banner",
    "ssh_pipename", "data_jitter", "headers_remove",
}


def _parse_top_level(tokens: List[str], profile: Dict[str, Any]) -> None:
    """Parse top-level statements and blocks."""
    pos = 0
    while pos < len(tokens):
        tok = tokens[pos]
        if tok == "set":
            pos += 1
            if pos >= len(tokens):
                raise CSParseError("Expected identifier after 'set'")
            key = tokens[pos]
            pos += 1
            val, pos = _parse_value(tokens, pos)
            if pos < len(tokens) and tokens[pos] == ";":
                pos += 1
            profile["set"][key] = val
        elif tok in _TOP_LEVEL_BLOCKS:
            block_name = tok
            block_name_cs = tokens[pos]  # original case
            pos += 1
            # Optional variant name for http-get/http-post
            variant = None
            if block_name in ("http-get", "http-post") and pos < len(tokens) and tokens[pos].startswith('"'):
                variant, pos = _parse_value(tokens, pos)
            if pos >= len(tokens) or tokens[pos] != "{":
                raise CSParseError(f"Expected '{{' after {block_name_cs}")
            pos += 1  # consume {
            block, pos = _parse_block_body(tokens, pos, block_name)
            if pos >= len(tokens) or tokens[pos] != "}":
                raise CSParseError(f"Expected '}}' to close {block_name_cs}")
            pos += 1  # consume }
            # Store block
            if block_name in _BLOCK_WITH_CLIENT_SERVER and "client" in block:
                block["_has_client_server"] = True
            profile[block_name]["_variant_" + str(variant) if variant else "default"] = block
        else:
            # Unknown top-level directive — skip until ;
            while pos < len(tokens) and tokens[pos] != ";":
                pos += 1
            if pos < len(tokens):
                pos += 1


def _parse_block_body(tokens: List[str], pos: int, context: str) -> Tuple[Dict[str, Any], int]:
    """Parse the body of a block until closing }."""
    block: Dict[str, Any] = {"set": {}}
    while pos < len(tokens) and tokens[pos] != "}":
        tok = tokens[pos]
        if tok == "set":
            pos += 1
            if pos >= len(tokens):
                raise CSParseError("Expected identifier after 'set'")
            key = tokens[pos]
            pos += 1
            val, pos = _parse_value(tokens, pos)
            if pos < len(tokens) and tokens[pos] == ";":
                pos += 1
            block["set"][key] = val
        elif tok == "header":
            pos += 1
            name, pos = _parse_value(tokens, pos)
            value, pos = _parse_value(tokens, pos)
            if pos < len(tokens) and tokens[pos] == ";":
                pos += 1
            block.setdefault("headers", {})[_unquote_if_str(name)] = _unquote_if_str(value)
        elif tok == "parameter":
            pos += 1
            name, pos = _parse_value(tokens, pos)
            value, pos = _parse_value(tokens, pos)
            if pos < len(tokens) and tokens[pos] == ";":
                pos += 1
            block.setdefault("parameters", {})[_unquote_if_str(name)] = _unquote_if_str(value)
        elif tok in _BLOCK_WITH_CLIENT_SERVER_TOKENS:
            # client/server/metadata/output/id sub-blocks
            sub_name = tok
            pos += 1
            if pos < len(tokens) and tokens[pos] == "{":
                pos += 1
                sub_block, pos = _parse_sub_block(tokens, pos)
                if pos < len(tokens) and tokens[pos] == "}":
                    pos += 1
                block[sub_name] = sub_block
            else:
                # e.g., output { print; }
                pass
        elif tok in ("metadata", "output", "id"):
            sub_name = tok
            pos += 1
            if pos < len(tokens) and tokens[pos] == "{":
                pos += 1
                sub_block, pos = _parse_sub_block(tokens, pos)
                if pos < len(tokens) and tokens[pos] == "}":
                    pos += 1
                block[sub_name] = sub_block
            else:
                # Shouldn't happen
                pass
        elif tok in ("transform-x86", "transform-x64"):
            # Stage/process-inject transforms
            sub_name = tok
            pos += 1
            if pos < len(tokens) and tokens[pos] == "{":
                pos += 1
                sub_block, pos = _parse_transform_block(tokens, pos)
                if pos < len(tokens) and tokens[pos] == "}":
                    pos += 1
                block[sub_name] = sub_block
            else:
                pass
        elif tok == "execute":
            pos += 1
            if pos < len(tokens) and tokens[pos] == "{":
                pos += 1
                exec_items, pos = _parse_execute_block(tokens, pos)
                if pos < len(tokens) and tokens[pos] == "}":
                    pos += 1
                block["execute"] = exec_items
            else:
                pass
        else:
            # Skip unknown tokens until ; or }
            while pos < len(tokens) and tokens[pos] not in (";", "}"):
                pos += 1
            if pos < len(tokens) and tokens[pos] == ";":
                pos += 1
    return block, pos


_BLOCK_WITH_CLIENT_SERVER_TOKENS = {"client", "server"}


# Sub-blocks that may nest further ``{ ... }`` bodies inside a client/server
# block (e.g. ``client { metadata { base64; } }``). We recurse into these so
# brace tracking stays balanced and the encoding chains are actually captured.
_NESTED_SUB_BLOCKS = {"metadata", "output", "id", "client", "server"}


def _parse_sub_block(tokens: List[str], pos: int) -> Tuple[Dict[str, Any], int]:
    """Parse a sub-block body: header, metadata, output, id, client, server.

    Nested blocks (``metadata``/``output``/``id`` inside ``client``/``server``)
    are parsed recursively so their ``body``/``encode`` chains survive and the
    block's closing brace is consumed at the correct nesting depth.
    """
    sub: Dict[str, Any] = {}
    encoding_steps: List[str] = []
    prepend_chunks: List[str] = []
    append_chunks: List[str] = []
    headers_dict: Dict[str, str] = {}
    parameters_dict: Dict[str, str] = {}

    def _flush_encoding(target: Dict[str, Any]) -> None:
        if encoding_steps:
            # Preserve order; the list *is* the encode chain.
            target["encoding_chain"] = encoding_steps[:]
        if prepend_chunks:
            target["prepend"] = prepend_chunks[:]
        if append_chunks:
            target["append"] = append_chunks[:]

    def _consume_semi() -> None:
        nonlocal pos
        if pos < len(tokens) and tokens[pos] == ";":
            pos += 1

    while pos < len(tokens) and tokens[pos] != "}":
        tok = tokens[pos]
        if tok == "header":
            pos += 1
            name, pos = _parse_value(tokens, pos)
            # A ``header "Name";`` inside metadata/id/output declares the
            # *carrier* header (no value); ``header "Name" "Value";`` sets one.
            if pos < len(tokens) and tokens[pos] == ";":
                pos += 1
                headers_dict[_unquote_if_str(name)] = ""
                continue
            value, pos = _parse_value(tokens, pos)
            _consume_semi()
            headers_dict[_unquote_if_str(name)] = _unquote_if_str(value)
        elif tok == "parameter":
            pos += 1
            name, pos = _parse_value(tokens, pos)
            # Same one-vs-two-argument distinction as ``header``.
            if pos < len(tokens) and tokens[pos] == ";":
                pos += 1
                parameters_dict[_unquote_if_str(name)] = ""
                continue
            value, pos = _parse_value(tokens, pos)
            _consume_semi()
            parameters_dict[_unquote_if_str(name)] = _unquote_if_str(value)
        elif tok in ("base64", "base64url", "netbios", "netbiosu", "mask", "uri-append"):
            encoding_steps.append(tok)
            pos += 1
            _consume_semi()
        elif tok == "print":
            encoding_steps.append("print")
            pos += 1
            _consume_semi()
        elif tok == "prepend":
            pos += 1
            val, pos = _parse_value(tokens, pos)
            _consume_semi()
            prepend_chunks.append(_unquote_if_str(val))
        elif tok == "append":
            pos += 1
            val, pos = _parse_value(tokens, pos)
            _consume_semi()
            append_chunks.append(_unquote_if_str(val))
        elif tok in _NESTED_SUB_BLOCKS:
            # Recurse into nested metadata/output/id/client/server blocks.
            name = tok
            pos += 1
            if pos < len(tokens) and tokens[pos] == "{":
                pos += 1
                nested, pos = _parse_sub_block(tokens, pos)
                _consume_semi()  # tolerate a stray ';' after the closing brace
                if pos < len(tokens) and tokens[pos] == "}":
                    pos += 1
                sub[name] = nested
            else:
                # Bare directive such as ``output;`` — skip to end of statement.
                while pos < len(tokens) and tokens[pos] not in (";", "}"):
                    pos += 1
                _consume_semi()
        else:
            # Unknown directive: skip to the end of the statement but never
            # past the block's closing brace, so brace tracking stays balanced.
            while pos < len(tokens) and tokens[pos] not in (";", "}"):
                pos += 1
            _consume_semi()

    _flush_encoding(sub)
    if headers_dict:
        sub["headers"] = headers_dict
    if parameters_dict:
        sub["parameters"] = parameters_dict
    return sub, pos


def _parse_transform_block(tokens: List[str], pos: int) -> Tuple[Dict[str, Any], int]:
    """Parse transform-x86/x64 block."""
    result: Dict[str, Any] = {"prepend": [], "append": [], "strrep": {}}
    while pos < len(tokens) and tokens[pos] != "}":
        tok = tokens[pos]
        if tok == "prepend":
            pos += 1
            val, pos = _parse_value(tokens, pos)
            if pos < len(tokens) and tokens[pos] == ";":
                pos += 1
            result["prepend"].append(_unquote_if_str(val))
        elif tok == "append":
            pos += 1
            val, pos = _parse_value(tokens, pos)
            if pos < len(tokens) and tokens[pos] == ";":
                pos += 1
            result["append"].append(_unquote_if_str(val))
        elif tok == "strrep":
            pos += 1
            target, pos = _parse_value(tokens, pos)
            replacement, pos = _parse_value(tokens, pos)
            if pos < len(tokens) and tokens[pos] == ";":
                pos += 1
            result["strrep"][_unquote_if_str(target)] = _unquote_if_str(replacement)
        else:
            if pos < len(tokens) and tokens[pos] == ";":
                pos += 1
            else:
                pos += 1
    return result, pos


def _parse_execute_block(tokens: List[str], pos: int) -> Tuple[List[str], int]:
    """Parse execute block."""
    items: List[str] = []
    while pos < len(tokens) and tokens[pos] != "}":
        tok = tokens[pos]
        if tok == ";":
            pos += 1
            continue
        # Execution method names can contain special chars like !
        method = tok
        pos += 1
        # Some methods have a string argument (e.g., CreateThread "ntdll!...")
        if pos < len(tokens) and tokens[pos].startswith('"'):
            arg, pos = _parse_value(tokens, pos)
            items.append(f"{method} {_unquote_if_str(arg)}")
        else:
            items.append(method)
        if pos < len(tokens) and tokens[pos] == ";":
            pos += 1
    return items, pos


def _unquote_if_str(val: Any) -> str:
    """Ensure value is a string."""
    if isinstance(val, str):
        return val
    return str(val)
