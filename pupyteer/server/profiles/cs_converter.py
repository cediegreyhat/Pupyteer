"""Cobalt Strike Malleable C2 Profile Converter.

Converts a parsed CS profile (from cs_parser.py) into Pupyteer's
native YAML profile format.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional


BC_SECURITY_REPO = "https://github.com/BC-SECURITY/Malleable-C2-Profiles"


def _get_category(source_path: Optional[str] = None, profile_name: str = "") -> str:
    """Infer category from profile name or source path."""
    name_lower = profile_name.lower()
    # APT indicators
    apt_keywords = ["apt", "dukes", "sofacy", "apt29", "apt1", "cozy", "bear", "fancy",
                    "turla", "apt28", "apt10", "chches", "apt41", "bluenoroff", "lazarus"]
    # Crimeware indicators
    crime_keywords = ["emotet", "trickbot", "qakbot", "icedid", "ursnif", "zeus", "citadel",
                      "dridex", "gozi", "gandcrab", "ryuk", "conti", "revil", "lockbit",
                      "blackmatter", "alphv", "hive", "royal", "play", "medusa",
                      "formbook", "lokibot", "netwire", "agenttesla", "asyncrat"]

    for kw in apt_keywords:
        if kw in name_lower:
            return "apt"
    for kw in crime_keywords:
        if kw in name_lower:
            return "crimeware"

    if source_path:
        sp_lower = source_path.lower()
        if "/apt/" in sp_lower or "\\apt\\" in sp_lower:
            return "apt"
        if "/crimeware/" in sp_lower or "\\crimeware\\" in sp_lower:
            return "crimeware"

    return "normal"


def convert_cs_to_pupyteer(parsed: Dict[str, Any], profile_name: str = "unnamed",
                           source: str = "BC-SECURITY/Malleable-C2-Profiles",
                           category: Optional[str] = None) -> Dict[str, Any]:
    """Convert a parsed CS profile dict into Pupyteer YAML format.

    Args:
        parsed: Output from cs_parser.parse_cs_string() or parse_cs_file().
        profile_name: Name for the profile.
        source: Source reference (e.g., repo name).
        category: "normal", "apt", or "crimeware". Auto-detected if None.

    Returns:
        Dictionary in Pupyteer's YAML profile format.
    """
    # Sanitize profile name: replace dots and other invalid chars with hyphens
    sanitized_name = profile_name.replace(".", "-").replace(" ", "-")
    # Collapse consecutive hyphens
    while "--" in sanitized_name:
        sanitized_name = sanitized_name.replace("--", "-")
    profile_name = sanitized_name.strip("-") or "unnamed"
    if category is None:
        category = _get_category(profile_name=profile_name)

    # Build base structure
    result: Dict[str, Any] = {
        "profile": {
            "name": profile_name,
            "version": "1.0",
            "source": source,
            "category": category,
        },
        "transport": {
            "protocol": "https",
            "host": "localhost",
            "port": 443,
        },
        "c2": {},
    }

    # Global set directives
    global_set = parsed.get("set", {})

    # Sleep time (CS uses milliseconds)
    if "sleeptime" in global_set:
        try:
            sleep_ms = int(global_set["sleeptime"])
        except (ValueError, TypeError):
            sleep_ms = 60000
        result["c2"]["sleep_ms"] = sleep_ms
    else:
        result["c2"]["sleep_ms"] = 60000

    # Jitter
    if "jitter" in global_set:
        try:
            jitter_pct = int(global_set["jitter"])
        except (ValueError, TypeError):
            jitter_pct = 0
        result["c2"]["jitter"] = jitter_pct
    else:
        result["c2"]["jitter"] = 0

    # User-agent
    if "useragent" in global_set:
        result["c2"]["user_agent"] = str(global_set["useragent"])

    # DNS settings
    if "dns_idle" in global_set:
        result["c2"]["dns_idle"] = str(global_set["dns_idle"])
    if "maxdns" in global_set:
        try:
            result["c2"]["maxdns"] = int(global_set["maxdns"])
        except (ValueError, TypeError):
            pass
    if "dns_sleep" in global_set:
        try:
            result["c2"]["dns_sleep"] = int(global_set["dns_sleep"])
        except (ValueError, TypeError):
            pass

    # TCP port (if TCP beacon)
    if "tcp_port" in global_set:
        try:
            result["transport"]["port"] = int(global_set["tcp_port"])
            result["transport"]["protocol"] = "tcp"
        except (ValueError, TypeError):
            pass

    # Extract HTTP data
    http_get_block = _get_default_block(parsed.get("http-get", {}))
    http_post_block = _get_default_block(parsed.get("http-post", {}))

    # Process http-get
    if http_get_block:
        http_get_entry = _convert_http_block(http_get_block, "http-get")
        if http_get_entry:
            result["c2"]["http_get"] = http_get_entry

    # Process http-post
    if http_post_block:
        http_post_entry = _convert_http_block(http_post_block, "http-post")
        if http_post_entry:
            result["c2"]["http_post"] = http_post_entry

    # Process http-config for server headers and trust_x_forwarded_for
    http_config_block = _get_default_block(parsed.get("http-config", {}))
    if http_config_block:
        _apply_http_config(result, http_config_block)

    # Extract server headers (from http-get server block if present)
    server_headers = {}
    if http_get_block and "server" in http_get_block:
        server_cfg = http_get_block["server"]
        if "headers" in server_cfg:
            server_headers.update(server_cfg["headers"])
    if http_post_block and "server" in http_post_block:
        server_cfg = http_post_block["server"]
        if "headers" in server_cfg:
            server_headers.update(server_cfg["headers"])
    if server_headers:
        result["c2"]["server_headers"] = server_headers

    # Process https-certificate
    cert = _extract_certificate(parsed)
    if cert:
        result["transport"]["certificate"] = cert

    return result


def _get_default_block(blocks_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Get the default variant block from a parsed blocks dict.

    The parser stores blocks under keys like 'default', '_variant_<name>', etc.
    """
    if not blocks_dict:
        return None
    # Priority: 'default' key, then first key that doesn't start with '_'
    if "default" in blocks_dict:
        return blocks_dict["default"]
    for key, val in blocks_dict.items():
        if not key.startswith("_"):
            return val
    # Fallback: return first value
    for val in blocks_dict.values():
        return val
    return None


def _convert_http_block(block: Dict[str, Any], block_type: str) -> Optional[Dict[str, Any]]:
    """Convert a parsed http-get/post block to Pupyteer format."""
    entry: Dict[str, Any] = {}

    block_set = block.get("set", {})
    client_block = block.get("client", {})
    server_block = block.get("server", {})

    # URI
    if "uri" in block_set:
        entry["uri"] = str(block_set["uri"])
    else:
        return None  # No URI, not usable

    # Verb
    if "verb" in block_set:
        entry["verb"] = str(block_set["verb"]).upper()

    # Client headers
    if "headers" in client_block:
        entry["headers"] = {str(k): str(v) for k, v in client_block["headers"].items()}

    # Client parameters
    if "parameters" in client_block:
        entry["query_params"] = {str(k): str(v) for k, v in client_block["parameters"].items()}

    # Metadata block (session data)
    if "metadata" in client_block:
        meta = client_block["metadata"]
        encoding_chain = meta.get("encoding_chain", [])
        # Determine encoding type from the chain
        encoding = _determine_encoding(encoding_chain, "metadata")
        if encoding:
            entry["metadata_encoding"] = encoding

        if "prepend" in meta:
            entry["metadata_prepend"] = "".join(meta["prepend"])
        if "append" in meta:
            entry["metadata_append"] = "".join(meta["append"])
        if "headers" in meta:
            # The header field tells which header carries metadata
            header_name = list(meta["headers"].keys())
            if header_name:
                entry["metadata_header"] = header_name[0]

    # ID block (beacon session ID)
    if "id" in client_block:
        id_block = client_block["id"]
        encoding_chain = id_block.get("encoding_chain", [])
        encoding = _determine_encoding(encoding_chain, "id")
        if encoding:
            entry["id_encoding"] = encoding

        if "prepend" in id_block:
            entry["id_prepend"] = "".join(id_block["prepend"])
        if "append" in id_block:
            entry["id_append"] = "".join(id_block["append"])
        if "headers" in id_block:
            header_name = list(id_block["headers"].keys())
            if header_name:
                entry["id_header"] = header_name[0]
        if "parameters" in id_block:
            param_name = list(id_block["parameters"].keys())
            if param_name:
                entry["id_parameter"] = param_name[0]

    # Output block (task/response data)
    output_block = None
    if "output" in client_block:
        output_block = client_block["output"]
    elif "output" in server_block:
        output_block = server_block["output"]

    if output_block:
        encoding_chain = output_block.get("encoding_chain", [])
        encoding = _determine_encoding(encoding_chain, "output")
        if encoding:
            entry["output_encoding"] = encoding
        if "prepend" in output_block:
            entry["output_prepend"] = "".join(output_block["prepend"])
        if "append" in output_block:
            entry["output_append"] = "".join(output_block["append"])

    # Server headers (for this specific block)
    if "headers" in server_block:
        entry["response_headers"] = {str(k): str(v) for k, v in server_block["headers"].items()}

    return entry if "uri" in entry else None


def _determine_encoding(chain: List[str], context: str) -> Optional[str]:
    """Determine the primary encoding from an encoding chain.

    CS profiles can have multiple transforms (e.g., base64 then mask).
    We represent this as a string like 'base64' or 'mask,base64'.
    """
    if not chain:
        return None
    # Filter out non-encoding tokens
    encoding_tokens = []
    for tok in chain:
        if tok in ("base64", "base64url", "netbios", "netbiosu", "mask", "uri-append"):
            encoding_tokens.append(tok)
        # "print" is the final terminator, not encoding
    if not encoding_tokens:
        return None
    # Return the primary (first) encoding
    return encoding_tokens[0] if len(encoding_tokens) == 1 else ",".join(encoding_tokens)


def _apply_http_config(result: Dict[str, Any], config_block: Dict[str, Any]) -> None:
    """Apply http-config block settings."""
    config_set = config_block.get("set", {})
    if "trust_x_forwarded_for" in config_set:
        result["c2"]["trust_x_forwarded_for"] = config_set["trust_x_forwarded_for"].lower() == "true"

    # http-config headers are global response headers
    if "headers" in config_block:
        result["c2"].setdefault("server_headers", {}).update(
            {str(k): str(v) for k, v in config_block["headers"].items()}
        )


def _extract_certificate(parsed: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Extract https-certificate info."""
    cert_blocks = parsed.get("https-certificate", {})
    cert_block = _get_default_block(cert_blocks)
    if not cert_block:
        return None

    cert_set = cert_block.get("set", {})
    if not cert_set:
        return None

    cert: Dict[str, str] = {}
    # Map CS cert fields to our format
    field_map = {
        "C": "C",
        "CN": "CN",
        "L": "L",
        "O": "O",
        "OU": "OU",
        "ST": "ST",
        "validity": "validity",
        "keystore": "keystore",
        "password": "password",
    }
    for cs_field, out_field in field_map.items():
        if cs_field in cert_set:
            cert[out_field] = str(cert_set[cs_field])

    return cert if cert else None


def convert_cs_file_to_yaml(parsed: Dict[str, Any], profile_name: str,
                            output_path: str) -> str:
    """Convert and write to a YAML file."""
    import yaml
    result = convert_cs_to_pupyteer(parsed, profile_name)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as fh:
        yaml.safe_dump(result, fh, default_flow_style=False, sort_keys=False)
    return output_path
