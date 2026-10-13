"""Golden round-trip tests for Cobalt Strike ``.profile`` conversion.

These lock in the fix for the lossy CS parser: ``_parse_sub_block`` now
recurses into nested ``http-get``/``http-post`` sub-blocks (``metadata`` /
``output`` / ``id`` / ``client`` / ``server``) so that the important fields —
the request ``uri`` and the metadata/id encoding chains — actually survive
parsing instead of silently coming back empty.

Every default profile ships in ``default_profiles/`` and the tests assert:

  * the real GET and POST ``uri`` for each of the 7 files,
  * the metadata ``encode`` chain (or, for slack which has no encoder, the
    captured ``prepend`` + carrier header) for the GET direction,
  * the beacon-id ``encode`` chain (or captured id header/parameter) for the
    POST direction,
  * that no profile silently converts to an empty ``c2`` section, and
  * that the emitted top-level sections stay within what ``validator.py``
    accepts (only ``profile``/``transport``/``c2``), with the converted
    profile passing validation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from pupyteer.server.profiles.cs_parser import parse_cs_file, parse_cs_string
from pupyteer.server.profiles.cs_converter import convert_cs_to_pupyteer
from pupyteer.server.profiles.validator import validate_profile

DEFAULT_PROFILE_DIR = (
    Path(__file__).resolve().parents[2] / "server" / "profiles" / "default_profiles"
)

# Expected golden data recovered from the ACTUAL contents of each shipped
# profile.  Kept explicit so a regression in the parser (dropping a nested
# block) fails loudly rather than producing an empty c2 section.
GOLDEN: Dict[str, Dict[str, Any]] = {
    "amazon": {
        "get_uri": "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books",
        "get_meta_encoding": "base64",
        "get_meta_prepend": "session-token=skin=noskin;",
        "get_meta_header": "Cookie",
        "post_uri": "/N4215/adj/amzn.us.sr.aps",
        "post_id_parameter": "sn",
    },
    "apt1_virtuallythere": {
        "get_uri": "/zOMGAPT",
        "get_meta_encoding": "netbiosu",
        "post_uri": "/BUYTHEAPTDETECTORNOW",
        # ``base64url; uri-append;`` is a two-step chain.
        "post_id_encoding": "base64url,uri-append",
    },
    "dukes_apt29": {
        "get_uri": "/jquery-3.3.1.min.woff2",
        "get_meta_encoding": "base64",
        "get_meta_header": "Cookie",
        "post_uri": "/jquery-3.3.2.min.woff2",
        "post_id_encoding": "base64url",
    },
    "emotet": {
        "get_uri": "/LSnmkxT/",
        "get_meta_encoding": "netbios",
        "get_meta_header": "Cookie",
        "post_uri": "/LSnmkXT/",
        "post_id_encoding": "base64url",
    },
    "jquery-c2.4.2": {
        "get_uri": "/jquery-3.3.1.min.js",
        "get_meta_encoding": "base64url",
        "post_uri": "/jquery-3.3.2.min.js",
        # ``mask; base64url;`` chain, plus the __cfduid carrier parameter.
        "post_id_encoding": "mask,base64url",
        "post_id_parameter": "__cfduid",
    },
    "slack": {
        "get_uri": "/messages/C0527B0NM",
        # slack metadata has no encoder; the nested block must still be seen.
        "get_meta_prepend": "d=_ga=GA1.2.875;b=.12vPkW22o;",
        "get_meta_header": "Cookie",
        "post_uri": "/api/api.test",
        "post_id_header": "_ga",
    },
    "sofacy": {
        "get_uri": "/url/544036/cormac.mcr",
        "get_meta_encoding": "base64",
        "get_meta_header": "Cookie",
        "post_uri": "/k9/eR3/a/UE/eR.pdf/bKC=xCCmnuXFZ6Chw2ah1oM=",
        "post_id_encoding": "netbios",
    },
}


def _profile_names() -> List[str]:
    return sorted(p.stem for p in DEFAULT_PROFILE_DIR.glob("*.profile"))


def _convert(name: str) -> Dict[str, Any]:
    path = DEFAULT_PROFILE_DIR / f"{name}.profile"
    parsed = parse_cs_file(str(path))
    return convert_cs_to_pupyteer(parsed, profile_name=name)


# ── Structural / presence checks ──────────────────────────────────────────

def test_default_profiles_directory_ships_all_seven_files():
    names = _profile_names()
    assert set(names) == set(GOLDEN), (
        f"expected exactly the 7 shipped default profiles, found: {names}"
    )


# ── Golden round-trip over ALL 7 files ────────────────────────────────────

@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_both_http_directions_yield_their_real_uri(name: str):
    """The historical bug: http-post came back empty for every file, and even
    http-get vanished for jquery. Both directions must now yield their uri."""
    exp = GOLDEN[name]
    c2 = _convert(name)["c2"]

    http_get = c2.get("http_get")
    http_post = c2.get("http_post")

    assert http_get and http_get.get("uri") == exp["get_uri"], (
        f"{name}: http_get uri lost/garbled -> {http_get}"
    )
    assert http_post and http_post.get("uri") == exp["post_uri"], (
        f"{name}: http_post uri lost/garbled -> {http_post}"
    )


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_metadata_encode_chain_is_recursed_into(name: str):
    """Nested ``client { metadata { ... } }`` blocks must be captured, not
    dropped at the first inner brace."""
    exp = GOLDEN[name]
    http_get = _convert(name)["c2"]["http_get"]

    if "get_meta_encoding" in exp:
        assert http_get.get("metadata_encoding") == exp["get_meta_encoding"], (
            f"{name}: metadata encode chain lost -> {http_get}"
        )
    if "get_meta_prepend" in exp:
        assert http_get.get("metadata_prepend") == exp["get_meta_prepend"], (
            f"{name}: metadata prepend chain lost -> {http_get}"
        )
    if "get_meta_header" in exp:
        assert http_get.get("metadata_header") == exp["get_meta_header"], (
            f"{name}: metadata carrier header lost -> {http_get}"
        )


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_id_encode_chain_is_recursed_into(name: str):
    """Nested ``client { id { ... } }`` blocks in http-post must be captured."""
    exp = GOLDEN[name]
    http_post = _convert(name)["c2"]["http_post"]

    if "post_id_encoding" in exp:
        assert http_post.get("id_encoding") == exp["post_id_encoding"], (
            f"{name}: id encode chain lost -> {http_post}"
        )
    if "post_id_parameter" in exp:
        assert http_post.get("id_parameter") == exp["post_id_parameter"], (
            f"{name}: id carrier parameter lost -> {http_post}"
        )
    if "post_id_header" in exp:
        assert http_post.get("id_header") == exp["post_id_header"], (
            f"{name}: id carrier header lost -> {http_post}"
        )


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_no_file_silently_parses_to_empty_c2_section(name: str):
    """A conversion that yields neither GET nor POST uri is a silent failure;
    it must never be mistaken for success."""
    result = _convert(name)
    c2 = result["c2"]
    hg = c2.get("http_get") or {}
    hp = c2.get("http_post") or {}
    assert hg.get("uri") or hp.get("uri"), (
        f"{name}: converted to an empty c2 section (silent parse failure): {c2}"
    )


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_converted_profile_passes_validator_and_only_emits_known_sections(name: str):
    """Keep the emitted sections consistent with what validator.py accepts:
    only ``profile``/``transport``/``c2`` at the top level, and validation with
    no errors."""
    result = _convert(name)
    assert set(result.keys()) == {"profile", "transport", "c2"}, (
        f"{name}: converter emitted sections outside the validated schema: "
        f"{sorted(result.keys())}"
    )
    res = validate_profile(result)
    assert res.is_valid, f"{name}: converted profile failed validation: {res.error_messages()}"


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_no_bogus_carrier_semicolon_header_regression(name: str):
    """Regression guard: a single-argument ``header "Cookie";`` used to be
    parsed as ``{'Cookie': ';'}``. No converted header value may be ``';'``."""
    c2 = _convert(name)["c2"]
    for entry_key in ("http_get", "http_post"):
        entry = c2.get(entry_key) or {}
        for header_map in (entry.get("headers"), entry.get("response_headers")):
            if header_map:
                assert all(v != ";" for v in header_map.values()), (
                    f"{name}: {entry_key} regressed to a bogus ';' header value: {header_map}"
                )


# ── Focused parser-structure unit tests (nesting proof) ────────────────────

def test_parse_nests_metadata_under_client_and_output_under_server():
    """Directly assert the parser's nested structure, independent of the
    converter, so a future refactor cannot quietly re-flatten it."""
    content = """
    http-get {
        set uri "/nested";
        client {
            header "Accept" "*/*";
            metadata {
                base64;
                prepend "p=";
                header "Cookie";
            }
        }
        server {
            header "Server" "test";
            output {
                netbios;
                print;
            }
        }
    }
    """
    parsed = parse_cs_string(content)
    block = parsed["http-get"]["default"]

    assert block["set"]["uri"] == "/nested"
    client = block["client"]
    server = block["server"]

    # metadata is nested under client, not a sibling of it.
    assert "metadata" in client, "metadata block was not recursed into client"
    assert client["metadata"]["encoding_chain"] == ["base64"]
    assert client["metadata"]["prepend"] == ["p="]
    assert client["metadata"]["headers"] == {"Cookie": ""}
    assert client["headers"] == {"Accept": "*/*"}

    # output is nested under server with its own chain.
    assert "output" in server, "output block was not recursed into server"
    assert server["output"]["encoding_chain"] == ["netbios", "print"]
    assert server["headers"] == {"Server": "test"}


def test_parse_recovers_http_post_after_http_get():
    """The old brace desync dropped the second block entirely; verify the
    http-post block following an http-post is still parsed and stored."""
    content = """
    http-get { set uri "/g"; client { metadata { base64; header "Cookie"; } } }
    http-post { set uri "/p"; client { id { netbios; parameter "id"; } } }
    """
    parsed = parse_cs_string(content)
    assert parsed["http-get"]["default"]["set"]["uri"] == "/g"
    assert parsed["http-post"]["default"]["set"]["uri"] == "/p"
    assert parsed["http-post"]["default"]["client"]["id"]["encoding_chain"] == ["netbios"]
    assert parsed["http-post"]["default"]["client"]["id"]["parameters"] == {"id": ""}


def test_convert_handles_variant_named_blocks_without_default():
    """A profile that only ships a *named* variant (no default block) must not
    be silently dropped by the converter's block selection."""
    content = """
    http-post "submit" {
        set uri "/submit.php";
        client { id { base64url; uri-append; } }
    }
    """
    parsed = parse_cs_string(content)
    result = convert_cs_to_pupyteer(parsed, profile_name="variantonly")
    http_post = result["c2"].get("http_post")
    assert http_post and http_post["uri"] == "/submit.php"
    assert http_post["id_encoding"] == "base64url,uri-append"
