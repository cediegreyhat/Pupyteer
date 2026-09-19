"""Test configuration profiles for Pupyteer evasion testing.

Profiles define which obfuscation techniques to apply during a test run,
allowing reproducible, comparable detection-resilience experiments.

Each profile is a named ObfuscationConfig preset that maps to a specific
evasion strategy (e.g., XOR-only, full chain, PE manipulation, anti-analysis).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, List, Optional

from pupyteer.server.evasion.obfuscator import EncodingScheme, ObfuscationConfig


@dataclass
class TestConfigurationProfile:
    """Named preset of obfuscation settings for reproducible tests.

    A profile captures exactly which techniques were applied so that
    detection results can be correlated with specific evasion strategies.
    """

    # Domain model, not a pytest test class — the "Test" prefix collides with
    # pytest's default collection pattern.
    __test__: ClassVar[bool] = False

    name: str
    description: str = ""
    obfuscation: ObfuscationConfig = field(default_factory=ObfuscationConfig)
    controls: List[str] = field(default_factory=list)
    environment: str = "local"
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "obfuscation_scheme": self.obfuscation.scheme.value if self.obfuscation.scheme else None,
            "encrypt_strings": self.obfuscation.encrypt_strings,
            "obfuscate_imports": self.obfuscation.obfuscate_imports,
            "randomize_pe_sections": self.obfuscation.randomize_pe_sections,
            "strip_pe_debug": self.obfuscation.strip_pe_debug,
            "modify_pe_timestamp": self.obfuscation.modify_pe_timestamp,
            "anti_sandbox": self.obfuscation.anti_sandbox,
            "anti_debug": self.obfuscation.anti_debug,
            "anti_vm": self.obfuscation.anti_vm,
            "injection_enabled": self.obfuscation.injection_enabled,
            "injection_method": self.obfuscation.injection_method,
            "controls": self.controls,
            "environment": self.environment,
            "tags": self.tags,
        }


# ─── Built-in Profiles ────────────────────────────────────────────────


PROFILE_BASIC_XOR = TestConfigurationProfile(
    name="basic_xor",
    description="Single XOR encryption — minimal evasion baseline",
    obfuscation=ObfuscationConfig(
        scheme=EncodingScheme.XOR,
        xor_key_size=32,
        encrypt_strings=False,
        obfuscate_imports=False,
        randomize_pe_sections=False,
        strip_pe_debug=False,
        modify_pe_timestamp=False,
        anti_sandbox=False,
        anti_debug=False,
        anti_vm=False,
    ),
    controls=["yara", "sigma"],
    tags=["baseline", "minimal"],
)


PROFILE_FULL_CHAIN = TestConfigurationProfile(
    name="full_chain",
    description="Full encryption chain: XOR → RC4 → AES",
    obfuscation=ObfuscationConfig(
        scheme=EncodingScheme.CHAIN,
        xor_key_size=32,
        rc4_key_size=16,
        aes_key_size=32,
        encrypt_strings=False,
        obfuscate_imports=False,
        randomize_pe_sections=False,
        strip_pe_debug=False,
        modify_pe_timestamp=False,
        anti_sandbox=False,
        anti_debug=False,
        anti_vm=False,
    ),
    controls=["windows_defender", "yara", "amsi", "sigma"],
    tags=["full-encryption", "chain"],
)


PROFILE_PE_MANIPULATION = TestConfigurationProfile(
    name="pe_manipulation",
    description="PE header manipulation: section rename, timestamp randomization, debug strip",
    obfuscation=ObfuscationConfig(
        scheme=EncodingScheme.XOR,
        xor_key_size=16,
        encrypt_strings=False,
        obfuscate_imports=False,
        randomize_pe_sections=True,
        strip_pe_debug=True,
        modify_pe_timestamp=True,
        anti_sandbox=False,
        anti_debug=False,
        anti_vm=False,
    ),
    controls=["yara", "pe-sieve", "hollows_hunter"],
    tags=["pe", "static-evasion"],
)


PROFILE_ANTI_ANALYSIS = TestConfigurationProfile(
    name="anti_analysis",
    description="Anti-sandbox, anti-debug, anti-VM checks with light obfuscation",
    obfuscation=ObfuscationConfig(
        scheme=EncodingScheme.XOR,
        xor_key_size=16,
        encrypt_strings=False,
        obfuscate_imports=False,
        randomize_pe_sections=False,
        strip_pe_debug=False,
        modify_pe_timestamp=False,
        anti_sandbox=True,
        anti_debug=True,
        anti_vm=True,
    ),
    controls=["windows_defender", "amsi", "etw"],
    tags=["anti-analysis", "dynamic"],
)


PROFILE_ANTI_INJECTION = TestConfigurationProfile(
    name="anti_injection",
    description="Encrypted payload with process injection stubs (lab-only)",
    obfuscation=ObfuscationConfig(
        scheme=EncodingScheme.RC4,
        rc4_key_size=32,
        encrypt_strings=True,
        obfuscate_imports=True,
        randomize_pe_sections=True,
        strip_pe_debug=True,
        modify_pe_timestamp=True,
        anti_sandbox=True,
        anti_debug=True,
        anti_vm=True,
        injection_enabled=True,
        injection_method="createremotethread",
    ),
    controls=["windows_defender", "crowdstrike", "sentinelone", "carbon_black", "yara", "sigma", "amsi", "etw"],
    tags=["injection", "full-suite", "lab-only"],
)


PROFILE_STEALTH_FULL = TestConfigurationProfile(
    name="stealth_full",
    description="Maximum evasion: all techniques combined for full red-team simulation",
    obfuscation=ObfuscationConfig(
        scheme=EncodingScheme.CHAIN,
        xor_key_size=32,
        rc4_key_size=16,
        aes_key_size=32,
        encrypt_strings=True,
        obfuscate_imports=True,
        randomize_pe_sections=True,
        strip_pe_debug=True,
        modify_pe_timestamp=True,
        anti_sandbox=True,
        anti_debug=True,
        anti_vm=True,
        injection_enabled=True,
        injection_method="thread_hijack",
    ),
    controls=["windows_defender", "crowdstrike", "sentinelone", "carbon_black", "elastic_siem", "yara", "sigma", "amsi", "etw"],
    tags=["stealth", "full-suite", "red-team"],
)


# Registry of all built-in profiles
BUILTIN_PROFILES: Dict[str, TestConfigurationProfile] = {
    p.name: p for p in [
        PROFILE_BASIC_XOR,
        PROFILE_FULL_CHAIN,
        PROFILE_PE_MANIPULATION,
        PROFILE_ANTI_ANALYSIS,
        PROFILE_ANTI_INJECTION,
        PROFILE_STEALTH_FULL,
    ]
}


def get_profile(name: str) -> Optional[TestConfigurationProfile]:
    """Retrieve a built-in profile by name."""
    return BUILTIN_PROFILES.get(name)


def list_profiles() -> List[Dict[str, Any]]:
    """List all built-in profiles as dicts."""
    return [p.to_dict() for p in BUILTIN_PROFILES.values()]


def create_custom_profile(
    name: str,
    description: str = "",
    scheme: str = "xor",
    controls: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    **kwargs: Any,
) -> TestConfigurationProfile:
    """Build a TestConfigurationProfile from keyword arguments.

    Any ObfuscationConfig field can be overridden via kwargs.
    """
    scheme_enum = EncodingScheme(scheme) if scheme in [s.value for s in EncodingScheme] else EncodingScheme.XOR
    obfuscation = ObfuscationConfig(scheme=scheme_enum, **kwargs)
    return TestConfigurationProfile(
        name=name,
        description=description,
        obfuscation=obfuscation,
        controls=controls or [],
        tags=tags or ["custom"],
    )
