"""GhostRE inspectors: pure-stdlib, bounds-checked format parsing.

``inspect_path`` is the single entry point. It returns one plain
dict (JSON-ready) describing a file or a JavaScript application
directory:

    path, size, sha256, format, detail, entropy, strings, warnings

``format`` is one of: elf, pe, macho, wasm, apk, zip, pyc, sqlite,
plist, javascript-app, text, unknown.

Inspectors never raise on malformed input: they return whatever
parsed and note the problem in ``warnings``. The only hard failure
is a path that does not exist or cannot be read, which raises
``InspectError`` (the CLI turns that into exit code 2).
"""
from __future__ import annotations

import hashlib
import math
import os
import plistlib
import re
import sqlite3
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path
from urllib.parse import quote

BLOCK_SIZE = 4096
MAX_STRINGS = 40
MIN_STRING = 6
MAX_FILES = 100
MAX_ENTRIES = 100

JS_SUFFIXES = {".js", ".mjs", ".cjs", ".json"}
SKIP_DIRS = {"node_modules", ".git", "__pycache__"}


class InspectError(Exception):
    """The path is missing or unreadable (CLI exit code 2)."""


# ---------------------------------------------------------------- #
# small total helpers

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return round(h, 6)


def entropy_block(data: bytes) -> dict:
    blocks = []
    for off in range(0, len(data), BLOCK_SIZE):
        chunk = data[off:off + BLOCK_SIZE]
        blocks.append({"offset": off, "entropy": _entropy(chunk)})
    return {"overall": _entropy(data), "blocks": blocks}


def extract_strings(data: bytes, limit: int = MAX_STRINGS) -> list:
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= MIN_STRING:
                out.append(cur.decode("ascii"))
                if len(out) >= limit:
                    return out
            cur = bytearray()
    if len(cur) >= MIN_STRING and len(out) < limit:
        out.append(cur.decode("ascii"))
    return out


def _u16(data: bytes, off: int, en: str = "<") -> int:
    return struct.unpack_from(en + "H", data, off)[0]


def _u32(data: bytes, off: int, en: str = "<") -> int:
    return struct.unpack_from(en + "I", data, off)[0]


def _cstring(data: bytes, off: int, maxlen: int = 4096) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, min(len(data), off + maxlen))
    if end < 0:
        end = min(len(data), off + maxlen)
    return data[off:end].decode("utf-8", "replace")


# ---------------------------------------------------------------- #
# ELF

ELF_MACHINES = {
    0: "none", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
    40: "ARM", 50: "IA-64", 62: "x86-64", 183: "AArch64",
    243: "RISC-V",
}
ELF_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}


def inspect_elf(data: bytes, warnings: list) -> dict:
    d = {}
    if len(data) < 16:
        warnings.append("elf: file shorter than e_ident")
        return d
    ei_class = data[4]
    ei_data = data[5]
    bits = 64 if ei_class == 2 else 32
    en = ">" if ei_data == 2 else "<"
    d["bits"] = bits
    d["endianness"] = "big" if ei_data == 2 else "little"
    try:
        e_type = _u16(data, 16, en)
        e_machine = _u16(data, 18, en)
        d["type"] = e_type
        d["type_name"] = ELF_TYPES.get(e_type, "unknown")
        d["machine"] = e_machine
        d["machine_name"] = ELF_MACHINES.get(e_machine, "unknown")
        if bits == 64:
            d["entry_point"] = struct.unpack_from(en + "Q", data, 24)[0]
            shoff = struct.unpack_from(en + "Q", data, 40)[0]
            phentsize = _u16(data, 54, en)
            phnum = _u16(data, 56, en)
            shentsize = _u16(data, 58, en)
            shnum = _u16(data, 60, en)
            shstrndx = _u16(data, 62, en)
            shdr_size = 64
        else:
            d["entry_point"] = _u32(data, 24, en)
            shoff = _u32(data, 32, en)
            phentsize = _u16(data, 42, en)
            phnum = _u16(data, 44, en)
            shentsize = _u16(data, 46, en)
            shnum = _u16(data, 48, en)
            shstrndx = _u16(data, 50, en)
            shdr_size = 40
        d["program_headers"] = phnum

        # Section names via the section-header string table.
        names = []
        if shoff and shentsize >= shdr_size and shnum:
            headers = []
            for i in range(shnum):
                off = shoff + i * shentsize
                if off + shdr_size > len(data):
                    warnings.append("elf: section header table truncated")
                    break
                if bits == 64:
                    name_off = _u32(data, off, en)
                    sh_size = struct.unpack_from(en + "Q", data,
                                                 off + 32)[0]
                    sh_offset = struct.unpack_from(en + "Q", data,
                                                   off + 24)[0]
                else:
                    name_off = _u32(data, off, en)
                    sh_size = _u32(data, off + 20, en)
                    sh_offset = _u32(data, off + 16, en)
                headers.append((name_off, sh_offset, sh_size))
            if 0 <= shstrndx < len(headers):
                _, str_off, str_size = headers[shstrndx]
                strtab = data[str_off:str_off + str_size]
                for name_off, _, _ in headers:
                    names.append(_cstring(strtab, name_off, 1024))
            else:
                warnings.append("elf: no section string table")
        elif shoff and shnum == 0:
            warnings.append("elf: extended section count not resolved")
        d["sections"] = names
        d["section_count"] = len(names)
    except (struct.error, IndexError) as e:
        warnings.append(f"elf: truncated header ({e})")
    return d


# ---------------------------------------------------------------- #
# PE

PE_MACHINES = {
    0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM",
    0x01C4: "ARMv7", 0xAA64: "ARM64", 0x0200: "IA-64",
}
PE_SUBSYSTEMS = {
    1: "native", 2: "windows-gui", 3: "windows-console",
    5: "os2-console", 7: "posix-console", 9: "windows-ce-gui",
    10: "efi-application", 11: "efi-boot-driver",
    12: "efi-runtime-driver", 13: "efi-rom", 14: "xbox",
    16: "boot-application",
}
PE_CHARACTERISTICS = {
    0x0001: "RELOCS_STRIPPED", 0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED", 0x0008: "LOCAL_SYMS_STRIPPED",
    0x0020: "LARGE_ADDRESS_AWARE", 0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED", 0x1000: "SYSTEM",
    0x2000: "DLL", 0x4000: "UP_SYSTEM_ONLY",
}


def inspect_pe(data: bytes, warnings: list) -> dict:
    d = {}
    if len(data) < 0x40:
        warnings.append("pe: file shorter than DOS header")
        return d
    try:
        pe_off = _u32(data, 0x3C)
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            warnings.append("pe: PE signature not found at e_lfanew")
            return d
        coff = pe_off + 4
        machine = _u16(data, coff)
        nsects = _u16(data, coff + 2)
        timestamp = _u32(data, coff + 4)
        opt_size = _u16(data, coff + 16)
        chars = _u16(data, coff + 18)
        d["machine"] = machine
        d["machine_name"] = PE_MACHINES.get(machine, "unknown")
        d["timestamp"] = timestamp
        d["characteristics"] = chars
        d["characteristics_flags"] = [
            name for bit, name in sorted(PE_CHARACTERISTICS.items())
            if chars & bit]
        opt = coff + 20
        is64 = False
        imports_rva = 0
        imports_size = 0
        if opt_size >= 2 and opt + 2 <= len(data):
            magic = _u16(data, opt)
            if magic == 0x20B:
                d["optional_header"] = "PE32+"
                is64 = True
            elif magic == 0x10B:
                d["optional_header"] = "PE32"
            else:
                d["optional_header"] = hex(magic)
                warnings.append("pe: unknown optional header magic")
            # Subsystem sits at offset 68 in both PE32 and PE32+.
            if opt_size >= 70:
                subsystem = _u16(data, opt + 68)
                d["subsystem"] = subsystem
                d["subsystem_name"] = PE_SUBSYSTEMS.get(
                    subsystem, "unknown")
            dir_base = opt + (112 if is64 else 96)
            if opt_size >= (112 if is64 else 96) + 16 \
                    and dir_base + 16 <= len(data):
                imports_rva = _u32(data, dir_base + 8)
                imports_size = _u32(data, dir_base + 12)
        sections = []
        sec_off = opt + opt_size
        for i in range(min(nsects, 96)):
            off = sec_off + i * 40
            if off + 40 > len(data):
                warnings.append("pe: section table truncated")
                break
            raw_name = data[off:off + 8].split(b"\x00")[0]
            sections.append({
                "name": raw_name.decode("utf-8", "replace"),
                "virtual_size": _u32(data, off + 8),
                "virtual_address": _u32(data, off + 12),
                "raw_size": _u32(data, off + 16),
                "raw_offset": _u32(data, off + 20),
            })
        d["sections"] = sections
        d["number_of_sections"] = len(sections)

        def rva_to_off(rva: int) -> int:
            for s in sections:
                start = s["virtual_address"]
                span = max(s["virtual_size"], s["raw_size"])
                if start <= rva < start + span:
                    return s["raw_offset"] + (rva - start)
            return -1

        dlls = []
        if imports_rva:
            desc_off = rva_to_off(imports_rva)
            if desc_off < 0:
                warnings.append("pe: import directory RVA unmapped")
            else:
                for i in range(512):
                    off = desc_off + i * 20
                    if off + 20 > len(data):
                        warnings.append("pe: import table truncated")
                        break
                    fields = struct.unpack_from("<IIIII", data, off)
                    if all(v == 0 for v in fields):
                        break
                    name_off = rva_to_off(fields[3])
                    name = _cstring(data, name_off) if name_off >= 0 \
                        else ""
                    if name:
                        dlls.append(name)
        d["imports"] = dlls
    except (struct.error, IndexError) as e:
        warnings.append(f"pe: truncated ({e})")
    return d


# ---------------------------------------------------------------- #
# Mach-O

MACHO_CPUS = {
    7: "x86", 0x01000007: "x86_64", 12: "ARM",
    0x0100000C: "ARM64", 18: "PowerPC", 0x01000012: "PowerPC64",
}
MACHO_FILETYPES = {
    1: "OBJECT", 2: "EXECUTE", 3: "FVMLIB", 4: "CORE",
    5: "PRELOAD", 6: "DYLIB", 7: "DYLINKER", 8: "BUNDLE",
    9: "DYLIB_STUB", 10: "DSYM", 11: "KEXT_BUNDLE",
}
LC_NAMES = {
    0x01: "LC_SEGMENT", 0x02: "LC_SYMTAB", 0x03: "LC_SYMSEG",
    0x04: "LC_THREAD", 0x05: "LC_UNIXTHREAD", 0x06: "LC_LOADFVMLIB",
    0x07: "LC_IDFVMLIB", 0x08: "LC_IDENT", 0x09: "LC_FVMFILE",
    0x0B: "LC_DYSYMTAB", 0x0C: "LC_LOAD_DYLIB", 0x0D: "LC_ID_DYLIB",
    0x0E: "LC_LOAD_DYLINKER", 0x0F: "LC_ID_DYLINKER", 0x10: "LC_PREPAGE",
    0x11: "LC_ROUTINES", 0x12: "LC_SUB_FRAMEWORK", 0x13: "LC_SUB_UMBRELLA",
    0x14: "LC_SUB_CLIENT", 0x15: "LC_SUB_LIBRARY", 0x16: "LC_TWOLEVEL_HINTS",
    0x17: "LC_PREBIND_CKSUM", 0x18: "LC_LOAD_WEAK_DYLIB",
    0x19: "LC_SEGMENT_64", 0x1A: "LC_ROUTINES_64", 0x1B: "LC_UUID",
    0x1C: "LC_RPATH", 0x1D: "LC_CODE_SIGNATURE", 0x1E: "LC_SEGMENT_SPLIT_INFO",
    0x1F: "LC_REEXPORT_DYLIB", 0x20: "LC_LAZY_LOAD_DYLIB",
    0x21: "LC_ENCRYPTION_INFO", 0x22: "LC_DYLD_INFO",
    0x23: "LC_DYLD_INFO_ONLY", 0x24: "LC_LOAD_UPWARD_DYLIB",
    0x25: "LC_VERSION_MIN_MACOSX", 0x26: "LC_VERSION_MIN_IPHONEOS",
    0x27: "LC_FUNCTION_STARTS", 0x28: "LC_DYLD_ENVIRONMENT",
    0x29: "LC_MAIN", 0x2A: "LC_DATA_IN_CODE", 0x2B: "LC_SOURCE_VERSION",
    0x2C: "LC_DYLIB_CODE_SIGN_DRS", 0x2D: "LC_ENCRYPTION_INFO_64",
    0x2E: "LC_LINKER_OPTION", 0x2F: "LC_LINKER_OPTIMIZATION_HINT",
    0x30: "LC_VERSION_MIN_TVOS", 0x31: "LC_VERSION_MIN_WATCHOS",
    0x32: "LC_NOTE", 0x33: "LC_BUILD_VERSION",
}


def inspect_macho(data: bytes, warnings: list) -> dict:
    d = {}
    magic = data[:4]
    # Fat binaries: magic is stored big-endian on disk.
    if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        fat64 = magic == b"\xca\xfe\xba\xbf"
        d["fat"] = True
        d["bits"] = 64 if fat64 else 32
        d["endianness"] = "big"
        archs = []
        try:
            count = struct.unpack_from(">I", data, 4)[0]
            d["architectures"] = count
            rec = 32 if fat64 else 20
            for i in range(min(count, 32)):
                off = 8 + i * rec
                if off + rec > len(data):
                    warnings.append("macho: fat arch table truncated")
                    break
                cpu = struct.unpack_from(">i", data, off)[0] & 0xFFFFFFFF
                archs.append({"cpu_type": cpu,
                              "cpu_name": MACHO_CPUS.get(cpu, "unknown")})
        except (struct.error, IndexError) as e:
            warnings.append(f"macho: fat header truncated ({e})")
        d["arch_list"] = archs
        return d
    thin = {
        b"\xfe\xed\xfa\xce": (32, ">"), b"\xce\xfa\xed\xfe": (32, "<"),
        b"\xfe\xed\xfa\xcf": (64, ">"), b"\xcf\xfa\xed\xfe": (64, "<"),
    }
    bits, en = thin[magic]
    d["fat"] = False
    d["bits"] = bits
    d["endianness"] = "big" if en == ">" else "little"
    try:
        cpu = struct.unpack_from(en + "i", data, 4)[0] & 0xFFFFFFFF
        d["cpu_type"] = cpu
        d["cpu_name"] = MACHO_CPUS.get(cpu, "unknown")
        ftype = _u32(data, 12, en)
        d["file_type"] = ftype
        d["file_type_name"] = MACHO_FILETYPES.get(ftype, "unknown")
        ncmds = _u32(data, 16, en)
        types = []
        off = 32 if bits == 64 else 28
        for _ in range(min(ncmds, 4096)):
            if off + 8 > len(data):
                warnings.append("macho: load commands truncated")
                break
            cmd = _u32(data, off, en) & 0x7FFFFFFF
            cmdsize = _u32(data, off + 4, en)
            types.append(LC_NAMES.get(cmd, hex(cmd)))
            if cmdsize < 8:
                warnings.append("macho: bad load command size")
                break
            off += cmdsize
        d["load_commands"] = len(types)
        d["load_command_types"] = types
    except (struct.error, IndexError) as e:
        warnings.append(f"macho: truncated header ({e})")
    return d


# ---------------------------------------------------------------- #
# WASM

WASM_SECTIONS = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "datacount",
}


def _uleb(data: bytes, off: int):
    result = 0
    shift = 0
    i = off
    while i < len(data) and shift < 35:
        b = data[i]
        result |= (b & 0x7F) << shift
        i += 1
        if not (b & 0x80):
            return result, i
        shift += 7
    raise ValueError("uleb128 overrun")


def inspect_wasm(data: bytes, warnings: list) -> dict:
    d = {}
    try:
        d["version"] = _u32(data, 4, "<")
        sections = []
        off = 8
        while off < len(data):
            sid = data[off]
            size, body_off = _uleb(data, off + 1)
            if body_off + size > len(data):
                warnings.append("wasm: section body truncated")
                sections.append({"id": sid,
                                 "name": WASM_SECTIONS.get(sid,
                                                           "unknown"),
                                 "size": size})
                break
            sections.append({"id": sid,
                             "name": WASM_SECTIONS.get(sid, "unknown"),
                             "size": size})
            off = body_off + size
        d["sections"] = sections
    except (struct.error, IndexError, ValueError) as e:
        warnings.append(f"wasm: truncated ({e})")
        d.setdefault("sections", [])
    return d


# ---------------------------------------------------------------- #
# ZIP / APK

SIG_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC")
DEX_RE = re.compile(r"^classes\d*\.dex$")


def inspect_zip(path: Path, data: bytes, warnings: list,
                is_apk: bool) -> dict:
    d = {}
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            names = [i.filename for i in infos]
    except zipfile.BadZipFile as e:
        warnings.append(f"zip: bad zip file ({e})")
        names = []
    d["entries"] = len(names)
    d["names"] = names[:MAX_ENTRIES]
    if len(names) > MAX_ENTRIES:
        d["names_truncated"] = True
    if is_apk:
        d["android_manifest"] = "AndroidManifest.xml" in names
        d["dex_files"] = [n for n in names if DEX_RE.match(n)]
        d["signature_files"] = [
            n for n in names
            if n.startswith("META-INF/")
            and n.upper().endswith(SIG_SUFFIXES)]
    return d


# ---------------------------------------------------------------- #
# Python .pyc

# Exact CPython magic numbers (little-endian uint16) for final
# releases, plus the running interpreter's own magic merged in at
# runtime.
PYC_MAGICS = {
    3413: "3.8", 3425: "3.9", 3439: "3.10", 3495: "3.11",
    3531: "3.12", 3571: "3.13",
}
PYC_RANGES = [
    (3600, 3700, "3.14"),
]


def _pyc_version(magic_int: int):
    try:
        import importlib.util
        own = struct.unpack("<H", importlib.util.MAGIC_NUMBER[:2])[0]
        if magic_int == own:
            return "%d.%d" % sys.version_info[:2]
    except Exception:
        pass
    if magic_int in PYC_MAGICS:
        return PYC_MAGICS[magic_int]
    for lo, hi, ver in PYC_RANGES:
        if lo <= magic_int <= hi:
            return ver + " (guess)"
    return None


def _code_names(code, out: list, depth: int = 0):
    if depth > 12 or len(out) > 500:
        return
    import types
    if isinstance(code, types.CodeType):
        name = getattr(code, "co_name", None)
        if name:
            out.append(name)
        for const in code.co_consts:
            _code_names(const, out, depth + 1)


def inspect_pyc(data: bytes, warnings: list) -> dict:
    d = {}
    magic_int = struct.unpack("<H", data[:2])[0] if len(data) >= 2 \
        else 0
    d["magic_hex"] = data[:4].hex()
    d["magic_int"] = magic_int
    guess = _pyc_version(magic_int)
    d["python_version"] = guess
    if guess is None:
        warnings.append("pyc: magic number not in known table")
    if len(data) >= 8:
        d["flags"] = _u32(data, 4, "<")
    else:
        warnings.append("pyc: header truncated")
    d["names"] = []
    # Code objects live after the 16-byte (3.7+) header. Marshal is
    # version-specific: try, and honestly warn when it cannot read.
    try:
        import marshal
        code = marshal.loads(data[16:])
        names: list = []
        _code_names(code, names)
        d["names"] = names
    except Exception:
        warnings.append(
            "pyc: marshal could not read code object "
            "(different CPython version?)")
    return d


# ---------------------------------------------------------------- #
# SQLite

def inspect_sqlite(path: Path, data: bytes, warnings: list) -> dict:
    d = {}
    if len(data) >= 100:
        page_size = struct.unpack_from(">H", data, 16)[0]
        d["page_size"] = 65536 if page_size == 1 else page_size
        d["write_version"] = data[18]
        d["read_version"] = data[19]
        d["page_count"] = struct.unpack_from(">I", data, 28)[0]
        encoding = struct.unpack_from(">I", data, 56)[0]
        d["text_encoding"] = {1: "utf-8", 2: "utf-16le",
                              3: "utf-16be"}.get(encoding, "unknown")
    else:
        warnings.append("sqlite: header shorter than 100 bytes")
    tables = []
    try:
        uri = "file:" + quote(str(path)) + "?mode=ro"
        con = sqlite3.connect(uri, uri=True)
        try:
            rows = con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "ORDER BY name").fetchall()
            tables = [r[0] for r in rows]
        finally:
            con.close()
    except sqlite3.Error as e:
        warnings.append(f"sqlite: table listing failed ({e})")
    d["tables"] = tables
    return d


# ---------------------------------------------------------------- #
# Plist

def inspect_plist(data: bytes, warnings: list) -> dict:
    d = {}
    try:
        obj = plistlib.loads(data)
    except Exception as e:
        warnings.append(f"plist: parse failed ({e})")
        return d
    d["root_type"] = type(obj).__name__
    if isinstance(obj, dict):
        keys = [str(k) for k in obj.keys()]
        d["key_count"] = len(keys)
        d["keys"] = keys[:50]
    elif isinstance(obj, (list, tuple)):
        d["length"] = len(obj)
    return d


# ---------------------------------------------------------------- #
# JavaScript application

IMPORT_FROM_RE = re.compile(
    r"""import\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]""")
REQUIRE_RE = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
DYN_IMPORT_RE = re.compile(r"""import\(\s*['"]([^'"]+)['"]\s*\)""")
EXPORT_DECL_RE = re.compile(
    r"""export\s+(?:default\s+)?(?:async\s+)?"""
    r"""(?:function\*?|class|const|let|var|interface|type|enum)"""
    r"""\s+([A-Za-z_$][\w$]*)""")
EXPORT_LIST_RE = re.compile(r"""export\s*\{([^}]*)\}""")
EXPORT_DEFAULT_RE = re.compile(r"""export\s+default\b""")
MODULE_EXPORTS_OBJ_RE = re.compile(
    r"""module\.exports\s*=\s*\{([^}]*)\}""", re.S)
EXPORTS_ASSIGN_RE = re.compile(
    r"""(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=""")


def parse_js(text: str):
    imports = []
    for rx in (IMPORT_FROM_RE, REQUIRE_RE, DYN_IMPORT_RE):
        imports.extend(rx.findall(text))
    seen = set()
    imports = [i for i in imports if not (i in seen or seen.add(i))]
    exports = []
    if EXPORT_DEFAULT_RE.search(text):
        exports.append("default")
    exports.extend(EXPORT_DECL_RE.findall(text))
    for group in EXPORT_LIST_RE.findall(text):
        for part in group.split(","):
            part = part.strip()
            if not part:
                continue
            name = part.split(" as ")[-1].strip()
            if name and name != "default":
                exports.append(name)
    m = MODULE_EXPORTS_OBJ_RE.search(text)
    if m:
        for part in m.group(1).split(","):
            key = part.split(":")[0].strip().strip("'\"")
            if re.match(r"^[A-Za-z_$][\w$]*$", key or ""):
                exports.append(key)
    elif re.search(r"""module\.exports\s*=""", text):
        exports.append("module.exports")
    exports.extend(EXPORTS_ASSIGN_RE.findall(text))
    seen = set()
    exports = [e for e in exports if not (e in seen or seen.add(e))]
    return imports, exports


def inspect_js_app(root: Path, warnings: list) -> dict:
    d = {}
    files = []
    totals = {"imports": 0, "exports": 0}
    if root.is_file():
        candidates = [root]
        base = root.parent
    else:
        candidates = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(
                dn for dn in dirnames if dn not in SKIP_DIRS)
            for fn in sorted(filenames):
                p = Path(dirpath) / fn
                if p.suffix.lower() in JS_SUFFIXES:
                    candidates.append(p)
        candidates.sort()
        base = root
    truncated = len(candidates) > MAX_FILES
    for p in candidates[:MAX_FILES]:
        entry = {"path": "", "imports": [], "exports": []}
        try:
            entry["path"] = p.relative_to(base).as_posix() \
                if base != p else p.name
        except ValueError:
            entry["path"] = p.name
        if p.suffix.lower() in (".js", ".mjs", ".cjs"):
            try:
                text = p.read_bytes()[:2_000_000].decode(
                    "utf-8", "replace")
                imps, exps = parse_js(text)
                entry["imports"] = imps
                entry["exports"] = exps
            except OSError as e:
                warnings.append(f"js: could not read {p.name} ({e})")
        files.append(entry)
        totals["imports"] += len(entry["imports"])
        totals["exports"] += len(entry["exports"])
    d["file_count"] = len(candidates)
    d["files"] = files
    d["totals"] = totals
    if truncated:
        d["files_truncated"] = True
        warnings.append(
            f"js: file list truncated at {MAX_FILES} of "
            f"{len(candidates)}")
    return d


# ---------------------------------------------------------------- #
# Text fallback

def inspect_text(data: bytes, warnings: list) -> dict:
    text = data.decode("utf-8", "replace")
    lines = text.splitlines()
    return {
        "lines": len(lines),
        "first_line": lines[0][:200] if lines else "",
    }


def _looks_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:8192]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 32 <= b <= 126
                    or b in (9, 10, 13))
    return printable / len(sample) >= 0.9


# ---------------------------------------------------------------- #
# dispatch

def _is_pyc(data: bytes) -> bool:
    if len(data) < 4 or data[2:4] != b"\r\n":
        return False
    magic_int = struct.unpack("<H", data[:2])[0]
    return _pyc_version(magic_int) is not None or 3350 <= magic_int <= 3700


def _is_plist(data: bytes) -> bool:
    if data.startswith(b"bplist00"):
        return True
    head = data[:1024]
    return b"<plist" in head and head.lstrip().startswith(b"<?xml")


def inspect_path(path_str) -> dict:
    """Inspect one file or directory. Raises InspectError when the
    path is missing or unreadable."""
    path = Path(path_str)
    if not path.exists():
        raise InspectError(f"no such file or directory: {path_str}")
    warnings: list = []
    result = {
        "path": str(path),
        "warnings": warnings,
    }
    if path.is_dir():
        detail = inspect_js_app(path, warnings)
        result.update({
            "size": sum(f.stat().st_size for f in path.rglob("*")
                        if f.is_file()),
            "sha256": None,
            "format": "javascript-app",
            "detail": detail,
            "entropy": {"overall": 0.0, "blocks": []},
            "strings": [],
        })
        return result
    try:
        data = path.read_bytes()
    except OSError as e:
        raise InspectError(f"unreadable file: {path_str} ({e})")

    result["size"] = len(data)
    result["sha256"] = hashlib.sha256(data).hexdigest()
    result["entropy"] = entropy_block(data)
    result["strings"] = extract_strings(data)

    fmt = "unknown"
    detail: dict = {}
    suffix = path.suffix.lower()
    if data[:4] == b"\x7fELF":
        fmt, detail = "elf", inspect_elf(data, warnings)
    elif data[:2] == b"MZ":
        fmt, detail = "pe", inspect_pe(data, warnings)
    elif data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                      b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                      b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        fmt, detail = "macho", inspect_macho(data, warnings)
    elif data[:4] == b"\x00asm":
        fmt, detail = "wasm", inspect_wasm(data, warnings)
    elif zipfile.is_zipfile(path):
        is_apk = suffix == ".apk"
        probe = inspect_zip(path, data, warnings, is_apk)
        if not is_apk and probe.get("android_manifest"):
            is_apk = True
            probe = inspect_zip(path, data, warnings, True)
        fmt = "apk" if is_apk else "zip"
        detail = probe
    elif data[:16] == b"SQLite format 3\x00":
        fmt, detail = "sqlite", inspect_sqlite(path, data, warnings)
    elif _is_pyc(data) or suffix == ".pyc":
        fmt, detail = "pyc", inspect_pyc(data, warnings)
    elif _is_plist(data) or suffix == ".plist":
        fmt, detail = "plist", inspect_plist(data, warnings)
    elif suffix in (".js", ".mjs", ".cjs"):
        fmt = "javascript-app"
        detail = inspect_js_app(path, warnings)
    elif _looks_text(data):
        fmt, detail = "text", inspect_text(data, warnings)

    result["format"] = fmt
    result["detail"] = detail
    return result
