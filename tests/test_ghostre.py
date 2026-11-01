"""GhostRE suite: every inspector gets a synthetic fixture built
in the test itself (no downloads, no checked-in binaries), plus
malformed-input tests proving total, crash-free behaviour."""
from __future__ import annotations

import json
import plistlib
import py_compile
import sqlite3
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from ghostre.cli import main
from ghostre.inspect import inspect_path

SRC = Path(__file__).resolve().parents[1] / "src"


# ---------------------------------------------------------------- #
# fixture builders

def build_elf64() -> bytes:
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text = b"\x90" * 16
    ehsize = 64
    phoff = ehsize
    phnum = 1
    text_off = phoff + 56 * phnum
    shstr_off = text_off + len(text)
    shoff = shstr_off + len(shstrtab)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    hdr = struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, phoff, shoff, 0,
        ehsize, 56, phnum, 64, 3, 2)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000,
                       shoff, shoff, 4096)
    null_sh = b"\x00" * 64
    text_sh = struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0x401000, text_off,
                          len(text), 0, 0, 16, 0)
    str_sh = struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, shstr_off,
                         len(shstrtab), 0, 0, 1, 0)
    return ident + hdr + phdr + text + shstrtab + null_sh + text_sh \
        + str_sh


def build_elf32() -> bytes:
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    hdr = struct.pack("<HHIIIIIHHHHHH", 3, 40, 1, 0x8000, 52, 0, 0,
                      52, 32, 1, 40, 0, 0)
    return ident + hdr + b"\x00" * 32


def build_pe() -> bytes:
    pe_off = 0x80
    raw_off = 512
    dos = bytearray(pe_off)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_off)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)          # PE32
    struct.pack_into("<H", opt, 68, 3)             # subsystem console
    struct.pack_into("<I", opt, 92, 16)            # number of dirs
    struct.pack_into("<I", opt, 96 + 8, 0x1000)    # import dir RVA
    struct.pack_into("<I", opt, 96 + 12, 40)       # import dir size
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 224, 0x0022)
    sect = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x1000,
                       0x1000, 0x200, raw_off, 0, 0, 0, 0, 0x60000020)
    head = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sect
    head = head.ljust(raw_off, b"\x00")
    body = bytearray(0x200)
    # import descriptor at RVA 0x1000 -> raw 512; name RVA 0x1028
    struct.pack_into("<IIIII", body, 0, 0, 0, 0, 0x1028, 0)
    body[40:40 + 13] = b"KERNEL32.dll\x00"
    return head + bytes(body)


def build_macho64() -> bytes:
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 2,
                      72, 0, 0)
    lc1 = struct.pack("<II", 0x19, 72) + b"\x00" * 64   # LC_SEGMENT_64
    lc2 = struct.pack("<II", 0x02, 24) + b"\x00" * 16   # LC_SYMTAB
    return hdr + lc1 + lc2


def build_fat_macho() -> bytes:
    hdr = struct.pack(">II", 0xCAFEBABE, 2)
    arch = struct.pack(">IIIII", 0x01000007, 3, 0x1000, 0x100, 0)
    arch2 = struct.pack(">IIIII", 0x0100000C, 3, 0x2000, 0x100, 0)
    return hdr + arch + arch2


def build_wasm() -> bytes:
    type_sec = bytes([1, 4, 1, 0x60, 0, 0])
    export_sec = bytes([7, 5, 1, 1]) + b"f\x00\x00"
    return b"\x00asm" + struct.pack("<I", 1) + type_sec + export_sec


@pytest.fixture()
def elf_file(tmp_path):
    p = tmp_path / "prog"
    p.write_bytes(build_elf64())
    return p


@pytest.fixture()
def pe_file(tmp_path):
    p = tmp_path / "prog.exe"
    p.write_bytes(build_pe())
    return p


@pytest.fixture()
def apk_file(tmp_path):
    p = tmp_path / "app.apk"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        z.writestr("classes.dex", b"dex\n035\x00")
        z.writestr("classes2.dex", b"dex\n035\x00")
        z.writestr("META-INF/CERT.RSA", b"\x30\x82")
        z.writestr("META-INF/CERT.SF", b"Manifest-Version: 1.0\r\n")
        z.writestr("res/drawable/icon.png", b"\x89PNG")
    return p


@pytest.fixture()
def sqlite_file(tmp_path):
    p = tmp_path / "data.db"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, "
                "name TEXT)")
    con.execute("CREATE TABLE events (id INTEGER, kind TEXT)")
    con.execute("INSERT INTO users VALUES (1, 'ghost')")
    con.commit()
    con.close()
    return p


@pytest.fixture()
def js_app(tmp_path):
    root = tmp_path / "app"
    (root / "src").mkdir(parents=True)
    (root / "package.json").write_text(
        '{"name": "app", "version": "1.0.0"}')
    (root / "src" / "index.js").write_text(
        "import foo from './foo.js';\n"
        "const { pan } = require('./util');\n"
        "export function main() { return foo + pan; }\n")
    (root / "src" / "util.js").write_text(
        "function panForPosition(x, w) { return (x / w) * 2 - 1; }\n"
        "module.exports = { panForPosition };\n")
    (root / "src" / "esm.mjs").write_text(
        "export const answer = 42;\n"
        "export default answer;\n")
    return root


# ---------------------------------------------------------------- #
# ELF

def test_elf64(elf_file):
    r = inspect_path(elf_file)
    assert r["format"] == "elf"
    d = r["detail"]
    assert d["bits"] == 64
    assert d["endianness"] == "little"
    assert d["machine"] == 62 and d["machine_name"] == "x86-64"
    assert d["type_name"] == "EXEC"
    assert d["entry_point"] == 0x401000
    assert d["program_headers"] == 1
    assert ".text" in d["sections"]
    assert ".shstrtab" in d["sections"]
    assert r["size"] == elf_file.stat().st_size
    assert len(r["sha256"]) == 64


def test_elf32(tmp_path):
    p = tmp_path / "prog32"
    p.write_bytes(build_elf32())
    r = inspect_path(p)
    assert r["format"] == "elf"
    assert r["detail"]["bits"] == 32
    assert r["detail"]["machine_name"] == "ARM"


# ---------------------------------------------------------------- #
# PE

def test_pe(pe_file):
    r = inspect_path(pe_file)
    assert r["format"] == "pe"
    d = r["detail"]
    assert d["machine_name"] == "x86-64"
    assert d["optional_header"] == "PE32"
    assert d["subsystem_name"] == "windows-console"
    assert d["number_of_sections"] == 1
    assert d["sections"][0]["name"] == ".text"
    assert d["sections"][0]["virtual_size"] == 0x1000
    assert "EXECUTABLE_IMAGE" in d["characteristics_flags"]
    assert d["imports"] == ["KERNEL32.dll"]
    assert "KERNEL32.dll" in r["strings"]


# ---------------------------------------------------------------- #
# Mach-O

def test_macho64(tmp_path):
    p = tmp_path / "prog"
    p.write_bytes(build_macho64())
    r = inspect_path(p)
    assert r["format"] == "macho"
    d = r["detail"]
    assert d["fat"] is False and d["bits"] == 64
    assert d["cpu_name"] == "x86_64"
    assert d["file_type_name"] == "EXECUTE"
    assert d["load_commands"] == 2
    assert d["load_command_types"] == ["LC_SEGMENT_64", "LC_SYMTAB"]


def test_macho_fat(tmp_path):
    p = tmp_path / "fatprog"
    p.write_bytes(build_fat_macho())
    r = inspect_path(p)
    assert r["format"] == "macho"
    d = r["detail"]
    assert d["fat"] is True
    assert d["architectures"] == 2
    assert {a["cpu_name"] for a in d["arch_list"]} == {"x86_64", "ARM64"}


# ---------------------------------------------------------------- #
# WASM

def test_wasm(tmp_path):
    p = tmp_path / "mod.wasm"
    p.write_bytes(build_wasm())
    r = inspect_path(p)
    assert r["format"] == "wasm"
    assert r["detail"]["version"] == 1
    secs = r["detail"]["sections"]
    assert [(s["id"], s["name"]) for s in secs] == [
        (1, "type"), (7, "export")]
    assert secs[0]["size"] == 4


# ---------------------------------------------------------------- #
# APK / ZIP

def test_apk(apk_file):
    r = inspect_path(apk_file)
    assert r["format"] == "apk"
    d = r["detail"]
    assert d["entries"] == 6
    assert d["android_manifest"] is True
    assert d["dex_files"] == ["classes.dex", "classes2.dex"]
    assert "META-INF/CERT.RSA" in d["signature_files"]
    assert "META-INF/CERT.SF" in d["signature_files"]


def test_plain_zip(tmp_path):
    p = tmp_path / "bundle.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("a.txt", "hello")
        z.writestr("b/c.txt", "world")
    r = inspect_path(p)
    assert r["format"] == "zip"
    assert r["detail"]["entries"] == 2
    assert r["detail"]["names"] == ["a.txt", "b/c.txt"]


# ---------------------------------------------------------------- #
# .pyc

def test_pyc(tmp_path):
    src = tmp_path / "mod.py"
    src.write_text("def greet(name):\n    return 'hello ' + name\n\n"
                   "VALUE = 7\n")
    pyc = tmp_path / "mod.pyc"
    py_compile.compile(str(src), cfile=str(pyc), doraise=True)
    r = inspect_path(pyc)
    assert r["format"] == "pyc"
    d = r["detail"]
    assert d["magic_hex"] == pyc.read_bytes()[:4].hex()
    assert d["python_version"] == "%d.%d" % sys.version_info[:2]
    assert "flags" in d
    assert "greet" in d["names"]
    assert "<module>" in d["names"]


# ---------------------------------------------------------------- #
# SQLite

def test_sqlite(sqlite_file):
    r = inspect_path(sqlite_file)
    assert r["format"] == "sqlite"
    d = r["detail"]
    assert d["page_size"] in (512, 1024, 2048, 4096, 8192, 16384,
                               32768, 65536)
    assert d["write_version"] in (1, 2)
    assert d["read_version"] in (1, 2)
    assert d["tables"] == ["events", "users"]


# ---------------------------------------------------------------- #
# Plist

def test_plist(tmp_path):
    p = tmp_path / "info.plist"
    p.write_bytes(plistlib.dumps(
        {"CFBundleName": "Ghost", "CFBundleVersion": "1",
         "NSKeys": [1, 2]}, fmt=plistlib.FMT_BINARY))
    r = inspect_path(p)
    assert r["format"] == "plist"
    d = r["detail"]
    assert d["root_type"] == "dict"
    assert d["key_count"] == 3
    assert "CFBundleName" in d["keys"]


def test_plist_xml_list(tmp_path):
    p = tmp_path / "list.plist"
    p.write_bytes(plistlib.dumps(["a", "b", "c"]))
    r = inspect_path(p)
    assert r["format"] == "plist"
    assert r["detail"]["root_type"] == "list"
    assert r["detail"]["length"] == 3


# ---------------------------------------------------------------- #
# JavaScript application

def test_js_app_dir(js_app):
    r = inspect_path(js_app)
    assert r["format"] == "javascript-app"
    d = r["detail"]
    assert d["file_count"] == 4
    by_path = {f["path"]: f for f in d["files"]}
    assert "./foo.js" in by_path["src/index.js"]["imports"]
    assert "./util" in by_path["src/index.js"]["imports"]
    assert "main" in by_path["src/index.js"]["exports"]
    assert "panForPosition" in by_path["src/util.js"]["exports"]
    assert "answer" in by_path["src/esm.mjs"]["exports"]
    assert "default" in by_path["src/esm.mjs"]["exports"]
    assert d["totals"]["imports"] >= 2
    assert d["totals"]["exports"] >= 4


def test_js_single_file(js_app):
    r = inspect_path(js_app / "src" / "index.js")
    assert r["format"] == "javascript-app"
    assert r["detail"]["file_count"] == 1
    assert "main" in r["detail"]["files"][0]["exports"]


# ---------------------------------------------------------------- #
# Text, entropy, strings, unknown

def test_text(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("first line here\nsecond line\nthird\n")
    r = inspect_path(p)
    assert r["format"] == "text"
    assert r["detail"]["lines"] == 3
    assert r["detail"]["first_line"] == "first line here"


def test_entropy_and_strings(tmp_path):
    import random
    rng = random.Random(42)
    p = tmp_path / "rand.bin"
    p.write_bytes(bytes(rng.randrange(256) for _ in range(4096)))
    r = inspect_path(p)
    assert r["entropy"]["overall"] > 7.5
    assert r["entropy"]["blocks"][0]["offset"] == 0
    q = tmp_path / "zero.bin"
    q.write_bytes(b"\x00" * 512)
    rz = inspect_path(q)
    assert rz["entropy"]["overall"] == 0.0
    s = tmp_path / "strs.bin"
    s.write_bytes(b"\x01\x02hello world string\x00\xffanother "
                  b"printable run\x00")
    rs = inspect_path(s)
    assert "hello world string" in rs["strings"]
    assert "another printable run" in rs["strings"]


def test_garbage_is_unknown_not_crash(tmp_path):
    p = tmp_path / "junk.bin"
    p.write_bytes(bytes([0xFF, 0x00, 0x13, 0x37, 0x99, 0x42, 0x00,
                         0xFE] * 8))
    r = inspect_path(p)
    assert r["format"] == "unknown"
    assert r["detail"] == {}
    assert "entropy" in r and "strings" in r


# ---------------------------------------------------------------- #
# Malformed inputs never crash

def test_truncated_elf(tmp_path):
    p = tmp_path / "trunc"
    p.write_bytes(build_elf64()[:20])
    r = inspect_path(p)
    assert r["format"] == "elf"
    assert r["warnings"]  # said what went wrong


def test_elf_ident_only(tmp_path):
    p = tmp_path / "tiny"
    p.write_bytes(b"\x7fELF\x02\x01")
    r = inspect_path(p)
    assert r["format"] == "elf"
    assert r["warnings"]


def test_truncated_pe(tmp_path):
    p = tmp_path / "trunc.exe"
    p.write_bytes(build_pe()[:100])
    r = inspect_path(p)
    assert r["format"] == "pe"
    assert r["warnings"]


def test_truncated_wasm(tmp_path):
    p = tmp_path / "trunc.wasm"
    p.write_bytes(build_wasm()[:11])
    r = inspect_path(p)
    assert r["format"] == "wasm"
    assert r["warnings"]


def test_fake_sqlite_header(tmp_path):
    p = tmp_path / "fake.db"
    p.write_bytes(b"SQLite format 3\x00" + b"\x00" * 20)
    r = inspect_path(p)
    assert r["format"] == "sqlite"
    assert r["warnings"]


def test_empty_file(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    r = inspect_path(p)
    assert r["format"] == "unknown"
    assert r["size"] == 0
    assert r["entropy"]["overall"] == 0.0


# ---------------------------------------------------------------- #
# CLI contract

def test_cli_missing_file(tmp_path, capsys):
    rc = main(["inspect", str(tmp_path / "does-not-exist")])
    out = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert "error" in out


def test_cli_json_one_object(tmp_path, capsys):
    p = tmp_path / "notes.txt"
    p.write_text("alpha\nbeta\n")
    rc = main(["inspect", str(p)])
    out = capsys.readouterr().out
    assert rc == 0
    parsed = json.loads(out)
    assert parsed["format"] == "text"
    assert out.count("\n") == 1  # exactly one JSON object line


def test_cli_subprocess(tmp_path):
    p = tmp_path / "mod.wasm"
    p.write_bytes(build_wasm())
    import os
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    proc = subprocess.run(
        [sys.executable, "-m", "ghostre", "inspect", str(p)],
        capture_output=True, text=True, env=env, timeout=30)
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["format"] == "wasm"
    proc2 = subprocess.run(
        [sys.executable, "-m", "ghostre", "inspect",
         str(tmp_path / "nope")],
        capture_output=True, text=True, env=env, timeout=30)
    assert proc2.returncode == 2
    assert "error" in json.loads(proc2.stdout)
