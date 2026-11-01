# GhostRE

Ghost-native reverse-engineering inspector for Ghost Developer
Studio. GhostRE is Wave 2 of bringing REA's (Reverse Engineer
Anything) **provider-free** capabilities into GhostIDE: the part of
reverse engineering that needs no external analysis engine — no
Ghidra, Hopper, IDA, JADX, Rizin or Node — reimplemented in pure
Python stdlib so it runs anywhere GhostIDE runs, including
on-device in the phone APK.

MIT licensed. Dependencies: none. No subprocesses, no network.

## Usage

```
python -m ghostre inspect <path>
```

Prints ONE JSON object to stdout and exits 0. A missing or
unreadable path exits 2 with `{"error": "..."}` on stdout.

```json
{"path": "...", "size": 1234, "sha256": "...", "format": "elf",
 "detail": {...}, "entropy": {"overall": 4.21, "blocks": [...]},
 "strings": ["..."], "warnings": []}
```

`format` is one of: `elf`, `pe`, `macho`, `wasm`, `apk`, `zip`,
`pyc`, `sqlite`, `plist`, `javascript-app`, `text`, `unknown`.

Every result also carries Shannon entropy (whole file plus
4096-byte blocks) and the first 40 printable ASCII strings of
length >= 6. Inspectors are bounds-checked and total: malformed
input returns whatever parsed plus a `warnings` list, never a
crash.

## What each inspector extracts

- **ELF** — 32/64-bit, endianness, machine, type, entry point,
  program-header count, section names (via the section-header
  string table).
- **PE** — machine, characteristics (+ decoded flags), PE32/PE32+
  optional-header kind, subsystem, sections (name, virtual size /
  address, raw size / offset), imported DLL names (import
  directory walk with RVA mapping).
- **Mach-O** — thin 32/64 in either endianness (cpu type, file
  type, load-command count and type names); fat binaries report
  `fat: true` plus the architecture list.
- **WASM** — module version, section ids/names/sizes in order.
- **APK / ZIP** — entry count and first 100 names; APKs also get
  `android_manifest`, the `classes*.dex` list, and the META-INF
  signature files (.SF/.RSA/.DSA/.EC).
- **Python .pyc** — magic number (hex + int), CPython version
  guess from the magic table (3.8-3.14 plus the running
  interpreter's own magic), header flags, and code-object names
  collected via marshal where the running interpreter can read
  them (guarded; a version mismatch lands in `warnings`).
- **SQLite** — page size, read/write format versions, page count,
  text encoding, and table names from `sqlite_master`, opened
  read-only (URI `mode=ro`).
- **Plist** — root type (dict/list/...), top-level keys (first 50)
  for dicts, length for lists. Binary and XML plists.
- **JavaScript application** — a directory (or single
  .js/.mjs/.cjs file): counts of .js/.mjs/.cjs/.json files, and
  per file (first 100 files) the import / require / dynamic-import
  specifiers and the export names (declarations, export lists,
  `module.exports`, `exports.x`), plus totals. `node_modules` and
  `.git` are skipped.
- **Text** — line count and first-line preview. Anything else that
  is not mostly printable is `unknown`.

## Parity with REA (checked Nov 1, 2026, rea-agents 6.8.0)

GhostRE does **not** emit REA's Evidence JSON and does not claim
byte-identical output. Parity is claimed only at the level of
*facts*, and only where it was measured:

- **Entropy** — on a 12,288-byte SQLite fixture (built by the test
  suite), REA `inspect-byte-entropy` (block size 4096) reported
  file entropy 0.2087 and block entropies 0.5015 / 0.0478 /
  0.0066 at offsets 0 / 4096 / 8192. GhostRE reported 0.20867 and
  0.501488 / 0.047754 / 0.006564 — identical to REA's precision
  (REA rounds to 4 decimals, GhostRE keeps 6). SHA-256 and byte
  size were identical.
- **SQLite** — REA `inspect-sqlite-database` on the same fixture
  listed tables `users` and `events` with UTF-8 encoding; GhostRE
  lists the same two tables and `utf-8`. REA goes deeper (root
  pages, per-table column counts, optional row sampling); GhostRE
  reports header facts + table names only.
- **Format identification** — REA `inspect-artifact` identifies
  /bin/true with subject format `elf`; GhostRE also returns
  `elf` (x86-64, DYN, 30 sections). One honest difference: REA
  *refuses* a SQLite database in `inspect-artifact`
  ("unsupported binary format" — it has a separate SQLite
  command); GhostRE identifies `sqlite` directly.
- **JavaScript apps** — on the REA smoke app
  (~/workspace/rea-internal/smoke-app), REA
  `analyze-javascript-application` inventoried exactly 3 files
  (package.json, src/index.js, src/util.js) and built a graph of
  9 nodes / 11 edges. GhostRE reports the same 3 files, the same
  `./util` import in src/index.js, and the same `panForPosition`
  export in src/util.js. REA's analysis is far deeper (full AST
  semantic graph: 29 nodes, routes inventory, binding
  resolution); GhostRE is a regex-level structural pass and does
  not pretend otherwise.

## Layout

```
pyproject.toml          name ghostre, version 0.1.0, stdlib only
src/ghostre/__init__.py __version__ = "0.1.0"
src/ghostre/__main__.py python -m ghostre
src/ghostre/cli.py      argparse CLI (inspect subcommand)
src/ghostre/inspect.py  all inspectors + dispatch
tests/                  pytest suite, fixtures synthesized in-test
```

## Tests

```
python3 -m pytest tests/ -q
```

26 tests: one or more per inspector, all fixtures built
synthetically in the tests (struct-packed ELF/PE/Mach-O/WASM
headers, a zipfile APK, a py_compile .pyc, a real sqlite db, a
plistlib plist, a small JS app), plus truncated/garbage/empty
inputs and the CLI exit-code contract.
