"""GhostRE: Ghost-native reverse-engineering inspector.

GhostRE covers the provider-free core of reverse engineering —
format identification, header / section / import parsing, byte
entropy, printable strings, and JavaScript application structure —
in pure Python stdlib. It runs anywhere GhostIDE runs, including
on-device, with no external analysis engines (no Ghidra, Hopper,
JADX, Rizin or Node), no subprocesses, and no network.

Every inspector is bounds-checked and total: malformed input yields
whatever parsed plus a ``warnings`` list, never a crash.
"""

__version__ = "0.1.0"
