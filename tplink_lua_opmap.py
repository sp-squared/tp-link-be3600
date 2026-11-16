#!/usr/bin/env python3
"""
Recover TP-Link's Lua 5.1 opcode order (for tplink_lua_unshuffle.py).

Two sources, in order of preference:

  from-lib <liblua.so>     Authoritative. Reads the device's own Lua VM and
                           recovers the opcode enum order from the luaP_opnames
                           table (the array of opcode-name C-strings, which is
                           kept in opcode order). Works on stripped libraries
                           via either direct pointers or ELF relocations.

  from-source <lopcodes.h> Only if the GPL drop shipped TP-Link's (modified)
                           Lua source. Parses the `OP_*` enum order. NOTE: many
                           GPL drops ship STOCK lua or omit it, in which case
                           this yields the canonical order and will NOT match
                           the shuffled bytecode -- prefer from-lib.

Output: 38 opcode names, one per line, in TP-Link's opcode order -> feed to
tplink_lua_unshuffle.py --opnames.

Needs pyelftools for from-lib:  pip install pyelftools
"""

import re
import sys
import argparse

STOCK_NAMES = [
    "MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETGLOBAL", "GETTABLE",
    "SETGLOBAL", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF", "ADD", "SUB", "MUL",
    "DIV", "MOD", "POW", "UNM", "NOT", "LEN", "CONCAT", "JMP", "EQ", "LT", "LE",
    "TEST", "TESTSET", "CALL", "TAILCALL", "RETURN", "FORLOOP", "FORPREP",
    "TFORLOOP", "SETLIST", "CLOSE", "CLOSURE", "VARARG",
]
NAMESET = set(STOCK_NAMES)


# --- from Lua source (lopcodes.h) --------------------------------------------

def from_source(path: str) -> list[str]:
    text = open(path, "r", errors="replace").read()
    # Grab the typedef enum { OP_MOVE, OP_LOADK, ... } body.
    m = re.search(r"enum\s+OpCode?.*?\{(.*?)\}", text, re.S) \
        or re.search(r"typedef\s+enum\s*\{(.*?)\}\s*OpCode", text, re.S) \
        or re.search(r"\{(.*?OP_MOVE.*?)\}", text, re.S)
    if not m:
        raise ValueError("couldn't find the OpCode enum in this header")
    body = m.group(1)
    names = []
    for tok in re.findall(r"OP_([A-Z0-9_]+)", body):
        if tok in NAMESET and tok not in names:
            names.append(tok)
    return names


# --- from liblua.so ----------------------------------------------------------

def from_lib(path: str) -> list[str]:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import Section
    from elftools.elf.relocation import RelocationSection

    f = open(path, "rb")
    elf = ELFFile(f)
    little = elf.little_endian
    psize = elf.elfclass // 8          # pointer size: 4 or 8
    order = "little" if little else "big"

    # 1) locate every opcode-name C-string -> set of virtual addresses
    name_at_vaddr: dict[int, str] = {}
    alloc_progbits = []
    for sec in elf.iter_sections():
        if sec["sh_type"] != "SHT_PROGBITS":
            continue
        if not (sec["sh_flags"] & 0x2):   # SHF_ALLOC
            continue
        alloc_progbits.append(sec)
        data = sec.data()
        base = sec["sh_addr"]
        for name in STOCK_NAMES:
            needle = name.encode() + b"\x00"
            start = 0
            while True:
                i = data.find(needle, start)
                if i < 0:
                    break
                # Record EVERY occurrence. GCC suffix-merges string constants,
                # so e.g. "CALL\0" lives inside "TAILCALL\0" and luaP_opnames
                # may point straight at that interior address -- requiring a
                # preceding NUL would miss it.
                name_at_vaddr[base + i] = name
                start = i + 1
    found = set(name_at_vaddr.values())
    missing = NAMESET - found
    if missing:
        sys.stderr.write(f"[warn] opcode-name strings not found: {sorted(missing)}\n")

    vaddr_of = {}          # name -> vaddr (first). ok if unique enough
    for va, nm in name_at_vaddr.items():
        vaddr_of.setdefault(nm, va)
    name_vaddrs = set(name_at_vaddr)

    # 2a) try DIRECT pointers: a run of pointer slots whose values are name vaddrs
    def scan_direct():
        best = None
        for sec in alloc_progbits:
            data = sec.data()
            base = sec["sh_addr"]
            n = len(data) // psize
            slots = [int.from_bytes(data[i*psize:(i+1)*psize], order) for i in range(n)]
            i = 0
            while i < n:
                if slots[i] in name_vaddrs:
                    j = i
                    seq = []
                    while j < n and slots[j] in name_vaddrs:
                        seq.append(name_at_vaddr[slots[j]]); j += 1
                    if len({*seq}) >= 38 and (best is None or len(seq) > len(best)):
                        best = seq
                    i = j
                else:
                    i += 1
        return best

    # 2b) try RELOCATIONS: relative relocs whose target is a name vaddr,
    #     taken in r_offset order over a contiguous pointer-stride run.
    def scan_relocs():
        targets: dict[int, int] = {}   # r_offset -> target vaddr
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            is_rela = sec.is_RELA()
            for r in sec.iter_relocations():
                off = r["r_offset"]
                if is_rela:
                    tgt = r["r_addend"]
                else:
                    # REL: addend is the value stored at r_offset; read it
                    tgt = _read_at_vaddr(elf, off, psize, order)
                    if tgt is None:
                        continue
                if tgt in name_vaddrs:
                    targets[off] = tgt
        if not targets:
            return None
        offs = sorted(targets)
        # find the longest run with constant pointer-size stride
        best = None
        i = 0
        while i < len(offs):
            run = [offs[i]]
            j = i + 1
            while j < len(offs) and offs[j] - run[-1] == psize:
                run.append(offs[j]); j += 1
            seq = [name_at_vaddr[targets[o]] for o in run]
            if len({*seq}) >= 38 and (best is None or len(seq) > len(best)):
                best = seq
            i = j
        return best

    seq = scan_direct() or scan_relocs()
    f.close()
    if not seq:
        raise ValueError(
            "could not locate luaP_opnames in this library.\n"
            "  - confirm it is the device's liblua.so (or the lua binary),\n"
            "  - it may be fully stripped with packed relocations; in that case\n"
            "    open it in Ghidra, find the array of 38 pointers to the opcode\n"
            "    name strings (xref the \"MOVE\" string), and read its order.")
    # trim to exactly 38 in order, de-duping a possible NULL/sentinel tail
    out, seen = [], set()
    for nm in seq:
        if nm not in seen:
            out.append(nm); seen.add(nm)
        if len(out) == 38:
            break
    return out


def _read_at_vaddr(elf, vaddr, psize, order):
    for sec in elf.iter_sections():
        if sec["sh_type"] not in ("SHT_PROGBITS",):
            continue
        base = sec["sh_addr"]
        size = sec["sh_size"]
        if base <= vaddr < base + size:
            data = sec.data()
            off = vaddr - base
            return int.from_bytes(data[off:off + psize], order)
    return None


# --- validation / output -----------------------------------------------------

def validate(names: list[str]):
    if len(names) != 38:
        sys.stderr.write(f"[warn] got {len(names)} names, expected 38\n")
    extra = [n for n in names if n not in NAMESET]
    if extra:
        sys.stderr.write(f"[warn] non-standard names: {extra}\n")
    if sorted(names) == sorted(STOCK_NAMES):
        if names == STOCK_NAMES:
            sys.stderr.write("[note] order is the STOCK Lua 5.1 order -- either this "
                             "build isn't shuffled, or you read stock source.\n")
        else:
            sys.stderr.write("[ok] recovered a valid permutation of the 38 opcodes.\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("from-lib"); s1.add_argument("path")
    s2 = sub.add_parser("from-source"); s2.add_argument("path")
    args = ap.parse_args()

    if args.cmd == "from-lib":
        names = from_lib(args.path)
    else:
        names = from_source(args.path)
    validate(names)
    print("\n".join(names))


if __name__ == "__main__":
    main()
