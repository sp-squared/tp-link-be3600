#!/usr/bin/env python3
"""
Normalize TP-Link shuffled-opcode + LNUM Lua 5.1 bytecode to a canonical,
host-portable stock Lua 5.1 chunk that luadec / unluac can decompile.

Three transforms in one pass:
  1. opcode un-shuffle   -- map each instruction's opcode field back to the
     canonical Lua 5.1 numbering (opcode order from tplink_lua_opmap.py).
  2. LNUM -> stock       -- OpenWrt's integer-subtype patch tags integer
     constants LUA_TINT=9; convert them to stock LUA_TNUMBER (doubles).
  3. retarget the chunk  -- re-emit with a canonical header
     (little-endian, sizeof int=4, size_t=8, Instruction=4, lua_Number=8),
     widening the size_t-encoded string lengths accordingly. This is what lets
     bytecode compiled for 32-bit ARM (size_t=4) load in a 64-bit luadec built
     on x86-64 (size_t=8), instead of failing with "bad header".

The LNUM integer width isn't in the header, so it's auto-calibrated: the width
that makes the whole chunk transcode to exact EOF is the right one.

Usage:
    python3 tplink_lua_unshuffle.py --opnames tp_opnames.txt in.luac out.luac

Stdlib only.
"""

import sys
import struct
import argparse

STOCK_NAMES = [
    "MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETGLOBAL", "GETTABLE",
    "SETGLOBAL", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF", "ADD", "SUB", "MUL",
    "DIV", "MOD", "POW", "UNM", "NOT", "LEN", "CONCAT", "JMP", "EQ", "LT", "LE",
    "TEST", "TESTSET", "CALL", "TAILCALL", "RETURN", "FORLOOP", "FORPREP",
    "TFORLOOP", "SETLIST", "CLOSE", "CLOSURE", "VARARG",
]
STOCK_INDEX = {n: i for i, n in enumerate(STOCK_NAMES)}
OP_MASK = (1 << 6) - 1

# canonical output target (standard 64-bit little-endian Lua 5.1)
T_INT = 4
T_SIZET = 8
T_NUM = 8
CANON_HEADER = b"\x1bLua\x51\x00\x01" + bytes([T_INT, T_SIZET, 4, T_NUM, 0])


class Walk:
    def __init__(self, data: bytes, emit: bool):
        self.d = data
        self.p = 0
        self.out = bytearray() if emit else None
        self.instr = self.remap = self.lnum = 0

    def rd(self, n: int) -> bytes:
        if self.p + n > len(self.d):
            raise ValueError(f"unexpected EOF at {self.p} (+{n})")
        b = self.d[self.p:self.p + n]
        self.p += n
        return b

    def w(self, b: bytes):
        if self.out is not None:
            self.out += b


def read_header(wk: Walk) -> dict:
    """Consume (never emit) the source header; return its parameters."""
    if wk.rd(4) != b"\x1bLua":
        raise ValueError("not a Lua chunk (bad signature)")
    if wk.rd(1)[0] != 0x51:
        raise ValueError("not Lua 5.1")
    wk.rd(1)                              # format
    endian = wk.rd(1)[0]
    si = wk.rd(1)[0]
    sst = wk.rd(1)[0]
    sin = wk.rd(1)[0]
    snum = wk.rd(1)[0]
    integ = wk.rd(1)[0]
    if sin != 4:
        raise ValueError(f"sizeof(Instruction)={sin}, expected 4")
    return {"o": "little" if endian == 1 else "big",
            "so": "<" if endian == 1 else ">",
            "si": si, "sst": sst, "snum": snum, "integ": integ}


def src_int(wk, h):                       # read an int in source width/endianness
    return int.from_bytes(wk.rd(h["si"]), h["o"])


def rint(wk, h):                          # read source int, emit canonical int
    v = src_int(wk, h)
    wk.w(v.to_bytes(T_INT, "little"))
    return v


def rstring(wk, h):                       # read source string, emit canonical
    n = int.from_bytes(wk.rd(h["sst"]), h["o"])
    wk.w(n.to_bytes(T_SIZET, "little"))
    if n:
        wk.w(wk.rd(n))


def emit_number_from_double(wk, d):
    wk.w(b"\x03" + struct.pack("<d", d))


def walk_function(wk: Walk, h: dict, intw: int, opmap: list[int]):
    rstring(wk, h)                        # source name
    rint(wk, h); rint(wk, h)              # linedefined, lastlinedefined
    wk.w(wk.rd(4))                        # nups, numparams, is_vararg, maxstack (bytes)

    # code
    n = rint(wk, h)
    for _ in range(n):
        instr = int.from_bytes(wk.rd(4), h["o"])
        old = instr & OP_MASK
        new = opmap[old]
        wk.instr += 1
        if new != old:
            wk.remap += 1
        wk.w(((instr & ~OP_MASK) | new).to_bytes(4, "little"))

    # constants
    n = rint(wk, h)
    for _ in range(n):
        t = wk.rd(1)[0]
        if t == 0:
            wk.w(b"\x00")
        elif t == 1:
            wk.w(b"\x01" + wk.rd(1))
        elif t == 3:                      # number
            raw = wk.rd(h["snum"])
            if h["integ"]:
                d = float(int.from_bytes(raw, h["o"], signed=True))
            elif h["snum"] == 8:
                d = struct.unpack(h["so"] + "d", raw)[0]
            elif h["snum"] == 4:
                d = struct.unpack(h["so"] + "f", raw)[0]
            else:
                raise ValueError(f"unsupported lua_Number size {h['snum']}")
            emit_number_from_double(wk, d)
        elif t == 9:                      # LNUM integer -> number
            val = int.from_bytes(wk.rd(intw), h["o"], signed=True)
            wk.lnum += 1
            emit_number_from_double(wk, float(val))
        elif t == 4:
            wk.w(b"\x04"); rstring(wk, h)
        else:
            raise ValueError(f"bad constant type {t} at {wk.p}")

    # nested prototypes
    n = rint(wk, h)
    for _ in range(n):
        walk_function(wk, h, intw, opmap)

    # debug: lineinfo
    n = rint(wk, h)
    for _ in range(n):
        rint(wk, h)
    # debug: locvars
    n = rint(wk, h)
    for _ in range(n):
        rstring(wk, h); rint(wk, h); rint(wk, h)
    # debug: upvalue names
    n = rint(wk, h)
    for _ in range(n):
        rstring(wk, h)


def build_map(tp_names):
    if len(tp_names) != len(STOCK_NAMES):
        raise ValueError(f"expected {len(STOCK_NAMES)} opcode names, got {len(tp_names)}")
    if sorted(tp_names) != sorted(STOCK_NAMES):
        raise ValueError(f"opcode name set mismatch: {sorted(set(tp_names) ^ set(STOCK_NAMES))}")
    return [STOCK_INDEX[tp_names[i]] for i in range(len(tp_names))]


def transcode(data, tp_names):
    opmap = build_map(tp_names)
    last = None
    width = None
    for iw in (4, 8, 2, 16):
        wk = Walk(data, emit=False)
        try:
            h = read_header(wk)
            if h["o"] == "big":
                sys.stderr.write("[warn] source is big-endian; output will be "
                                 "little-endian (values byte-swapped)\n")
            walk_function(wk, h, iw, opmap)
        except ValueError as e:
            last = e
            continue
        if wk.p == len(data):
            width = iw
            break
    if width is None:
        raise last or ValueError("chunk did not parse to EOF under any int width")

    wk = Walk(data, emit=True)
    h = read_header(wk)
    wk.w(CANON_HEADER)                    # emit canonical header, not the source one
    walk_function(wk, h, width, opmap)
    if wk.p != len(data):
        sys.stderr.write(f"[warn] {len(data) - wk.p} trailing bytes\n")
    sys.stderr.write(f"[ok] {wk.instr} instructions, {wk.remap} opcodes remapped, "
                     f"{wk.lnum} LNUM ints -> number; retargeted to "
                     f"int{T_INT}/size_t{T_SIZET}/num{T_NUM} LE"
                     + (f" (src int width {width}B)" if width != 4 else "") + "\n")
    return bytes(wk.out)


def read_opnames(path):
    with open(path) as f:
        return [t.strip().upper().replace("OP_", "") for t in f.read().split() if t.strip()]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--opnames", required=True)
    ap.add_argument("infile")
    ap.add_argument("outfile")
    args = ap.parse_args()
    tp_names = read_opnames(args.opnames)
    with open(args.infile, "rb") as f:
        data = f.read()
    out = transcode(data, tp_names)
    with open(args.outfile, "wb") as f:
        f.write(out)
    sys.stderr.write(f"[done] wrote {args.outfile} -- decompile with: luadec {args.outfile}\n")


if __name__ == "__main__":
    main()
