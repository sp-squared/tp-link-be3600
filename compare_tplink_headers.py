#!/usr/bin/env python3
"""
TP-Link firmware structure analyzer / differ.

Rewrite notes vs. the original:
  (a) Fixed the KB delta (operator-precedence bug: a - b / 1024).
  (b) Section boundaries are DISCOVERED via a sliding-window entropy scan
      instead of hardcoded offsets like 0x0130. Nothing is assumed about
      where the "signature" or "metadata" lives.
  (c) Each high-entropy segment is classified compressed-vs-encrypted using,
      in order of trust:
        1. known container/compression magic bytes  -> high confidence
        2. byte-distribution uniformity (chi-square) -> heuristic only
      The wording of the verdicts is deliberately hedged: high entropy alone
      cannot prove encryption, and this tool does not pretend otherwise.

  Changes in this revision:
  (d) gzip is now matched as 1f 8b 08 -- the third byte is the compression
      method, and 08 (deflate) is the only one in practice. A bare 1f 8b
      scatters false hits through high-entropy data; requiring the method
      byte removes almost all of them.
  (e) Strings are NO LONGER extracted from high-entropy segments. Printable
      runs inside compressed/encrypted data are binary coincidences, not
      real strings, so only low/mid-band regions are scanned.
  (f) A per-window entropy profile is written to CSV (offset,entropy,band)
      for every image, so the profile can be plotted directly.

Stdlib-only, but uses numpy for the entropy scan if it's importable
(much faster on ~40 MB images). Falls back to pure Python otherwise.
"""

import sys
import csv
import math
import re
from pathlib import Path
from dataclasses import dataclass

try:
    import numpy as np
    _HAVE_NUMPY = True
except ImportError:
    _HAVE_NUMPY = False


# --- Tunables -----------------------------------------------------------------

WINDOW = 4096          # bytes per entropy window (section-boundary resolution)
LOW_BAND = 6.0         # < this  -> "structured" (header/text/code/padding)
HIGH_BAND = 7.5        # >= this -> "high entropy" (compressed or encrypted)
MIN_SEGMENT = WINDOW   # don't report slivers smaller than one window
CHI2_DF = 255          # degrees of freedom for a 256-bin byte histogram
# For uniform random bytes chi2 ~ N(255, sqrt(510)) ~ 255 +/- 22.6.
# We treat chi2/df well above 1.0 as "has residual structure".
CHI2_UNIFORM_MAX = 310 # above this, distribution is not convincingly uniform


# --- Known magics (offset-relative to a segment start, and free-scan) ---------
# Kept short and router-relevant. Matched at a segment's start for the verdict,
# and free-scanned across the whole file for the locator section.
MAGICS = {
    b"\x1f\x8b\x08":             ("gzip (deflate)", "compression"),
    b"\x42\x5a\x68":             ("bzip2", "compression"),
    b"\xfd7zXZ\x00":             ("xz", "compression"),
    b"\x5d\x00\x00":             ("lzma (raw)", "compression"),
    b"\x04\x22\x4d\x18":         ("lz4 frame", "compression"),
    b"\x28\xb5\x2f\xfd":         ("zstd", "compression"),
    b"\x89\x4c\x5a\x4f":         ("lzop", "compression"),
    b"\x78\x01":                 ("zlib (no/low comp)", "compression"),
    b"\x78\x9c":                 ("zlib (default)", "compression"),
    b"\x78\xda":                 ("zlib (best)", "compression"),
    b"hsqs":                     ("squashfs LE", "filesystem"),
    b"sqsh":                     ("squashfs BE", "filesystem"),
    b"\x85\x19":                 ("jffs2 LE", "filesystem"),
    b"\x19\x85":                 ("jffs2 BE", "filesystem"),
    b"UBI#":                     ("ubi", "filesystem"),
    b"\x31\x18\x10\x06":         ("ubifs", "filesystem"),
    b"\x45\x3d\xcd\x28":         ("cramfs", "filesystem"),
    b"\x27\x05\x19\x56":         ("uImage (U-Boot legacy)", "container"),
    b"\xd0\x0d\xfe\xed":         ("FIT/dtb", "container"),
    b"HDR0":                     ("TRX", "container"),
    b"\x7fELF":                  ("ELF", "executable"),
    b"070701":                   ("cpio newc", "archive"),
}


@dataclass
class Segment:
    start: int
    end: int
    band: str            # "low" | "high" | "mid"
    entropy: float       # mean window entropy across the segment

    @property
    def size(self) -> int:
        return self.end - self.start


# --- Primitives ---------------------------------------------------------------

def _hist256(buf: bytes):
    if _HAVE_NUMPY:
        a = np.frombuffer(buf, dtype=np.uint8)
        return np.bincount(a, minlength=256).astype(np.float64)
    h = [0] * 256
    for b in buf:
        h[b] += 1
    return h


def shannon_entropy(buf: bytes) -> float:
    n = len(buf)
    if n == 0:
        return 0.0
    h = _hist256(buf)
    if _HAVE_NUMPY:
        p = h[h > 0] / n
        return float(-(p * np.log2(p)).sum()) + 0.0   # normalize -0.0 -> 0.0
    ent = 0.0
    for c in h:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent + 0.0                                    # normalize -0.0 -> 0.0


def chi_square_uniform(buf: bytes) -> float:
    """Chi-square statistic vs. a uniform 256-bin distribution.

    ~255 means 'looks like uniform random bytes' (encryption, or raw strong
    compression with no header). Much larger means residual structure.
    Only meaningful for reasonably large buffers (>= ~4 KB).
    """
    n = len(buf)
    if n < 1024:
        return float("nan")
    h = _hist256(buf)
    expected = n / 256.0
    if _HAVE_NUMPY:
        return float(((h - expected) ** 2 / expected).sum())
    return sum((c - expected) ** 2 / expected for c in h)


def printable_ratio(buf: bytes) -> float:
    if not buf:
        return 0.0
    printable = sum(1 for b in buf if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return printable / len(buf)


# --- Section discovery --------------------------------------------------------

def band_of(entropy: float) -> str:
    if entropy < LOW_BAND:
        return "low"
    if entropy >= HIGH_BAND:
        return "high"
    return "mid"


def entropy_profile(data: bytes) -> list[tuple[int, float]]:
    """Per-window Shannon entropy: list of (window_offset, entropy).

    Computed once and reused for segment discovery and the CSV export, so the
    ~40 MB image is only scanned a single time.
    """
    return [(off, shannon_entropy(data[off:off + WINDOW]))
            for off in range(0, len(data), WINDOW)]


def segments_from_profile(profile: list[tuple[int, float]], total: int) -> list[Segment]:
    """Coalesce the per-window profile into same-band segments."""
    segments: list[Segment] = []
    cur_band = None
    seg_start = 0
    ent_sum = 0.0
    ent_count = 0

    for off, e in profile:
        b = band_of(e)
        if cur_band is None:
            cur_band, seg_start, ent_sum, ent_count = b, off, e, 1
        elif b == cur_band:
            ent_sum += e
            ent_count += 1
        else:
            segments.append(Segment(seg_start, off, cur_band, ent_sum / ent_count))
            cur_band, seg_start, ent_sum, ent_count = b, off, e, 1

    if cur_band is not None:
        segments.append(Segment(seg_start, total, cur_band, ent_sum / ent_count))

    # Merge away sub-window noise by folding tiny segments into the previous one.
    merged: list[Segment] = []
    for s in segments:
        if merged and s.size < MIN_SEGMENT:
            prev = merged[-1]
            merged[-1] = Segment(prev.start, s.end, prev.band, prev.entropy)
        else:
            merged.append(s)
    return merged


def write_entropy_csv(profile: list[tuple[int, float]], out_path: Path) -> None:
    """Dump (offset, entropy, band) per window for plotting."""
    with out_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["offset", "entropy", "band"])
        for off, e in profile:
            w.writerow([off, f"{e:.4f}", band_of(e)])


def classify_high_segment(data: bytes, seg: Segment,
                          pre: int = WINDOW, post: int = WINDOW) -> str:
    """Compressed vs. encrypted verdict for one high-entropy segment.

    A real container/compression header rarely lands exactly on the
    WINDOW-aligned boundary: tail padding or a small partition header usually
    sits on one side of it, and the entropy window the header falls in can be
    classified as the adjacent band (squashfs seen at +0x85 in one image and
    at -0xB26 in the next). So scan a probe spanning one window before to one
    window after the boundary.

    Two passes: first look for a filesystem/container header (the structural
    marker), only then fall back to a bare compression magic. Without this a
    squashfs superblock loses to the xz block that starts ~96 bytes later
    inside it -- technically closer to the boundary, but far less informative.
    2-byte magics are skipped throughout -- too many coincidental hits in
    high-entropy data.
    """
    probe_start = max(0, seg.start - pre)
    probe = data[probe_start:seg.start + post]
    anchor = seg.start - probe_start          # index of the boundary within probe

    def nearest(kinds) -> tuple | None:
        best = None                            # (abs_dist, signed_off, name, kind)
        for magic, (name, kind) in MAGICS.items():
            if len(magic) < 3:
                continue
            if kinds is not None and kind not in kinds:
                continue
            j = probe.find(magic)
            if j == -1:
                continue
            signed = j - anchor
            if best is None or abs(signed) < best[0]:
                best = (abs(signed), signed, name, kind)
        return best

    hit = nearest(("filesystem", "container")) or nearest(None)
    if hit is not None:
        _, signed, name, kind = hit
        off = seg.start + signed
        if signed == 0:
            pos = "at segment start"
        elif signed > 0:
            pos = f"+0x{signed:X} into segment"
        else:
            pos = f"-0x{-signed:X} before boundary"
        return f"{kind}: {name} (magic {pos}, 0x{off:X}) [high confidence]"

    # No header found near the boundary. Fall back to a distribution test.
    sample = data[seg.start:min(seg.end, seg.start + (1 << 20))]  # cap at 1 MiB
    chi2 = chi_square_uniform(sample)
    if math.isnan(chi2):
        return "unknown (segment too small to test)"
    ratio = chi2 / CHI2_DF
    if chi2 <= CHI2_UNIFORM_MAX:
        return (f"no compression header; byte distribution statistically uniform "
                f"(chi2/df={ratio:.2f}) -> consistent with ENCRYPTION or raw/headerless "
                f"compression [heuristic]")
    return (f"no known header; distribution has residual structure "
            f"(chi2/df={ratio:.2f}) -> leans COMPRESSED/packed, not encrypted [heuristic]")


def scan_magics(data: bytes, per_magic: int = 8, total_limit: int = 200):
    """Free-scan the whole image for known magics. Returns [(offset, label)].

    Each magic has its OWN cap (per_magic). A single common magic -- e.g. the
    many stray 1f 8b 08 sequences that occur by chance inside xz/LZMA data --
    can otherwise consume a single global budget and hide rarer but far more
    important hits like squashfs (hsqs) or lzma. total_limit bounds the whole
    output as a backstop.
    """
    hits = []
    for magic, (name, kind) in MAGICS.items():
        count = 0
        start = 0
        while count < per_magic and len(hits) < total_limit:
            i = data.find(magic, start)
            if i == -1:
                break
            # Skip the 2-byte zlib/jffs2 magics unless word-aligned-ish, to cut
            # false positives inside high-entropy data.
            if len(magic) <= 2 and (i % 4) not in (0, 2):
                start = i + 1
                continue
            hits.append((i, f"{name} [{kind}]"))
            count += 1
            start = i + len(magic)
        if len(hits) >= total_limit:
            break
    hits.sort()
    return hits


def extract_strings(data: bytes, regions: list[tuple[int, int]],
                    minlen: int = 8, limit: int = 12):
    """Real strings from low/mid-entropy regions only.

    High-entropy segments are skipped entirely: printable runs inside
    compressed or encrypted data are coincidences, not strings. `regions` is a
    list of (start, end) byte ranges to scan (typically the non-high bands).
    """
    seen = []
    for start, end in regions:
        chunk = data[start:end]
        for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, chunk):
            s = m.group().decode("ascii", "ignore")
            # Drop runs that are mostly punctuation/symbols (binary coincidences).
            alnum = sum(c.isalnum() for c in s)
            if alnum / len(s) < 0.5:
                continue
            abs_off = start + m.start()
            if not any(s == prev_s for _, prev_s in seen):
                seen.append((abs_off, s))
            if len(seen) >= limit:
                return seen
    return seen


# --- Reporting ----------------------------------------------------------------

def analyze(path: Path, csv_dir: Path | None = None) -> dict:
    data = path.read_bytes()
    profile = entropy_profile(data)
    segments = segments_from_profile(profile, len(data))

    # Scan strings only in low/mid-band regions.
    scannable = [(s.start, s.end) for s in segments if s.band != "high"]

    csv_path = (csv_dir or path.parent) / f"{path.stem}.entropy.csv"
    write_entropy_csv(profile, csv_path)

    return {
        "path": path,
        "size": len(data),
        "segments": segments,
        "magics": scan_magics(data),
        "strings": extract_strings(data, scannable),
        "csv": csv_path,
        "data": data,
    }


def print_file_report(fw: dict):
    print(f"\n{'-'*75}")
    print(f"FILE: {fw['path'].name}")
    print(f"  size: {fw['size']:,} bytes")
    print(f"  entropy profile CSV: {fw['csv']}")

    print(f"\n  Discovered sections (entropy scan, {WINDOW}-byte windows):")
    print(f"    {'range':<23} {'size':>12}  {'band':<5} {'H':>5}  classification")
    for s in fw["segments"]:
        cls = ""
        if s.band == "high":
            cls = classify_high_segment(fw["data"], s)
        elif s.band == "low":
            seg_bytes = fw["data"][s.start:s.end]
            pr = printable_ratio(seg_bytes[:4096])
            if seg_bytes[:4096].count(0) > 4096 * 0.9:
                cls = "padding / zero-fill"
            elif pr > 0.85:
                cls = "text / cleartext header"
            else:
                cls = "structured (header/code/tables)"
        rng = f"0x{s.start:08X}-0x{s.end:08X}"
        print(f"    {rng:<23} {s.size:>12,}  {s.band:<5} {s.entropy:>5.2f}  {cls}")

    print(f"\n  Known magics located in image:")
    if fw["magics"]:
        for off, label in fw["magics"]:
            print(f"    0x{off:08X}  {label}")
    else:
        print(f"    (none found)")

    print(f"\n  Strings (>=8 chars, low/mid-entropy regions only):")
    if fw["strings"]:
        for off, s in fw["strings"]:
            print(f"    0x{off:08X}  {s[:60]}")
    else:
        print(f"    (none found)")


def compare(path_a: Path, path_b: Path):
    print("=" * 75)
    print("TP-Link Firmware Structure Analysis")
    print("=" * 75)

    a = analyze(path_a)
    b = analyze(path_b)

    print(f"\n[1] Overview")
    print(f"  A: {a['path'].name}  ({a['size']:,} bytes)")
    print(f"  B: {b['path'].name}  ({b['size']:,} bytes)")
    delta = b["size"] - a["size"]
    print(f"  delta B-A: {delta:,} bytes ({delta / 1024:.2f} KB)")   # fixed precedence

    print_file_report(a)
    print_file_report(b)

    print(f"\n{'-'*75}")
    print("[note] 'consistent with encryption' means only that no compression")
    print("header was found and the bytes are statistically uniform. That is a")
    print("heuristic, not proof -- raw/headerless compression looks the same.")
    print("Treat magic-byte hits as fact and chi-square verdicts as a lead.")
    print("=" * 75 + "\n")


def main():
    base_dir = Path.home() / "be3600-diff"
    p_a = sorted((base_dir / "1.3.5").glob("*.bin")) if (base_dir / "1.3.5").exists() else []
    p_b = sorted((base_dir / "1.3.7").glob("*.bin")) if (base_dir / "1.3.7").exists() else []

    if len(sys.argv) == 3:
        compare(Path(sys.argv[1]), Path(sys.argv[2]))
        return
    if p_a and p_b:
        compare(p_a[0], p_b[0])
        return

    print("[!] No .bin files auto-located in ~/be3600-diff/1.3.5 or 1.3.7.")
    print("    Usage: python3 compare_tplink_headers.py <fileA.bin> <fileB.bin>")


if __name__ == "__main__":
    main()
