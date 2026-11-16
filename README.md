# TP-Link Archer BE3600 (V2.6) Firmware Reverse-Engineering — 1.3.5 → 1.3.7

A full, reproducible walkthrough: from encrypted OEM firmware to decompiled LuCI
controllers, and the actual delta between firmware **1.3.5** and **1.3.7**.

**TL;DR** — The two images decrypt with TP-Link's own published keys, carve into a
standard Broadcom OpenWrt rootfs, and the real 1.3.5 → 1.3.7 change is a new
**certificate-management feature** (a downloadable device CA + a persisted 10-year
CA chain). Nearly everything else that "differs" between the two images is
recompilation noise — proven at the instruction level for the VPN and access-control
controllers, whose existing logic is unchanged (their only additions are one new
`set_clientinfo` admin handler and a single input-validator tweak).

---

## 0. Target & scope

| | |
|---|---|
| Device | Archer BE3600 **V2.6** (US/USW) |
| Shared image | Same payload as **Archer BE230 V2**; built from the **BE220 v1.0 "SCR"** tree |
| SoC / SDK | Broadcom `bcm963xx` SDK **5.04L.04**, Linux kernel **4.19.294** |
| Arch | ARM, 32-bit, EABI5, little-endian |
| Rootfs | squashfs v4, **xz**-compressed, 1 MiB block |
| Kernel | **LZMA**-compressed |
| Lua | 5.1, **LNUM** (OpenWrt integer-subtype patch), **shuffled VM opcodes** |

Versions compared:

| Version | Build | fw_id |
|---|---|---|
| 1.3.5 | `Build 20260812 rel.8951` | `D74490D431A701960E4A894F26260F39` |
| 1.3.7 | `Build 20261022 rel.15717` (RC) | `F266C30D313E116AC991BA658263C73F` |

> The filenames are telling: 1.3.5 ships as `be220v1-be230v2-be3600ProJP-all-…`
> and 1.3.7 as `be230v2_us-sp1-…`. Different packaging labels, same device payload.

---

## 1. Environment

Ubuntu 24.04 (x86-64; tested under WSL2). Install once:

```bash
sudo apt install -y binwalk liblzo2-dev
python3 -m venv venv && . venv/bin/activate
pip install pyelftools jefferson ubi_reader    # jefferson/ubi_reader: JFFS2/UBI carving
```

Project tools (in this repo):

| File | Purpose |
|---|---|
| `compare_tplink_headers.py` | Entropy/structure analyzer & differ |
| `tplink_lua_opmap.py` | Recover the shuffled Lua opcode order from `liblua.so` |
| `tplink_lua_unshuffle.py` | Normalize shuffled+LNUM 5.1 bytecode → stock Lua 5.1 |
| `luadec-x86_64` | Prebuilt luadec (Lua 5.1) for decompiling the normalized bytecode |

---

## 2. Acquire firmware + GPL source

Firmware (`.zip` → `.bin`) from the TP-Link **Archer BE3600 V2.6** download page.
GPL source from the **Open Source Code (GPL)** section of that same page:

- **GPL tarball:** `BE3600v2.6_GPL_20250918.tar.gz`
  (`https://static.tp-link.com/upload/gpl-code/2025/202510/20251015/BE3600v2.6_GPL_20250918.tar.gz`)

```
~/be3600-diff/
  1.3.5/  be220v1-be230v2-be3600ProJP-all-up-ver1-3-5-P1[...]_2048_signed_...bin
  1.3.7/  be230v2_us-sp1-up-ver1-3-7-P1[...]_2048_RC_...bin
  gpl/    BE3600v2.6_GPL_20250918.tar.gz (extracted to gpl/src/)
```

> The GPL drop matters because TP-Link's firmware signing/verification keys are
> recoverable from the binaries they themselves publish. Great care: this uses
> only vendor-published material.

---

## 3. Key recovery & decryption

TP-Link firmware is wrapped with a fixed scheme: an **RSA-2048 signature** over the
image, and **AES-128-CBC** payload encryption. The decryptor harvests the RSA keys
from TP-Link's own GPL/firmware binaries; **every image in the family uses the same
scheme**, so a donor image yields keys that verify the BE3600 too.

```bash
git clone https://github.com/robbins/tp-link-decrypt    # fork of watchfulip's tool
cd tp-link-decrypt
./extract_keys.sh        # downloads donor firmware, carves it, writes RSA keys to headers
make
```

`extract_keys.sh` needs `binwalk` + `jefferson` + `ubi_reader` installed (it carves
JFFS2/UBI donor images to reach the key-bearing binary). Success looks like:

```
[INFO] Extracted RSA keys match the expected data.
[INFO] RSA keys written to include directory. Ready for make.
```

Decrypt both images:

```bash
unzip -o 1.3.5/*.zip -d 1.3.5/ ; unzip -o 1.3.7/*.zip -d 1.3.7/
bin/tp-link-decrypt "1.3.5/<file>.bin"     # -> <file>.bin.dec
bin/tp-link-decrypt "1.3.7/<file>.bin"
```

Each run prints `fw-type: found / RSA-2048 / Firmware verification successful`. The
**AES KEY/IV are per-image** (e.g. 1.3.5 `KEY=02a37484…`, 1.3.7 `KEY=f2c037d3…`),
carried in the signed header; the RSA key is the shared constant. Output is ~20 bytes
smaller than input (a small wrapper is stripped).

---

## 4. Structure analysis

`compare_tplink_headers.py` does a sliding-window Shannon-entropy scan, classifies
high-entropy regions by nearby magic bytes (with a look-ahead so a header a little off
the window boundary is still found), free-scans known magics (per-magic caps so a flood
of one magic can't hide the rest), and writes a per-window entropy CSV for plotting.

```bash
python3 compare_tplink_headers.py "1.3.5/<file>.bin.dec" "1.3.7/<file>.bin.dec"
```

Decrypted layout (both versions, near-identical):

```
0x000000–0x203000   cleartext TP-Link "Cloud" header + SupportList (readable strings)
0x203000–~0x590000  LZMA-compressed kernel         (headerless at the window boundary)
~0x590000           4× FIT/dtb board device-trees  (BE220 / BE230 / BE3600 variants)
~0x5C4000–EOF       xz-compressed squashfs rootfs  (v4, 1 MiB block)
```

> Note: XZ/LZMA output is statistically uniform, so a naïve chi-square test reads it
> as "possibly encrypted." The honest verdict is "encrypted **or** raw/headerless
> compression" — the magic-byte scan resolves it. 1.3.5 rootfs = 4994 inodes,
> 1.3.7 = 4995 (one added file).

---

## 5. Extract the filesystem

```bash
binwalk -e "1.3.5/<file>.bin.dec" -C extract_135
binwalk -e "1.3.7/<file>.bin.dec" -C extract_137
```

This yields `…/squashfs-root/`, a normal Broadcom OpenWrt tree (`/lib/modules/4.19.294`,
`bcm_flasher`, `ntfs-3g`, LuCI under `/usr/lib/lua/luci`, …). The module symlinks leak
the vendor build path (`…/Archer_BE220_v1.0/…_Secure_Release_…/bcm504L04/bcm963xx_5.04L.04/…`).

---

## 6. File-level diff (de-noised)

A raw `diff -rq` of the two roots flags **almost every** ELF and `.control` file — that's
recompilation noise (build IDs, timestamps, the Jenkins path), **not** real change. The
signal is tiny:

```bash
R135=$(find extract_135 -type d -name squashfs-root | head -1)
R137=$(find extract_137 -type d -name squashfs-root | head -1)
diff <(cd "$R135" && find . | sort) <(cd "$R137" && find . | sort)   # added/removed
diff -rq "$R135" "$R137"                                             # changed
# then read the TEXT changes directly:
for f in etc/init.d/uhttpd etc/iplatform.config etc/partition_config/soft-version \
         www/webpages/app.manifest ; do diff -u "$R135/$f" "$R137/$f"; done
```

**The one added file:** `usr/lib/lua/luci/controller/admin/cert_mgmt.lua` (the +1 inode).

To tell which *binaries* really changed (vs. just recompiled), compare sorted strings
or use `radiff2 -s`; most show only the build-path string differing (e.g. `libcrypto.so.3`
is byte-for-byte the same code).

---

## 7. Decompile the LuCI controllers

TP-Link ships LuCI controllers as Lua 5.1 bytecode that is (a) **opcode-shuffled** and
(b) **LNUM-patched** (integer constant tag `9`). Stock decompilers choke on both. The
pipeline:

**7a. Recover the opcode permutation from the device's own VM:**

```bash
LIB=$(find "$R137" -name 'liblua.so*' | head -1)        # liblua.so.5.1.4 (ARM, stripped)
python3 tplink_lua_opmap.py from-lib "$LIB" > tp_opnames.txt
```

This reads `luaP_opnames` out of `liblua.so` (handling GCC string suffix-merging and
PIC relocations) and prints the 38 opcodes in TP-Link's order. **Verify the shuffle is
the same for the version you're diffing** — extract it from each firmware's own
`liblua.so` (for 1.3.5 vs 1.3.7 here, they matched).

**7b. Normalize bytecode → stock Lua 5.1:**

```bash
python3 tplink_lua_unshuffle.py --opnames tp_opnames.txt \
  "$R137/usr/lib/lua/luci/controller/admin/vpn.lua" vpn.stock.luac
```

`tplink_lua_unshuffle.py` does three things in one pass: remaps each instruction's
opcode field to canonical numbering; converts LNUM integer constants (tag 9) to stock
`LUA_TNUMBER`; and **retargets** the chunk to a canonical 64-bit header
(`int4/size_t8/num8`, little-endian) so a decompiler built on x86-64 accepts the
ARM-origin (`size_t=4`) bytecode instead of rejecting it with "bad header."

**7c. Decompile:**

```bash
./luadec-x86_64 vpn.stock.luac > vpn.lua.src
```

(To rebuild luadec yourself: `github.com/viruscamp/luadec` →
`git submodule update --init lua-5.1 && (cd lua-5.1 && make linux) && (cd luadec && make LUAVER=5.1)`.)

luadec emits readable source plus many `cannot find blockend` / `DECOMPILER ERROR`
warnings on stderr — those are its control-flow/local-variable **guesser** being
imperfect, not corruption. Logic, strings and structure come through. For an exact
instruction-level view that hides nothing, use `./luadec-x86_64 -dis file.stock.luac`.

---

## 8. Findings — what actually changed, 1.3.5 → 1.3.7

### 8.1 New feature: certificate management (the "improved security" item)

- **New endpoint** `cert_mgmt.lua` registers `admin/cert_mgmt`, which serves
  `/etc/cacert.pem` as a download (`Content-Disposition: attachment; filename="cacert-<date>.crt"`).
- **`etc/init.d/uhttpd`** now:
  - generates the CA with **`-days 3650`** (10-year validity),
  - **persists** the CA: `cp $CA_PATH/cacert.pem /etc`,
  - **bundles `cacert.pem`** alongside `uhttpd.crt`/`uhttpd.key` into the NVRAM-stored,
    AES-256-CBC-encrypted `https_cert` blob (`nvrammanager -w … -p https_cert`).

Net effect: the router now builds a proper **CA → device-cert chain**, persists the CA
across reboots/upgrades, and lets the user install it in their browser for a trusted
admin-UI HTTPS session. This is the user-facing "improved overall security" change.

### 8.2 Minor changes

- **`etc/iplatform.config`** — new OTA component `TMP_COMP_CLIENT_INFO_MANAGE=y`
  (type `0x0030`, v1), persisting the **VPN-client device-assignment** config. Its
  admin handler is `set_clientinfo` in `access_control.lua` (§8.3). The frontend store
  `www/webpages/js/vpnDevice-*.js` (Pinia store `vpnDevice`) reads/writes
  `clientInfo = { mode, serverDes, serverKey }` via `updateClientInfo` → `set_clientinfo`:
  whether the VPN client applies to **all** clients or a **custom** per-device set, and
  which VPN server. The `deviceList`/`deviceMaxNum` are the selectable clients and the
  custom-entry cap; `macaddr` validates the per-device MACs. (It lives in
  `access_control.lua` because device selection reuses the access-control client
  enumeration.)
- **`nvrammanager`** — 98.9% identical; one new string (`common type not support to upgrade!`),
  almost certainly handling the new `0x0030` component type.
- **`dropbear`** — adds `kexguess2@matt.ucc.asn.au` (an SSH KEX bump).
- **`etc/init.d/wireless`** — adds `echo 3 > /proc/sys/vm/drop_caches` at wifi start
  (a memory-pressure workaround before the large `wl.ko` loads).
- **`soft-version`** / `app.manifest` — version + asset-build stamps.

### 8.3 Instruction-level delta in the two controllers

No function was added, removed, or rewritten in either controller — the set of
registered global functions (`SETGLOBAL` names in the `-dis` disassembly) is identical
across versions. The small bytecode growth (vpn 16071 → 16109; access_control
3867 → 3895) is a few **additive, string-level** changes, isolated by diffing the
cascade-immune constant pool (`grep -oE '"[^"]+"' …`) rather than the renumbered
instruction stream:

**`access_control.lua`** — one new admin operation:
- new dispatch key **`"set_clientinfo"`**, with a **`"macaddr"`** validator and an
  **`"invalid params"`** error. This is the write-path of the new
  `TMP_COMP_CLIENT_INFO_MANAGE` component (§8.2) — the **VPN-client device-assignment**
  setter (apply-to-all vs custom-per-MAC, + server selection), confirmed from the
  frontend store `vpnDevice-*.js`. No new field strings were introduced because it
  reuses the existing client-record vocabulary; luadec drops the handler body (the
  `undefined locals` warning), so read it from the `-dis` disassembly, not the
  decompiled source.

**`vpn.lua`** — input-validation tightening + one temp file:
- a field validator changed from **`"safestring"` → `"alphanumeric_str"`** (allowed
  extra chars **`"-_"`**),
- added temp file **`"/tmp/thirdvpn_purevpn_login.data"`** (PureVPN login flow).

Neither touches the existing VPN connection logic or the black/white-list matching.
The ~38 / ~28 extra instructions are entirely accounted for by these additions.

> Method note: a raw `-dis` diff *cascades* — inserting one instruction renumbers every
> downstream register, jump target and constant index — so always diff the string pool
> and the `SETGLOBAL` name set to isolate real changes.

### 8.4 What did NOT change

- **`libcrypto.so.3` / OpenSSL** — only the embedded build path differs; code unchanged.
- The ~700 other "differing" files are recompilation artifacts.

---

## 9. Security-research notes (present in BOTH versions — not 1.3.7 regressions)

From the decompiled `vpn.lua` (a multi-vendor commercial-VPN client — Surfshark,
NordVPN, IPVanish, PureVPN, plus manual OpenVPN/WireGuard/PPTP/L2TP):

- **Hardcoded third-party integration constants** baked into firmware: an IPVanish
  login API key (32-hex), a PureVPN client ID (UUID), Surfshark/IPVanish CA certs, and
  a shared OpenVPN `tls-auth` static key. These are app-level integration material, not
  user credentials — but a device-wide shared `tls-auth` key weakens that control.
- **Command-construction surface.** The controller builds shell strings from config and
  runs them with `os.execute`, e.g.
  `string.format("/lib/vpn/vpn_core.sh stop %s %s %s %s %s %s", ruleindex, mark, key, type, endpoint_port, nat)`.
  Worth auditing whether any interpolated field can carry shell metacharacters and
  whether the `checktypes`/`check` tables validate them before this point.

These are standing properties to audit, not changes introduced in 1.3.7.

---

## 10. Reproduction checklist

1. Install deps (§1); download firmware `.zip`s + the GPL tarball (§2).
2. Build `tp-link-decrypt`, run `extract_keys.sh` + `make` (§3).
3. Decrypt both images → `.dec` (§3).
4. Run `compare_tplink_headers.py` to confirm structure (§4).
5. `binwalk -e` both `.dec` → `squashfs-root` (§5).
6. De-noised `diff -rq` + text diffs → find `cert_mgmt.lua` + the config/init changes (§6).
7. `tplink_lua_opmap.py` per firmware → `tplink_lua_unshuffle.py` → `luadec-x86_64` (§7).
8. Diff decompiled controllers across versions (§8.3).

---

## 11. Caveats

- Keys and decryption rely on **vendor-published GPL/firmware material**; this is
  interoperability/security research on firmware for devices you own.
- The opcode shuffle and LNUM width are recovered empirically per image; re-verify them
  when moving to a different firmware family (`opmap` warns if the order looks stock;
  `unshuffle` auto-calibrates the LNUM integer width to a clean EOF parse).
- luadec output is lossy in spots; trust `-dis` for exact instruction-level questions.
- Verdicts like "consistent with encryption" from the entropy tool are heuristics —
  magic-byte hits are fact, chi-square is a lead.
