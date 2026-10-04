# Honor X10 (TEL-AN10) — Huawei/Honor "2pct mode" USB Flashing Protocol (Reverse Engineering)

Reverse engineering of the **USB upgrade / "2pct mode" (DLOAD)** protocol used by Huawei / Honor
devices, performed on an **Honor X10 — TEL-AN10** (Kirin 820) running **HarmonyOS 2.0.0.270**.

The **handshake was implemented and confirmed working against real hardware** over
`DBAdapter Reserved Interface` (USB CDC / COM port).

> ⚠️ **This repository is research documentation, NOT a working downgrade tool.**
> Downgrading is blocked cryptographically (see "Why downgrade fails").

---

## TL;DR

| Goal | Result |
|---|---|
| Downgrade HarmonyOS 2 → EMUI / MagicUI | ❌ **Blocked** (server auth signature + version check, RSA-protected) |
| Reverse the 2pct mode protocol | ✅ **Done** — command set, frame format, package header decoded |
| Working handshake over COM port | ✅ **Confirmed** — device replies correctly (7-byte response) |
| Full firmware transfer | ❌ Not completed (package header rejected — see Limitations) |

---

## Device under test

```
Model        Honor X10 — TEL-AN10 (China, C00)
SoC          Kirin 820 (kirin820)
Shipped with MagicUI 3.1.1 / EMUI 10.1.1
Current      HarmonyOS 2.0.0.270 (TEL-AN10 2.0.0.270(C00E230R7P5))
Android base 10
Bootloader   FB LockState: LOCKED / USER LockState: LOCKED
```

Serial number and host-specific paths have been **redacted** from all files.

---

## What we figured out

### 1. Transport

```
Channel   DBAdapter Reserved Interface (USB CDC / COM port)
Baud      9600 (rate irrelevant for USB CDC)
Framing   HDLC
          0x7E + escape(payload + CRC16-X25 LE) + 0x7E
Escaping  0x7E -> 0x7D 0x5E
          0x7D -> 0x7D 0x5D
          (i.e. emit 0x7D, then byte XOR 0x20)
```

Confirmed from `send_package` @ `0x3F536C`:
```asm
mov  w13, #0x7d        ; escape char
sub  w14, w15, #0x7d
cmp  w14, #1           ; byte == 0x7D or 0x7E
eor  w15, w15, #0x20   ; byte ^= 0x20
strb w13, ...          ; write 0x7D
strb w15, ...          ; write escaped byte
```

### 2. Handshake — ⭐ the key correction

**The command word was the single biggest mistake in earlier attempts.**

```
WRONG (old / 5% mode):  0x0026   -> bytes 26 00
RIGHT (new / 2pct mode):  0x0226   -> bytes 26 02
                                            ^^ one byte difference

Magic:     0x0600A725, located at payload offset 2 (NOT offset 3)
```

From `handshake_cmd` @ `0x3EC860`:
```asm
ldrb w22, [x19]        ; pkt[0]
ldrb w26, [x19, #1]    ; pkt[1]
ldur w23, [x19, #2]    ; magic at offset 2
bfi  w22, w26, #8, #8  ; cmd = pkt[0] | (pkt[1] << 8)
cmp  w23, 0x0600A725   ; magic check
cmp  w22, #0x226       ; accepts ONLY 0x0226
```

**Correct handshake frame (22 bytes):**
```
7E 26 02 25 A7 00 06 00 00 00 00 00 00 00 00 00 00 00 01 43 8E 7E
   ^cmd=0x0226
      ^magic=0x0600A725 (LE)
                                                ^pkt[16] ^pkt[17]
```

**Device replies (7 bytes):** `7E 03 00 07 17 5D 7E` ✅

> Using `0x0026` returns a **137-byte error response** which was originally
> misread as "handshake succeeded".

### 3. Command dispatch table

Dispatch table base: `0x11B9568` (indexed by command byte, populated at runtime).
Initializer: `0x411444 – 0x411500`.

From `process_data_thread` @ `0x410218`:
```asm
adrp x8, #0x11b9000
add  x8, x8, #0x568           ; 0x11B9568
ldr  x8, [x8, x5, lsl #3]     ; handler = table[cmd_byte]
cbz  x8, ...                  ; null -> discard
add  x0, x23, #1              ; arg0 = payload (cmd+1)
sub  w1, w9, #1               ; arg1 = length-1
blr  x8                       ; call handler(payload, len, cmd)
```

| Command | Handler | Purpose |
|---|---|---|
| `0x0F` | `new_write_cmd` (0x410C6C) | **data** |
| `0x26` | `new_process_shake_hand_cmd` (0x410DFC) | **handshake** |
| `0x41` | `new_write_begin_cmd` (0x410E5C) | **package header / begin write** |
| `0x43` | (0x411018) | write end |
| `0x44` | (0x4111AC) | process |
| `0x45` | `new_process_update_auth_cmd` (0x411208) | auth |
| `0x46` | `transmit_write_begin_cmd` | write control |
| `0x48` | `transmit_write_post_cmd` | write control |
| `0x4C` | `get_total_pkg_size_cmd` (0x410AC0) | total package size |

This matches the checks in `process_data_thread`:
```asm
cmp w5, #0x41
cmp w5, #0x43
cmp w5, #0x44
```

### 4. Package header — `module_head` (100 bytes)

Parsed by `cmd_unit_write_begin_func` @ `0x3ECB60`.

```c
struct module_head {
    /* 0x00 */ uint32_t dwMagicNum;      // 0xA55AAA55  (bytes 55 AA 5A A5)
    /* 0x04 */ uint32_t dwHeadLen;       // actual header length (VARIES per module!)
    /* 0x08 */ uint32_t dwVersion;       // 1
    /* 0x0C */ char     hw[8];           // "HW7x27\xFF\xFF"
    /* 0x14 */ uint32_t dwDataStartAddr; // start address / offset
    /* 0x18 */ uint32_t dwDataLen;       // data length
    /* 0x1C */ char     date[16];        // "2021.08.27"
    /* 0x2C */ char     time[16];        // "14.21.49"
    /* 0x3C */ char     module_name[];   // module name
    /* 0x5E */ uint16_t dwBlockSize;     // big-endian, always 0x0010
    /* 0x60 */ uint16_t dwBlockSize_hw;  // big-endian, 0x0000
};
```

**`dwHeadLen` is NOT fixed at 100.** Verified against 11 real headers dumped from `UPDATE.APP`:

| Module | dataLen | startAddr | headLen |
|---|---|---|---|
| SHA256RSA | 0x00000384 | 0xFE000000 | 100 |
| CRC | 0x0004BED0 | 0xFE000000 | 250 |
| BASE_VERLIST | 0x00000760 | 0xFFFFFFF1 | 100 |
| BASE_VER | 0x00000018 | 0xFFFFFFF0 | 100 |
| PACKAGE_TYPE | 0x0000005F | 0xFFFFFFF2 | 100 |
| HISIUFS_GPT | 0x00035400 | 0x00000000 | 206 |
| XLOADER | 0x0003E000 | 0x00000018 | 222 |
| FASTBOOT | 0x002FFF80 | 0x00000013 | 1634 |
| BL2 | 0x00063300 | 0x00000013 | 298 |
| BOOT | 0x01E00000 | 0x0000000C | 15458 |
| DTBO | 0x009D8280 | 0x0000000C | 5140 |

Layout verification:
`SHA256RSA` header 100 + data 900 = 1000 → next magic at `0x5C + 1000 = 0x444` ✅

### 5. Data frame

```
payload[0..3] = address/offset (uint32, BIG endian)
payload[4..7] = data length    (uint32, BIG endian)
payload[8..]  = zlib-compressed data
```

From `new_write_cmd` @ `0x410C6C`:
```asm
sub  w8, w1, #0xa        ; compressed length = len - 10
add  x2, x0, #8          ; compressed data starts at payload+8
str  x9, [sp]            ; uncompress output limit 0x400000 (4 MB)
bl   uncompress
bl   write_cmd
```

### 6. 94 valid module names

Extracted from `data_partition_process_table` @ `0x529330` (12784 bytes).

Notable: `OTA_ZIP`, `OTA_ZIP_APP`, `USERDATA_ZIP` (modules that carry a zip),
plus `BASE_VER`, `BASE_VERLIST`, `PACKAGE_TYPE`, `CUST`, `PRELOAD`, `SYSTEM`,
`VENDOR`, `XLOADER`, `FASTBOOT`, `CRC`, `HISIUFS_GPT`, `PTABLE_*`.

---

## Why downgrade fails

The version number lives in **RSA-signed** `PTABLE.APP` / `UPDATE.APP`.
Forging it requires **Huawei's private key** — mathematically impossible.

Verified failure points:

| Attempt | Result |
|---|---|
| HiSuite official rollback | ❌ Channel closed for this model |
| HiSuite Proxy + custom firmware | ⚠️ Injects & downloads, then blocked by **server auth signature** |
| 3-button SD-card flash | ❌ `升级包版本号信息校验失败` (version check) |
| Edited version list in package | ❌ Breaks RSA signature |
| "高维禁用" (High-Level Repair Center) package | ❌ Removes service-center restriction **only**, not version check |
| 5% mode (no BL unlock) | ⚠️ Feasible in principle, but tools support Kirin ≤970 — **820 not included** |
| Unlock BL | ❌ Requires **teardown / ISP** |

---

## Limitations of this work

- Package header (`0x41`) was **always rejected** — ACK `0x08`.
  Log: `module_head.dwDataLen too large` — declared length exceeded partition size.
- **Only the first header attempt per session is meaningful**; subsequent ones return ACK `0x0D` (state locked).
- Full 4 GB transfer **not completed**.
- No CUST / PRELOAD packages available (only BASE was obtained; three copies were identical).

---

## Repository layout

```
README.md                  this file
README-先读我.md            Chinese overview
01-总览与结论.md            full Chinese technical write-up
02-实测记录.md              chronological test log
03-反汇编与符号/            disassembly output + symbol tables
05-脚本与工具/              Python scripts used
06-日志/                    raw USB / serial logs
07-历史文档/                earlier notes
```

### Reproducing

```bash
pip install pyserial pyelftools capstone

python 05-脚本与工具/hs_new_test.py     # verify handshake (0x0226) -> expect 7-byte reply
```

Device must be in upgrade mode with `DBAdapter Reserved Interface (COMx)` present.
⚠️ If your `adb server` holds port 5037, HiSuite cannot detect the phone — `adb kill-server` fixes it.

---

## Legal / safety

- This is **independent reverse engineering for research and interoperability**.
- **No Huawei/Honor proprietary binaries are included.** All binaries referenced are identified by
  version and origin only; download them from official sources yourself.
- Flashing will **erase all data**. You do this at your own risk.
- Nothing here bypasses any security mechanism — the version check remains cryptographically enforced.

## License

MIT — see `LICENSE`.
