# 荣耀X10（TEL-AN10）— 华为/荣耀「2% 模式」USB 线刷协议（逆向分析）

> 对华为 / 荣耀设备 **USB 升级模式（2% 模式，又称 DLOAD）** 通信协议的逆向工程。
>
> 实测机型：**荣耀X10 — TEL-AN10**（麒麟 820），系统 **HarmonyOS 2.0.0.270**。
>
> ⭐ **握手已在真实硬件上实现并验证成功** —— 通过 `DBAdapter Reserved Interface`（USB CDC / COM 口）通信。
>
> ⚠️ **本仓库是研究文档，不是可用的降级工具。** 降级已被密码学机制封堵（见「为什么降级走不通」）。

[English version → README-EN.md](README-EN.md)

---

## 一句话结论

| 目标 | 结果 |
|---|---|
| 鸿蒙 2 降级回 EMUI / MagicUI | ❌ **走不通**（服务器授权签名 + 版本校验，RSA 保护） |
| 逆向 2% 模式协议 | ✅ **已完成** —— 命令集、帧格式、包头结构全部解码 |
| COM 口握手通信 | ✅ **已确认** —— 设备正确响应（7 字节） |
| 完整固件传输 | ❌ 未完成（包头被拒，见「局限」） |

---

## 测试设备

```
型号        荣耀X10 — TEL-AN10（国行 C00）
SoC         麒麟 820（kirin820）
出厂系统    MagicUI 3.1.1 / EMUI 10.1.1
当前系统    HarmonyOS 2.0.0.270（TEL-AN10 2.0.0.270(C00E230R7P5)）
Android 基座 10
Bootloader  FB LockState: LOCKED / USER LockState: LOCKED
```

> 设备序列号、主机路径均已**脱敏**处理。

---

## 我们搞清楚了什么

### 1. 传输层

```
通道   DBAdapter Reserved Interface（USB CDC / COM 口）
波特率 9600（USB CDC 下速率由 USB 决定）
帧格式 HDLC
        0x7E + 转义(载荷 + CRC16-X25 小端) + 0x7E
转义    0x7E → 0x7D 0x5E
        0x7D → 0x7D 0x5D
        （即：输出 0x7D，再输出 原字节 XOR 0x20）
```

证据来自 `send_package` @ `0x3F536C`：
```asm
mov  w13, #0x7d        ; 转义符
sub  w14, w15, #0x7d
cmp  w14, #1           ; 字节 == 0x7D 或 0x7E
eor  w15, w15, #0x20   ; 字节 ^= 0x20
strb w13, ...          ; 写 0x7D
strb w15, ...          ; 写转义后字节
```

### 2. 握手 —— ⭐ 最关键的修正

**命令字错误是早期所有尝试失败的最大根源。**

```
错误（老协议 / 5% 模式）：  0x0026  → 字节 26 00
正确（新协议 / 2% 模式）：  0x0226  → 字节 26 02
                                             ^^ 仅一字节之差

魔数：     0x0600A725，位于载荷【偏移 2】（不是偏移 3）
```

来自 `handshake_cmd` @ `0x3EC860`：
```asm
ldrb w22, [x19]        ; pkt[0]
ldrb w26, [x19, #1]    ; pkt[1]
ldur w23, [x19, #2]    ; 魔数在偏移 2
bfi  w22, w26, #8, #8  ; cmd = pkt[0] | (pkt[1] << 8)
cmp  w23, 0x0600A725   ; 魔数校验
cmp  w22, #0x226       ; 只接受 0x0226
```

**正确的握手帧（22 字节）：**
```
7E 26 02 25 A7 00 06 00 00 00 00 00 00 00 00 00 00 00 01 43 8E 7E
   ^cmd=0x0226
      ^魔数=0x0600A725（小端）
                                                ^pkt[16] ^pkt[17]
```

**设备响应（7 字节）：** `7E 03 00 07 17 5D 7E` ✅

> 用 `0x0026` 会返回 **137 字节的错误响应**，早期曾被误判为「握手成功」。

### 3. 命令分发表

分发表基址：`0x11B9568`（按命令字节索引，运行时填充）
初始化代码：`0x411444 – 0x411500`

来自 `process_data_thread` @ `0x410218`：
```asm
adrp x8, #0x11b9000
add  x8, x8, #0x568           ; 0x11B9568
ldr  x8, [x8, x5, lsl #3]     ; handler = 表[命令字节]
cbz  x8, ...                  ; 为空 → 丢弃
add  x0, x23, #1              ; 参数0 = 载荷（cmd+1）
sub  w1, w9, #1               ; 参数1 = 长度-1
blr  x8                       ; 调用 handler(载荷, 长度, 命令)
```

| 命令 | Handler | 作用 |
|---|---|---|
| `0x0F` | `new_write_cmd` (0x410C6C) | **数据** |
| `0x26` | `new_process_shake_hand_cmd` (0x410DFC) | **握手** |
| `0x41` | `new_write_begin_cmd` (0x410E5C) | **包头 / 写开始** |
| `0x43` | (0x411018) | 写结束 |
| `0x44` | (0x4111AC) | 处理 |
| `0x45` | `new_process_update_auth_cmd` (0x411208) | 授权 |
| `0x46` | `transmit_write_begin_cmd` | 写控制 |
| `0x48` | `transmit_write_post_cmd` | 写控制 |
| `0x4C` | `get_total_pkg_size_cmd` (0x410AC0) | 包总大小 |

与 `process_data_thread` 中的检查完全吻合：
```asm
cmp w5, #0x41
cmp w5, #0x43
cmp w5, #0x44
```

### 4. 包头 `module_head`（100 字节）

由 `cmd_unit_write_begin_func` @ `0x3ECB60` 解析。

```c
struct module_head {
    /* 0x00 */ uint32_t dwMagicNum;      // 0xA55AAA55（字节 55 AA 5A A5）
    /* 0x04 */ uint32_t dwHeadLen;       // 包头实际长度（★ 各模块不同！）
    /* 0x08 */ uint32_t dwVersion;       // 1
    /* 0x0C */ char     hw[8];           // "HW7x27\xFF\xFF"
    /* 0x14 */ uint32_t dwDataStartAddr; // 起始地址 / 偏移
    /* 0x18 */ uint32_t dwDataLen;       // 数据长度
    /* 0x1C */ char     date[16];        // "2021.08.27"
    /* 0x2C */ char     time[16];        // "14.21.49"
    /* 0x3C */ char     module_name[];   // 模块名
    /* 0x5E */ uint16_t dwBlockSize;     // 大端，恒为 0x0010
    /* 0x60 */ uint16_t dwBlockSize_hw;  // 大端，0x0000
};
```

**`dwHeadLen` 并非固定 100。** 已用从 `UPDATE.APP` dump 出的 11 个真实包头验证：

| 模块名 | dataLen | startAddr | headLen |
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

结构验证：`SHA256RSA` 包头 100 + 数据 900 = 1000 → 下一个魔数正好在 `0x5C + 1000 = 0x444` ✅

### 5. 数据帧

```
载荷[0..3] = 地址 / 偏移（uint32，大端）
载荷[4..7] = 数据长度（uint32，大端）
载荷[8..]  = zlib 压缩数据
```

来自 `new_write_cmd` @ `0x410C6C`：
```asm
sub  w8, w1, #0xa        ; 压缩数据长度 = len - 10
add  x2, x0, #8          ; 压缩数据起始 = 载荷 + 8
str  x9, [sp]            ; 解压输出上限 0x400000（4 MB）
bl   uncompress
bl   write_cmd
```

### 6. 94 个合法模块名

来源：`data_partition_process_table` @ `0x529330`（12784 字节）。

值得注意的：`OTA_ZIP`、`OTA_ZIP_APP`、`USERDATA_ZIP`（承载 zip 的模块），
以及 `BASE_VER`、`BASE_VERLIST`、`PACKAGE_TYPE`、`CUST`、`PRELOAD`、`SYSTEM`、
`VENDOR`、`XLOADER`、`FASTBOOT`、`CRC`、`HISIUFS_GPT`、`PTABLE_*`。

---

## 为什么降级走不通

版本号存在于 **RSA 签名**的 `PTABLE.APP` / `UPDATE.APP` 中。
伪造它需要 **华为的私钥** —— 数学上不可能。

已验证的失败点：

| 尝试 | 结果 |
|---|---|
| HiSuite 官方回退 | ❌ 该机型回退通道已关闭 |
| HiSuite Proxy + 自定义固件 | ⚠️ 能注入、能下载，卡在**服务器授权签名** |
| 三键 SD 卡刷 | ❌ `升级包版本号信息校验失败` |
| 改包里的版本列表 | ❌ 破坏 RSA 签名 |
| 「高维禁用」包 | ❌ 只解除**用服中心限制**，**不解除版本校验** |
| 5% 模式（免解锁 BL） | ⚠️ 原理可行，但工具只支持麒麟 ≤970，**820 不在内** |
| 解锁 BL | ❌ 需**拆机短接 / ISP 飞线** |

---

## 本研究的局限

- 包头（`0x41`）**始终被拒** —— ACK `0x08`。
  日志：`module_head.dwDataLen too large`（声明长度超过分区实际大小）。
- **每个会话只有第一次包头尝试有效**；之后返回 ACK `0x0D`（状态锁死）。
- 完整 4 GB 传输**未完成**。
- 缺 CUST / PRELOAD 包（只拿到 BASE，且三份拷贝完全相同）。

---

## 仓库结构

```
README.md               本文件（中文）
README-EN.md            英文版
01-总览与结论.md         完整技术总结（中文）
02-实测记录.md           按时间的实测流水
03-反汇编与符号/         反汇编输出 + 符号表
05-脚本与工具/           所用 Python 脚本
06-日志/                 原始 USB / 串口日志
07-历史文档/             早期笔记
LICENSE                 MIT
```

### 复现方式

```bash
pip install pyserial pyelftools capstone

python 05-脚本与工具/hs_new_test.py     # 验证握手（0x0226）→ 期望 7 字节响应
```

设备需处于升级模式，且电脑识别到 `DBAdapter Reserved Interface (COMx)`。
⚠️ 若你的 `adb server` 占用 5037 端口，HiSuite 会检测不到手机 —— 执行 `adb kill-server` 即可恢复。

---

## 法律与安全声明

- 本项目为**独立的逆向工程研究**，用于学习与互操作性目的。
- **不包含任何华为 / 荣耀专有二进制文件。** 文中提及的固件仅标注版本与来源，请自行从官方渠道获取。
- 刷机会**清空全部数据**，请自行承担风险。
- **本项目不绕过任何安全机制** —— 文中描述的版本校验仍受厂商签名的密码学保护。

## 许可证

MIT —— 见 `LICENSE`。
