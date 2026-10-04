# 荣耀X10 降级研究 · 成果包（先读我）

> 设备：荣耀X10 **TEL-AN10**（S/N `XXXXXXXXXXXXXXXXX`）
> SoC：麒麟 **820**（kirin820）
> 当前系统：**HarmonyOS 2.0.0.270**（`TEL-AN10 2.0.0.270(C00E230R7P5)`，Android 10 基座）
> BL 状态：`FB LockState: LOCKED`、`USER LockState: LOCKED`
> 研究时间：2026-10-03 ~ 2026-10-04（一整晚）

---

## 0. 一句话结论

**降级本身（鸿蒙2 → EMUI/MagicUI）已被华为的服务器授权签名 + 版本校验封堵，公开渠道走不通。**

**但这一晚我们做成了另一件更有价值的事：把荣耀/华为「2% 模式（USB 线刷升级模式）」的通信协议逆向出来了，并且实测握手成功。**

这份包里装的是**协议逆向的证据、脚本和已知边界**，不是"一键降级工具"。

---

## 1. 这个包里有什么

| 目录 | 内容 | 说明 |
|---|---|---|
| `README-先读我.md` | 本文件 | 总览 + 结论 + 安全边界 |
| `01-总览与结论.md` | 完整技术总结 | **最值得看**，含协议全貌、命令表、包头结构 |
| `02-实测记录.md` | 一整晚的实测流水 | 每一步做了什么、设备回了什么 |
| `03-反汇编与符号/` | 反汇编结果 + 符号表 | 协议逆向的原始证据 |
| `05-脚本与工具/` | 所有 Python 脚本 | 可复现、可继续研究 |
| `06-日志/` | USB/串口监控日志 | 实测原始数据 |
| `07-历史文档/` | 之前写的旧文档 | 避雷指南、操作手册等 |

---

## 2. 核心成果（协议逆向）

### 2.1 传输层已确认

```
通道：DBAdapter Reserved Interface（COM 口）
波特率：9600（USB CDC，实际速率由 USB 决定）
帧格式：HDLC
    0x7E + 转义(载荷 + CRC16-X25) + 0x7E
转义规则：
    字节 == 0x7E → 输出 0x7D 0x5E
    字节 == 0x7D → 输出 0x7D 0x5D
    （即：0x7D 后跟 原字节 XOR 0x20）
```

### 2.2 握手协议（★ 已实测成功）

**这是整晚最大的修正：之前用的命令字是错的。**

```
错误（老协议/5%模式）：  0x0026  → 字节 26 00
正确（新协议/2%模式）：  0x0226  → 字节 26 02
                                        ↑ 这一个字节的差别
魔数：0x0600A725，在载荷【偏移 2】（不是偏移 3）
```

**握手帧（22 字节）：**
```
7E 26 02 25 A7 00 06 00×10 00 01 <CRC> 7E
   └cmd=0x0226
      └magic=0x0600A725(LE)
                        └pkt[16] └pkt[17]
```

**设备正确响应（7 字节）：** `7E 03 00 07 17 5D 7E`
（而错误的 0x0026 会得到 137 字节的**错误响应**，曾被误判为"握手成功"）

### 2.3 命令分发表（从二进制里解码出来）

分发表基址：`0x11B9568`（按命令字节索引，运行时填充）
初始化代码：`0x411444 ~ 0x411500`

| 命令字节 | Handler | 作用 |
|---|---|---|
| `0x0F` | `new_write_cmd` | **数据** |
| `0x26` | `new_process_shake_hand_cmd` | **握手** |
| `0x41` | `new_write_begin_cmd` | **包头（写开始）** |
| `0x43` | `0x411018` | 写结束 |
| `0x44` | `0x4111AC` | 处理 |
| `0x45` | `new_process_update_auth_cmd` | 授权 |
| `0x46` | `transmit_write_begin_cmd` | 写控制 |
| `0x48` | `transmit_write_post_cmd` | 写控制 |
| `0x4C` | `get_total_pkg_size_cmd` | 包总大小 |

> 与 `process_data_thread` 里 `cmp 0x41 / 0x43 / 0x44` 的检查完全吻合。

### 2.4 包头结构 `module_head`（100 字节，字段偏移已验证）

```c
struct module_head {
    /* 0x00 */ uint32_t dwMagicNum;      // 0xA55AAA55（字节 55 AA 5A A5）
    /* 0x04 */ uint32_t dwHeadLen;       // 包头实际长度（实测各模块不同：100/206/222/298/1634/15458/5140…）
    /* 0x08 */ uint32_t dwVersion;       // 1
    /* 0x0C */ char     hw[8];           // "HW7x27\xFF\xFF"
    /* 0x14 */ uint32_t dwDataStartAddr; // 起始地址/偏移
    /* 0x18 */ uint32_t dwDataLen;       // 数据长度
    /* 0x1C */ char     date[16];        // "2021.08.27"
    /* 0x2C */ char     time[16];        // "14.21.49"
    /* 0x3C */ char     module_name[];   // ★ 模块名
    /* 0x5E */ uint16_t dwBlockSize;     // 大端，实测恒 0x0010
    /* 0x60 */ uint16_t dwBlockSize_hw;  // 大端，0x0000
};
```

**验证方式：** 从 `C:\dload_build\dload\UPDATE.APP` 里 dump 出 11 个真实包头，逐字段比对。
结构确认为 `[包头 headLen 字节][数据 dataLen 字节]`：
`SHA256RSA` 包头 100 + 数据 0x384(900) = 1000 → 下一个魔数正好在 `0x5C+1000 = 0x444` ✓

### 2.5 数据帧格式

```
载荷[0..3]  = 地址/偏移（32位 大端）
载荷[4..7]  = 数据长度（32位 大端）
载荷[8..]   = zlib 压缩数据
```
> 与老协议 `usbdload.py` 的 `data_cmd()` 格式一致。
> 设备端 `new_write_cmd` 会 `uncompress()`，解压输出上限 `0x400000`(4MB)。

### 2.6 94 个合法模块名（从 `data_partition_process_table` @ `0x529330` 提取）

含 `OTA_ZIP` / `OTA_ZIP_APP` / `USERDATA_ZIP`（承载 zip 的模块）
以及 `BASE_VER` `BASE_VERLIST` `PACKAGE_TYPE` `CUST` `PRELOAD` `SYSTEM` `VENDOR` `XLOADER` `FASTBOOT` `CRC` `HISIUFS_GPT` 等。

---

## 3. 已知的失败边界（很重要，别重复踩）

| 环节 | 结果 | 原因 |
|---|---|---|
| 包头 `0x41` | 被拒（ACK 码 `0x08`） | `dwDataLen(4GB) > 分区实际大小`，设备报 `module_head.dwDataLen too large` |
| 同一会话第 2 次包头 | ACK 码 `0x0D` | 状态锁死，**每个会话只有第一次包头尝试有效** |
| HiSuite Proxy + HiSuite 14 | `Patch failed` | 代理不认识 14 版 |
| HiSuite Proxy + 11.0.0.650 | 提示"需要更老版本" | 代理要求更老（社区文章指向 `11.0.0.630_OVE`） |
| 代理配置后 HiSuite | 仍显示"升级鸿蒙3" | 代理**只记录了请求但未替换响应**（日志里 `query.hicloud.com` 仍返回真实结果） |

---

## 4. 安全边界（读这段再决定要不要动手）

```
✅ 已确认安全：
   · 所有协议探测均未向手机写入任何数据
   · 4 次不同固件尝试，设备都是"安全拒绝"，手机始终正常
   · 手机至今仍在鸿蒙 2.0.0.270，未被改动

⚠️ 未验证的风险：
   · 未跑通过完整 4GB 传输
   · 未验证过签名/版本校验能否绕过（证据表明：不能）
   · 真刷会清空全部数据
```

**这台手机降级失败的根因是密码学级别的（华为私钥签名），不是技术问题。**

---

## 5. 建议的下一步（按性价比）

1. **🥇 容器方案装 GMS**（GBox / OurPlay）—— 零风险，今晚就能用，不降级
2. **🥈 售后/维修店**—— 他们有支持麒麟 820 的商业线刷工具（如西格玛/SFFT）+ 授权签名文件
3. **🥉 继续研究本协议**—— 包里的脚本可复现；但需先解决"包头被拒"和"签名校验"

---

## 6. 复现方式

```powershell
# 依赖
pip install pyserial pyelftools capstone

# 关键脚本（均在 05-脚本与工具/）
python hs_new_test.py          # 验证新协议握手（0x0226）→ 应返回 7 字节
python autotest_single.py <模块名> <startAddr> <dataLen>   # 单次包头尝试
python flash.py <包文件> [模块名]                          # 完整流程（实验性）
```

> **注意**：手机需进入「升级模式」→「USB升级模式」，且电脑识别到
> `DBAdapter Reserved Interface (COMx)`。
> 若 adb server 占用 5037 端口会导致 HiSuite 连不上手机（本次已踩，杀掉 adb 即恢复）。
