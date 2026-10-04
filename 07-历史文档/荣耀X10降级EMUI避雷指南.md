# 荣耀X10（TEL-AN10）鸿蒙降级 EMUI 完整避雷指南

> 实测日期：2026-10-03
> 设备：荣耀X10 TEL-AN10 / 鸿蒙 2.0.0.270
> 结论：**公开手段无法降级**，本文说明为什么，以及所有踩过的坑

---

## 0. 结论先行（省时间版）

| 你的想法 | 现实 |
|---|---|
| 用 HiSuite 官方回退 | ❌ 华为已关闭该机型的回退通道 |
| 用 HiSuite Proxy 注入老固件 | ⚠️ 能注入、能下载、**卡在服务器授权签名** |
| 三键强刷 SD 卡刷包 | ⚠️ 能识别、**卡在"升级包版本号信息校验失败"** |
| 买"高维禁用"包 | ❌ **"高维禁用"不解除版本校验**，只解除用服限制 |
| 改包里的版本号 | ❌ 版本号在**华为私钥签名的文件**里，改了签名就失效 |
| **5% 模式线刷（不用解 BL）** | ⚠️ **原理可行，但猎人工具只支持麒麟 650-970，820 不在内** |
| 解锁 BL 后随便刷 | ❌ 荣耀X10 的 BL 只能用**拆机短接 / ISP 飞线**方式解锁 |
| 刷机装 GMS | ❌ 降级走不通，但**容器方案可以不降级装 GMS** |

**一句话：荣耀X10（麒麟820）从鸿蒙降回 EMUI，公开渠道已经彻底走不通。**
**卡点是华为的私钥签名 + 芯片级工具支持，不是技术能力问题。**

---

## 1. 设备与锁状态（实测）

```
型号        TEL-AN10（荣耀X10 全网通）
S/N         XXXXXXXXXXXXXXXXX
SoC         kirin820（麒麟820）
出厂系统    EMUI 10.1.1
当前系统    HarmonyOS 2.0.0.270 (TEL-AN10 2.0.0.270(C00E230R7P5))
Android 基座 10
安全补丁    AOSP 2020-11-01 / 华为 2022-07-01
```

### Bootloader 锁状态

```
FB LockState:   LOCKED
USER LockState: LOCKED
verifiedbootstate = green
avb_version = 1.1
dm-verity: enforcing
SELinux: enforcing
ro.boot.vercnt1 = 1        ← 防回滚计数器
分区布局: A-only 单槽 + 动态分区（super）
```

**锁着 BL 时，fastboot 几乎全部命令被拒**（实测）：

```
fastboot getvar all          → Command not allowed
fastboot getvar serialno     → Command not allowed
fastboot getvar unlocked     → Command not allowed
fastboot getvar current-slot → Command not allowed
fastboot getvar rollback-index → Command not allowed
fastboot oem device-info     → Command not allowed
fastboot oem backdoor info   → Command not allowed

能用的只有：
fastboot getvar max-download-size   → 471859200
fastboot getvar product-model       → 也失败
```

---

## 2. 为什么降不了（核心原理）

### 2.1 华为的固件是"三段式"

```
Base     TEL-LGRP1-CHN 102.0.0.270        ← 系统主体
CUST     TEL-AN10-CUST 102.0.0.230(C00)   ← 定制层
Preload  TEL-AN10-PRELOAD 102.0.0.5(C00R7)← 预装层
```

**升级时必须三个组件齐全且匹配**，任何一个缺失或不匹配，整个升级被拒。

### 2.2 版本校验读的是"签名保护的版本号"

包里有几个关键文件：

```
update_sd_base.zip
  ├─ SOFTWARE_VER_LIST.mbn   1.4 KB   版本白名单（明文，可改，但没用）
  ├─ PTABLE.APP              221 KB   含版本号 ×2，开头是 RSA 签名块  ← 关键
  ├─ UPDATE.APP              4.97 GB  含版本号，开头是 RSA 签名块      ← 关键
  └─ META-INF/CERT.RSA       华为私钥签名
```

**实测证明**：
- 改 `SOFTWARE_VER_LIST.mbn`（把手机当前版本加进白名单）→ **校验仍然失败**
- 说明校验读的是 `PTABLE.APP` / `UPDATE.APP` 里的版本号
- 而这两个文件**开头就是 RSA 签名块**（`...SHA256RSA...` + 时间戳）

**改版本号 → 签名失效 → 需要华为私钥重新签名 → 拿不到。**

**这就是这堵墙的本质。**

### 2.3 官方回退通道已关闭（三层证据）

1. HiSuite 向服务器发送的 `hfull_switch` / `full_back` 请求（`full_back` 里的固件名后缀是 `_EmotionUI_10.1.1`，说明华为服务器知道 EMUI 包存在）
2. 服务器对 `full_back` 返回 **`status: "0"`（无可用回退包）**
3. HiSuite 界面只提供 **HarmonyOS 3.0.0.165** 升级，**没有任何回退选项**

> ⚠️ **千万别点那个"升级"** —— 升到鸿蒙 3.0 会抬高防回滚计数器，以后更降不下来。

---

## 3. 走过的十条路（含失败原因）

### 路线 1：HiSuite 官方回退 ❌

**做法**：HiSuite → 系统更新 → 看有没有回退选项

**结果**：只显示"已是最新正式版"，唯一选项是升级到鸿蒙 3.0

**教训**：这条路 2023 年之后就已经关闭了，别再浪费时间

---

### 路线 2：HiSuite Proxy 注入老固件 ⚠️（走得最远，但卡死）

**原理**：本地 MITM 代理拦截 HiSuite ↔ 华为服务器的 HTTPS，往响应里注入任意固件地址

**工具**：`HiSuite Proxy V3.3.0` + `HiSuite 10.1.0.550_OVE`

#### 踩过的 7 个坑

| # | 坑 | 现象 | 解决 |
|---|---|---|---|
| 1 | **HiSuite 版本太新** | Proxy 报 `These roms aren't supported in the current version of Hisuite` | **降到 10.1.0.550_OVE** |
| 2 | **NSIS 安装包自校验失败** | 安装器弹 `NSIS Error`，ExitCode=2 | **把安装包从超长含空格路径复制到 `C:\` 再运行** |
| 3 | **Proxy 启动报 `Files Corrupted!`** | 双击没反应 | **必须修正工作目录**（`Assembly.LoadFrom("ProxyUtilities.dll")` 是相对路径）。写个 `launch.bat` 先 `cd /d` |
| 4 | **Proxy 报 `ThrowSecurityException`** | 改注册表被拦 | **在沙箱外启动** |
| 5 | **网页连不上本地 Proxy** | Add Rom 报 `Couldn't add the ROM. ( Get HiSuite Proxy )` | **关掉 Clash 的 TUN 模式**（TUN 会劫持 127.0.0.1，即使系统代理有 bypass 规则也没用） |
| 6 | **CUST/Preload 找不到** | Proxy 里只有 Base 被填充 | 把 CUST/Preload 的 URL **都指向 Base 的地址** |
| 7 | **文件名含 Tab 字符** | 日志报 `ERROR_CODE=123 保存文件失败`（ERROR_INVALID_NAME） | **删掉名称开头的 Tab** |

#### 成功做到的部分 ✅

```
✅ HiSuite 认下了注入的固件（日志里出现 TEL-LGRP1-CHN 3.1.1.203）
✅ 出现"切换到其他版本"入口（勾选 Roll-back OS 后）
✅ 完整下载 11.51 GB 固件包，sha256 校验通过
✅ 走到最后一步"授权校验"
```

#### 最后卡死 ❌

```
[fn=5]  GetAuthFile  file=data=&sign=&cert=.        ← 授权文件是空的
[fn=6]  UpdateAuthorizationCheck ret = 7            ← 授权校验失败
```

**`GetAuthFile` 返回空** —— HiSuite 需要一份**华为服务器签名的授权文件**（`data` + `sign` + `cert` 三段）。

**Proxy 能伪造 ROM 列表、版本号、下载地址，但伪造不了华为私钥的签名。**

> 顺带一提：勾选 `Force Auth Bridge` 也没用，日志里没有任何相关记录。

---

### 路线 3：三键强刷 / SD 卡刷包 ❌

**原理**：把 `dload` 文件夹放到存储设备，手机关机后三键强刷

#### 踩过的坑

| # | 坑 | 现象 | 解决 |
|---|---|---|---|
| 1 | **内部存储不扫描** | 三键强刷掉进 Recovery 菜单；工程菜单报"储存卡不在位" | **这台机器只认外置存储设备**（U盘/SD卡） |
| 2 | **FAT32 装不下大文件** | `UPDATE.APP` 4.97 GB > FAT32 的 4 GB 上限 | **格式化成 exFAT** |
| 3 | **包格式不对** | 用 OTA 包的 `UPDATE.APP` 直接失败 | **必须用官方 SD 卡升级格式**（见下） |
| 4 | **三键强刷不触发升级** | 掉进 HarmonyOS Recovery 菜单 | 改用**工程菜单**（拨号 `*#*#2846579#*#*`） |

#### 正确的包格式

```
dload/
  update_sd_base.zip                          4.0 GB
  TEL-AN10_all_cn/
    update_sd_cust_TEL-AN10_all_cn.zip          382 KB
    update_sd_preload_TEL-AN10_all_cn_R5.zip    960 MB
```

> ⚠️ **不是** `dload/UPDATE.APP`！那是 OTA 格式，不是 SD 卡升级格式。

#### 最后卡死 ❌

```
升级失败!
升级包版本号信息校验失败        ← 精确原因
请重新下载关联升级包升级
```

**注意：这是"立即失败，没有进度条"** —— 说明在写入之前就被拦下了。

---

### 路线 4：自己改包的版本号 ❌

**做法**：把 `SOFTWARE_VER_LIST.mbn` 的第一行改成手机当前版本 `TEL-LGRP1-CHN 102.0.0.270`

**结果**：**同样的错误**

**教训**：版本校验读的不是这个明文白名单，而是签名保护的 `PTABLE.APP` / `UPDATE.APP`

---

### 路线 5：买"高维禁用"包 ❌（最关键的认知纠正）

**"高维禁用"到底是什么？**

从 CSDN 上的文件名看英文原名：

```
(High Level Repair Center is forbidden) Berlin-AL10AC00B381_Android7.0_EMUI5.0.zip
高维禁用_NOH-AN00 102.0.0.168_Firmware_HarmonyOS 2.0.0_05016QEW
```

**"高维禁用" = "高级维修中心禁用" = 解除了"只有授权维修点能用"的限制。**

**它 ≠ 解除版本校验！**

**实测证据**：下载了 `高维禁用_Teller-AN00DW 10.1.1.191(C00E185R7P1)` 用服包，结构和普通包对比：

```
高维禁用包 SOFTWARE_VER_LIST.mbn  1713 字节 / 67 行  → 全是 10.1.1.x，没有鸿蒙版本
普通包     SOFTWARE_VER_LIST.mbn  1438 字节 / 57 行  → 同样全是 EMUI 版本
```

**两者没有本质区别** → 刷上去**照样报"版本号信息校验失败"**。

> 💰 **避雷**：别再花钱买"高维禁用"包来降级了，**它解决不了版本校验**。

---

### 路线 6：dload + 高维禁用中转包（原计划）❌

和路线 5 一样，卡在版本校验。

---

### 路线 6.5：**5% 模式线刷**（不用解锁 BL）⚠️ **芯片不支持**

**这是维修行业绕开 BL 锁的正规做法**，值得单独讲。

#### 原理

> "华为手机的刷机模式**不是 Fastboot 模式，而是百分之五模式**"

进入方式：
- **生产模式** → 工具里点 `Production mode to erecovery`
- **Fastboot 模式** → 工具里点 `fastboot mode to erecovery`
- 手机进入"升级的百分之五界面" → 此时工具可以往底层写

#### 工具

**MRT HW Flash Tool**（猎人华为单机离线版）
- 不用网络、不用代理、不用加密狗、不用账号
- 不连服务器，不存在服务器关停问题
- 支持降级、刷机、写底层

#### 完整流程（来自 CSDN 教程）

```
1. 解压高维禁用包，得到：
     · UPDATE.APP                    ← "大包"（4 GB）
     · update_XXX_all_cn.app         ← "小包"（CUST+Preload 合并）

2. 进 5% 模式（关机 → 按电源键开机 → 同时按音量+ + 音量-）

3. 工具里选"大包" → START → 刷写
4. 选"小包" → START → 刷写
   （写 userdata 块时会报错，取消勾选 userdata 再刷即可）
```

#### ❌ 对麒麟 820 不可行的原因

教程原文明确写了工具支持范围：

> **"支持 650-970 写底层救砖～线刷降级"**

**麒麟 650 ~ 970。荣耀X10 是麒麟 820，不在范围内。**

知乎教程也印证：

> "**麒麟960是最后一代支持的 soc**"

而新麒麟（9000，如 Mate40）走的是 **ISP 飞线解锁**，是另一套方案，需要专业设备 + 拆机。

#### ⏳ 但值得再挖

猎人工具在持续更新。公开流传的版本停留在老芯片，**维修论坛里可能有人知道支持 820 的新版本**。

**如果你要问维修店，就问这一句：**

> "荣耀X10，麒麟820，鸿蒙2.0，**有没有支持 820 的 5% 模式线刷工具**？能不能降级到 EMUI 10.1？"

---

### 路线 7：解锁 Bootloader ❌（除非拆机）

**实测结论**：Kirin 820 + 鸿蒙 2.0 **没有任何免拆机解锁方案**

| 工具 | 最高支持 |
|---|---|
| HCU / DC-Unlocker | Kirin 980 |
| UnlockTool `[Unlock BL]` | 仅 Kirin 710 / 710F |
| PotatoNV | Kirin 960 |
| Huawei-Unlock-Tool | Kirin 980，且要求 EMUI 8/9 |

**jesse205 刷机指南**明确写着：解锁方法只适用于"**EMUI 9 及以下**"，"**新设备已经关闭了解锁命令，您可能需要拆机才可以解锁**"。

**唯一路径：拆机短接**（淘宝约 100-300 元）

---

### 路线 8：免解锁 root ❌

同上，Kirin 820 没有免解锁 root 方案。

---

### 路线 9：售后官方降级 ⏳ **没试过**

**这是唯一还没试过的正规渠道。** 售后手上有**能重新签名的工具** —— 正是我们缺的那把钥匙。

---

### 路线 10：容器方案装 GMS ⏳ **没试过，但最实际**

如果核心需求只是"装 GMS"而不是"要 EMUI"，用 **GBox / OurPlay** 这类容器，**不降级、不刷机、零风险**。

---

## 4. 避雷清单（可直接抄）

### 🔴 绝对不要做的事

1. **别点 HiSuite 里的"升级到鸿蒙 3.0"** —— 会抬高防回滚计数器，以后更降不下来
2. **别买"高维禁用"包来降级** —— 它不解除版本校验，白花钱
3. **别信"三键强刷能解 BL"** —— 那是解屏幕锁/账户锁（FRP），不是 BL 锁
4. **别用 FAT32 的 U 盘/SD 卡装大包** —— 4 GB 上限，必须 exFAT
5. **别把包放在超长含空格的路径下** —— NSIS 安装器会自校验失败

### 🟡 做之前必须确认的事

1. **手机有没有外置存储** —— 荣耀X10 **不扫描内部存储**做本地升级，必须 U 盘（Type-C 直插或 OTG）或 NM 卡
2. **Clash / 代理软件开没开 TUN** —— TUN 模式会劫持 `127.0.0.1`，破坏本地代理工具
3. **HiSuite 版本对不对** —— 刷老固件必须用 **HiSuite 10.1.0.550_OVE**，11.x 会拒绝老 ROM
4. **代理软件的工作目录** —— 很多 .NET 小工具用相对路径加载 DLL，双击启动会失败

### 🟢 有用的信息

- **工程菜单**：拨号输入 `*#*#2846579#*#*`
- **三键强刷**：关机后长按【音量+】+【音量-】+【电源键】
- **5% 模式**：关机 → 按电源键开机 → 开机过程中同时按【音量+】+【音量-】（维修工具刷机用）
- **荣耀X10 机型族**：TEL-AN10 / TEL-AN00 / TEL-AN00A **共用同一个 Base 包**（RomID 583193，同一个 filelist）
- **固件三段式命名**：Base `TEL-LGRP1-CHN <ver>` / CUST `TEL-AN10-CUST <ver>(C00)` / Preload `TEL-AN10-PRELOAD <ver>(C00R7)`
- **麒麟芯片与工具支持**：
  - 麒麟 650-970 → 猎人 MRT 线刷工具、PotatoNV 可用
  - 麒麟 980 → HCU/DC-Unlocker、Huawei-Unlock-Tool 上限
  - 麒麟 820 / 9000 → 只能 ISP 飞线或拆机短接

### 🔵 术语对照

| 中文 | 英文原文 | 真实含义 |
|---|---|---|
| **高维禁用** | `High Level Repair Center is forbidden` | 解除"只有授权维修点能用"的限制，**不是**解除版本校验 |
| **大包** | `UPDATE.APP` | 系统主体（约 4 GB） |
| **小包** | `update_XXX_all_cn.app` | CUST + Preload 合并（约 1-1.5 GB） |
| **百分之五模式** | 5% mode | 升级模式的底层写入状态，维修工具刷机入口 |
| **三键强刷** | — | 关机后音量+ + 音量- + 电源 |

---

## 5. 如果一定要降级，只剩这几条路

### ① 售后官方降级（免费，推荐先试）

话术：
> "我这是荣耀X10，型号 TEL-AN10，现在系统是鸿蒙 2.0.0.270，
>  用起来不习惯，想刷回原来的 EMUI 10.1，能不能帮忙处理？"

**去之前**：备份数据、带上购机凭证

### ② 问维修店有没有支持麒麟 820 的 5% 模式线刷工具（**新发现，值得一试**）

话术：
> "荣耀X10，麒麟820，鸿蒙2.0，**有没有支持 820 的 5% 模式线刷工具**？
>  能不能用高维禁用包降级到 EMUI 10.1？"

**理由**：5% 模式线刷是维修行业绕开 BL 锁的正规做法，原理可行。公开的猎人工具只支持 650-970，但**可能存在支持 820 的新版本**。

### ③ 拆机短接解锁 BL / ISP 飞线（约 100-300 元）

解锁后可以：
- fastboot 刷任意镜像
- 刷 Magisk 获取 root
- 随意降级

**风险**：拆机有损坏风险，且解锁后失去保修

### ④ 换手机

如果只是想要 GMS + 流畅，可能比折腾更划算

---

## 6. 附：完整的技术证据

### 6.1 HiSuite 服务器响应（Proxy 注入后的完整 JSON）

```json
{"status":"0","versionPackageCheckResults":[
  {"versionPackageType":2,"components":[{
      "versionID":"583193",
      "name":"TEL-LGRP1-CHN 3.1.1.203",
      "url":"http://update.dbankcdn.com/download/data/pub_13/HWHOTA_hota_900_9/8f/v3/WFjFCw3QSRWwO7kHuKsF2w/"
  }]},
  {"versionPackageType":3,"components":[{
      "name":"BLA-L29-CUST 10.0.0.4(C432)",
      "url":"http://update.dbankcdn.com/TDS/data/files/p3/s15/G5398/g1755/v386370/f1/"
  }]},
  {"versionPackageType":4,"components":[{
      "name":"BLA-L29-PRELOAD 10.0.0.3(C432R1)",
      "url":"http://update.dbankcdn.com/TDS/data/files/p3/s15/G5398/g1755/v386373/f1/"
  }]}
]}
```

`versionPackageType`：**2=Base / 3=CUST / 4=Preload**

### 6.2 授权校验失败（HiSuite 日志原文）

```
[fn=4]  GetUpdateAuthInfo m_deviceId = 9CCDFC74BF3CDB17F3ADBBE798ED515AD8877C811AB1B3A5B1058DD10B6577E8
[sn=93] m_versinoNumber = TEL-LGRP1-CHN 3.1.1.203\r\nTEL-LGRP1-CHN 3.1.1.203\r\nTEL-LGRP1-CHN 3.1.1.203
[fn=5]  GetAuthFile  file=data=&sign=&cert=.
[sn=94] package size 12355681926
[fn=6]  UpdateAuthorizationCheck ret = 7
```

### 6.3 SD 卡升级的校验失败

```
升级失败!
升级包版本号信息校验失败
请重新下载关联升级包升级
```

### 6.4 UPDATE.APP 的头部（证明是签名保护）

```
偏移 0x00 - 0x5F: 全 00（对齐）
偏移 0x60 起:     ...U.Z.d.......HW7x27......2021.03.04......17.00.48........SHA256RSA...
                  ↑                                    ↑
              签名标识                            签名时间戳
```

### 6.5 版本白名单的实际内容（base 包）

```
TEL-LGRP1-CHN 10.1.1.191      ← 本包版本
TEL-LGRP1-CHN 10.1.1.190
TEL-LGRP1-CHN 10.1.1.185
...
TEL-LGRP1-CHN 10.1.0.1        ← 全部 67 行都是 EMUI 版本
```

**手机是 `TEL-LGRP1-CHN 102.0.0.270`（鸿蒙），不在名单里 → 校验失败**

**但改成在名单里也没用**（实测）→ 说明真正的校验在签名文件里

---

## 7. 一句话总结

> **华为把"能不能降级"这件事，锁在了服务器端的私钥签名里。
> 关掉服务器授权 = 客户端拿到再多固件包也没用。
> 这不是技术能力问题，是密码学问题。**

---

*本文基于 2026-10-03 的实测，所有结论都有日志/文件证据。*
*手机全程完好，没有变砖，系统未被改动。*
