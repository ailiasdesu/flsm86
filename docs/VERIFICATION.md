# 实测记录（Verification）

所有结论均来自本机实测，命令与输出可复现。

## 1. 载荷注入稳定性

**样本**：上游 `version.dll`（10,522,624 字节，完整 CRT，导入 bcrypt + kernel32）

```
第 1 次: 注入=1 跑满=6/6
第 2 次: 注入=1 跑满=6/6
第 3 次: 注入=1 跑满=6/6
第 4 次: 注入=1 跑满=6/6
第 5 次: 注入=1 跑满=6/6
第 6 次: 注入=1 跑满=6/6
第 7 次: 注入=1 跑满=6/6
第 8 次: 注入=1 跑满=6/6
=== 8 轮压测: 跑满 8 / 早退 0 ===
```

加上此前 3/3，累计 **11/11** 次注入后目标进程完整跑完 30 秒（夹具每 5 秒自报状态）。

## 2. 隐身属性（目标进程自述）

```
[t=0]  modules: FakeGame.exe ntdll.dll KERNEL32.DLL KERNELBASE.dll VERSION.dll msvcrt.dll
[t=15s] modules: FakeGame.exe ntdll.dll KERNEL32.DLL KERNELBASE.dll VERSION.dll msvcrt.dll
        ← 注入后模块列表无任何新增条目
[t=15s] 私有可执行区域: 无映射名(手动映射痕迹)=1, 有映射名=0
        ← 映射区不是文件映射（GetMappedFileName 为空）
```

注入侧日志：

```
TLS: index=2 block=...
已临时插入 PEB 表项 base=0x180000000（DllMain 后摘除）
回退到线程劫持方式...
临时 PEB 表项已摘除
已注入: base=0000000180000000 size=0xA21000 (无 LoadImage / 无 PEB 条目)
```

| 检测面 | 结果 | 依据 |
|---|---|---|
| 内核 `PsSetLoadImageNotifyRoutine` | **不触发** | 全程不调用 LoadLibrary / 不映射 image section |
| PEB / Toolhelp32 模块枚举 | **无条目** | 临时表项在 DllMain 后摘除 |
| 磁盘文件（游戏目录） | **零文件** | 载荷加密存放于 `%LOCALAPPDATA%` |
| 内存 PE 结构 | **无** | 映射后抹除 MZ/PE 签名 |
| 映射类型 | `MEM_PRIVATE`，无映射文件名 | 目标进程 `GetMappedFileName` 为空 |

## 3. 性能

```
监视方式: WMI 事件驱动（进程创建时系统推送，自身零轮询）
ALIVE: CPU 15s = 0 ms = 0% of one core; WS = 10 MB
```

对照：轮询回退版本实测 `CPU 10s = 7437.5 ms`（≈74% 单核），已废弃并默认禁用。

## 4. 代理模式残留清理

```
C:\Program Files (x86)\Steam\steamapps\common -> 0 个
E:\SteamLibrary\steamapps\common            -> 0 个
E:\Neverness To Everness                     -> 0 个
```

（扫描 `version.dll` / `winmm.dll` / `dlssg_sm86.ini` / `*.flsm86bak`）

## 5. 反作弊实测（ACE）

| 项 | 状态 |
|---|---|
| ACE 内核驱动可启动 | ✅ `ACE-BASE` + `ace-game` RUNNING |
| ACE 是否扫描任意进程 | ❌ 不会（同结构假 `HTGame.exe` 未被注入 ACE 用户态组件） |
| 真实游戏内验证 | ⏳ 需要游戏实际运行（启动器需登录） |

> 结论：**静态/加载层面的隐身属性已实测**（见 §2）；**实战反作弊判定仍需在真实游戏内验证**。
> 未完成该验证前，不应宣称"对 ACE 完全隐身"。

## 6. 真实游戏 + ACE 实测（关键发现）

**环境**：《异环》`HTGame.exe`（UE5，250 MB）+ ACE 全套
（`AntiCheatExpert Service` / `SGuardSvc64` 运行，游戏进程内已加载 `ACE-Base64.dll`）

**对照实验**（每次都是：启动游戏 → 等 20 s 确认 ACE 模块已注入 → 注入 → 观察）：

| 载荷 | 是否调用 API | ACE 用户态 | 结果 |
|---|---|---|---|
| `empty_payload`（空 DllMain，无导入） | 否 | 已加载 | **存活 30 s+** ✅ |
| `nocrt_b`（只调 `GetCurrentProcessId`） | 是（基础 API） | 已加载 | **存活 20 s+** ✅ |
| `nocrt_a`（调 `CreateFileW`） | 是（文件 API） | 已加载 | **5 s 内崩 `0xC0000005`** ❌ |
| 上游 `version.dll`（10.5 MB） | 是（大量文件 API） | 已加载 | **5 s 内崩 `0xC0000005`** ❌ |
| 上游 `version.dll`（10.5 MB） | — | **未加载**（ACE 服务未启动） | **存活 30 s+** ✅ |

**结论**：

1. **注入机制本身不被检测** —— 空载荷与基础 API 载荷在 ACE 全环境下都存活，
   说明"手动映射 + 线程劫持 + 临时 PEB 表项"没有触发 ACE 的加载/模块/内存特征检测。
2. **ACE 检测的是"从无后备内存发起被挂钩 API 调用"** —— 一旦载荷调用 `CreateFileW`
   这类 ACE 挂钩的文件 API，其钩子在返回地址检查中发现调用方不属于任何模块映像，
   随即终止进程（表现为 `0xC0000005`）。
3. 关闭 ACE 用户态组件后同一载荷存活 → **确认是 ACE 用户态行为，而非注入器缺陷**。

**这是真实的检测向量，也是下一步要解决的核心问题。**

### 6.1 待解决

| 方案 | 思路 | 状态 |
|---|---|---|
| 模块踩踏（module stomping） | 把载荷代码放进已加载的合法模块地址空间，使返回地址解析到真实模块 | 待实现 |
| 返回地址伪装 | 调用被挂钩 API 前在栈上放置合法模块地址 | 待实现 |
| 合法模块跳板 | 通过合法模块内的 `call [IAT]` 跳板间接调用 | 待实现 |

## 8. 对抗实验（第 5 轮）：定位并修复真正原因

### 8.1 关键发现：跳板的栈未对齐（自身 bug）

跳板原实现是 `call [rip+0]; ret`。调用方进入跳板时 `RSP≡8 (mod 16)`，
再 `call` 一次后被调 API 看到 `RSP≡0`，**违反 x64 ABI**（被调方入口要求 `RSP≡8`），
API 内的 `movaps` 会因未对齐而触发 `0xC0000005`。

**修复**：跳板改为

```asm
sub rsp, 8
call qword ptr [rip+0]
add rsp, 8
ret
```

**修复后实测（真实游戏 + ACE 全环境，载荷调用 `CreateFileW`）**：

```
TRAMPOLINE-AREA: ... (4043 bytes) in C:\WINDOWS\SYSTEM32\ntdll.dll
import KERNEL32.dll -> resolved 2 functions (trampolines=3)
已注入: base=... size=0x4000 (无 LoadImage / 无 PEB 条目)
after+5 alive=True
after+10 alive=True
after+20 alive=True      ← 游戏存活！
```

> 结论修正：**第 3–4 轮观察到的"ACE 检测被挂钩 API 调用"其实是跳板栈对齐 bug**。
> 修复后，载荷在 ACE 全环境下调用被挂钩的文件 API **不再触发终止**。

### 8.2 新发现：ACE 拦截"未签名 DLL 加载"

上游 `version.dll` 载荷仍会崩。逐项二分后定位到它自己的一步操作：

| 载荷行为 | 结果 |
|---|---|
| 空 DllMain | 存活 ✅ |
| `GetCurrentProcessId` | 存活 ✅ |
| `CreateFileW`（读/写） | **存活** ✅（修复跳板后） |
| `LoadLibraryW("未签名的本地 DLL")` | **5 秒内崩** ❌ |

→ **ACE 检测的是"游戏进程内加载未签名 DLL"**（内核镜像加载通知 + 签名校验）。
这是**载荷自身行为**触发的，与注入方式无关：
上游 mod 会把内嵌的 `nvngx_dlssg.dll` / `sm86_backend.dll` 释放到磁盘再 `LoadLibrary`，
这一步必然被 ACE 看到。

### 8.3 下一步

| 方案 | 说明 |
|---|---|
| 拦截载荷的 `LoadLibrary*` 导入 | 换成"手动映射 + 返回已映射基址"的桩，使 mod 的 bundle 加载不经过内核 |
| 预映射 bundle | 该 bundle 已在 `%LOCALAPPDATA%\DlssgSm86\bundles\*` 落盘，可在注入时先手动映射 |
| 若仍被检测 | 需要内核侧对抗（超出用户态注入器范围） |

## 9. 对抗实验（第 7 轮）：ACE 的代码篡改检测

上游 mod 仍崩，继续二分。用最小载荷复现：

| 载荷行为 | 结果 |
|---|---|
| 空 DllMain | 存活 ✅ |
| `CreateFileW`（读/写） | 存活 ✅ |
| **对 `CreateFileW` 调一次 `VirtualProtect`（不改内容）** | **5 秒内崩** ❌ |
| 改用 `ntdll!NtProtectVirtualMemory`（绕过用户态钩子） | **仍崩** ❌ |

**结论**：ACE **检测"对已挂钩函数所在页面的写权限变更"**，且该检测在**内核层**
（绕过用户态 `VirtualProtect` 钩子后依然触发）。

这正是上游 mod 崩溃的原因：它的核心机制是 **Detours 内联钩子**
（`VirtualProtect` + 改写 `CreateFileW`/`FindFirstFileW` 等函数序言），
与 ACE 的钩子直接冲突 → 被终止。

### 9.1 边界结论

| 层 | 状态 |
|---|---|
| 注入器自身（手动映射 / 线程劫持 / 跳板 / 临时 PEB / bundle 预映射） | **通过 ACE 全部检查** ✅ |
| 上游 mod 的**行为**（内联钩子改写被 ACE 保护的代码页） | **被 ACE 内核层检测** ❌ |

要让上游 mod 在 ACE 下运行，需要修改 mod 自身（例如把"内联钩子"改成"IAT 重定向"，
不改写被 ACE 保护的代码页）——这属于修改上游 payload，不属于注入器范畴。

## 10. 第 8 轮：mod 与 ACE 的共存尝试

| 尝试 | 结果 |
|---|---|
| 拦截载荷的 `VirtualProtect`（让 Detours 装不上内联钩子） | 仍崩 ❌ |

原因：Detours 除了改写函数序言，还会 `SuspendThread` + `SetThreadContext`
（用于同步已执行线程），这些同样是 ACE 的检测面。**上游 mod 的行为与 ACE 本质不兼容**，
除非修改 mod 自身（例如改为纯 IAT 重定向）。

## 11. 结论汇总

### 11.1 注入器（本仓库交付物）

| 检测面 | 结果 |
|---|---|
| 内核 `PsSetLoadImageNotifyRoutine` | 不触发 ✅ |
| PEB / Toolhelp32 模块枚举 | 无条目 ✅ |
| 磁盘文件（游戏目录） | 零文件 ✅ |
| 内存 PE 结构 | 已抹除 ✅ |
| 被挂钩 API 调用（如 `CreateFileW`） | 通过 ✅ |
| 空载荷 / 基础 API 载荷 | 通过 ✅ |
| 空闲 CPU | 0 ms / 15 s ✅ |

### 11.2 上游 payload 的行为（不在本仓库范围）

| 行为 | 结果 |
|---|---|
| 加载未签名 DLL（bundle） | 被 ACE 拦截（本仓库已用"预映射 + LoadLibrary 拦截"绕过） |
| Detours 内联钩子（改写被保护代码页 + 线程上下文改写） | 被 ACE 内核层拦截 ❌ |

> **因此**：本注入器可用于**没有内核级反作弊的游戏**；
> 对 ACE 这类带内核驱动 + 代码完整性校验的反作弊，
> 注入器本身不被检测，但上游 mod 的**钩子行为**会被检测——需要改造 mod 自身。

## 12. 第 9 轮：与 ACE 共存的进一步尝试

| 尝试 | 结果 |
|---|---|
| 拦截 Detours 事务所需 API（`VirtualProtect`/`SuspendThread`/`SetThreadContext`/`FlushInstructionCache`…） | 仍崩 ❌ |
| 停止 `AntiCheatExpert Service` 后再注入 | 仍崩 ❌（**游戏自身会加载 `ACE-Base64.dll`**，与服务的运行状态无关） |
| 调试器抓崩溃点 | 崩在游戏模块内（`HTGameBase.dll` 范围），寄存器 `RAX=0x2B992DDFA232`（默认安全 cookie 值） |

**结论**：本机唯一支持 DLSS 帧生成的游戏《异环》**必然加载 ACE 用户态组件**，
而上游 payload 的行为（内联钩子 / 线程上下文改写）与之冲突。
在用户态注入器层面无法绕过——需要改造 payload 自身（例如把内联钩子换成 IAT 重定向）。

## 13. 交付边界（最终）

| 项 | 状态 |
|---|---|
| 注入器本体（本仓库） | ✅ 全部隐身属性实测通过（§11.1） |
| 对无内核反作弊的游戏 | ✅ 可用（注入 + payload 均实测稳定） |
| 对带内核反作弊（ACE）的游戏 | ⚠️ 注入器不被检测；**上游 payload 的钩子行为被检测**，需改造 payload |
