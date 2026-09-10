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

## 14. 第 13 轮：定位 mod 的钩子目标 + 硬边界确认

### 14.1 逆向 mod 的钩子安装（IDA）

`DllEntryPoint` → `sub_18001E7C8`（CRT）→ 用户 `DllMain` `sub_1800127C0`；
attach 分支为 `sub_180010C80`：

```c
GetModuleFileNameW(hinstDLL, ...);                  // 用自身模块句柄取路径
path = "%SystemRoot%\\System32\\version.dll";
Library = LoadLibraryExW(path, 0, LOAD_LIBRARY_SEARCH_SYSTEM32);
for (i = 0; i < 17; ++i) ptr[i] = GetProcAddress(Library, name[i]);
if (!DetourTransactionBegin()) {
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&ptr[0], hook0);   // sub_18000D1D0
    DetourAttach(&ptr[1], hook1);   // sub_18000D0E0
    DetourAttach(&ptr[2], hook2);   // sub_18000CEE0
    DetourAttach(&ptr[3], hook3);   // sub_18000CEF0
    if (ok) g_hooked = (DetourTransactionCommit() == 0);
    else DetourTransactionAbort();
}
```

→ **mod 挂钩的是系统 `version.dll` 的 4 个函数**（代理转发用），不是 `CreateFileW`。

### 14.2 针对性实验

最小载荷：对 `C:\Windows\System32\version.dll!GetFileVersionInfoSizeW` 做一次
`VirtualProtect(PAGE_EXECUTE_READWRITE)` → 写 6 字节 → 立刻还原 → 恢复保护。

```
已注入: base=... size=0x4000 (无 LoadImage / 无 PEB 条目)
after+5 alive=False
exit 0xC0000005
```

**结论**：ACE 的检测**不限于它自己挂钩的函数**——**任何对系统模块代码页的写权限变更/写入都会被终止**
（第 7 轮已确认绕过用户态 `VirtualProtect` 钩子（改调 `NtProtectVirtualMemory`）同样触发，
说明检测在内核层）。

### 14.3 硬边界

| 事实 | 含义 |
|---|---|
| ACE 内核驱动监控系统模块代码页写入 | 用户态**任何内联钩子方案**都会被检测 |
| 上游 mod 的核心机制 = 对 `version.dll` 的内联钩子 | **在 ACE 游戏内无法运行**（与注入方式无关） |
| 注入器本身不触碰任何代码页 | 注入器不被检测 ✅ |

要在 ACE 游戏内使用，只能**改写 payload 的转发机制**（内联钩子 → IAT/导出转发等不改写代码页的方案），
这属于对上游 payload 的改造，不属于注入器范畴。

## 15. 第 14 轮：IAT 重定向方案也被检测（边界闭合）

假设：用 **IAT 重定向**（改写数据页，不动代码页）替代内联钩子，是否可行？

最小载荷：遍历**游戏 exe 自身**的导入表，对某个 IAT 项做
`VirtualProtect(PAGE_READWRITE)` → **原值写回** → 恢复保护（完全无副作用）。

```
resolved 121 functions (trampolines=189)     ← 调用已经过合法模块跳板（返回地址在 ntdll 内）
已注入: base=... size=0x4000 (无 LoadImage / 无 PEB 条目)
after+5 alive=False
exit 0xC0000005
```

**结论**：即使调用方已伪装（跳板）、即使只改**数据页**、即使**写回原值**，仍然被终止。

### 15.1 ACE 的完整保护面（三轮实验汇总）

| 被监控的行为 | 实验（第几轮） | 结果 |
|---|---|---|
| 对 ACE 挂钩函数的代码页写权限变更 | 7 | ❌ 崩 |
| 绕过用户态钩子（`NtProtectVirtualMemory`） | 7 | ❌ 崩 |
| 对系统 `version.dll` 函数下内联钩子 | 13 | ❌ 崩 |
| 对**游戏自身 IAT**（数据页）的保护变更/写入 | 14 | ❌ 崩 |
| 从无后备内存调用被挂钩 API | 3（后用跳板解决） | ✅ 已解决 |

→ **ACE 内核驱动监控"对任何已加载模块（系统 + 游戏自身）的代码/数据修改"**。
用户态的所有 hook / patch 方案（内联钩子、IAT 重定向、导出转发落地）都会被覆盖。

### 15.2 最终交付边界

| 项 | 状态 |
|---|---|
| 注入器本体（手动映射 / 跳板 / 临时 PEB / bundle 预映射 / 事件驱动） | ✅ 通过 ACE 全部检查 |
| 上游 payload（内联钩子改 `version.dll`） | ❌ 在 ACE 游戏内无法运行（内核层检测） |
| 无内核反作弊的游戏 | ✅ 注入器 + payload 均可用 |

**要在 ACE 游戏内使用，只能走内核层方案（驱动）或改写 payload 的转发机制到"不改动任何已加载模块"的形式**，
两者都超出本注入器的范畴。

## 16. 第 16–17 轮：把触发点压缩到"bundle 的内存映射"

### 16.1 mod 的钩子到底在拦什么（IDA）

`hook1`/`hook3` = **`GetFileVersionInfoSizeW/A` 的代理**（带 TLS 重入保护），
自定义实现返回**伪造的版本信息**。

版本对比说明动机：

| DLL | 版本 |
|---|---|
| mod 的 bundle `nvngx_dlssg.dll` | `310,1,0,0` |
| 游戏自带的 | `310,5,2,0` |

→ 游戏做版本校验会拒绝 mod 的 DLL，所以 mod 必须钩 API 撒谎。

### 16.2 静态版本补丁（运行时零模块修改）

`patch_ver.py` 原地改写版本资源（`VS_FIXEDFILEINFO` + UTF-16 版本串）：

```
替换: 310,1,0,0 -> 310,5,2,0 x2
VS_FIXEDFILEINFO: 2 处, 字符串替换: 2 处
PowerShell 读回: FileVersion = 310,5,2,0  ✅
```

**这意味着"版本伪装"不再需要运行时钩子。**

### 16.3 隔离实验

| 配置 | 结果 |
|---|---|
| 注入器 + 空载荷 + **bundle 目录移走** | ✅ 游戏存活 30+ 秒 |
| 注入器 + 空载荷 + bundle 预映射 | ❌ 崩 |
| 同上但**不给 bundle 加 PEB 表项** | ❌ 仍崩 |
| 注入器 + `nocrt_d` + **版本补丁后的 bundle** | ✅ 存活 20+ 秒（1 次） |
| 同上一配置重复 3 次 | ❌ 3/3 崩 |
| `nocrt_d`（加载未签名 DLL）在跳板修复后的构建上 | ✅ 存活 20+ 秒 |

**结论**：
1. 触发 ACE 的**不是 mod 的钩子**，而是**内存里出现 `nvngx_dlssg.dll` 的未后备副本**；
2. 该触发**不稳定（有竞态）**——同样的配置有时存活 20+ 秒、有时 5 秒内崩，
   说明与"游戏何时加载自己的 nvngx_dlssg.dll"相对我们的映射时机有关；
3. 第 3 轮"加载未签名 DLL 必崩"的结论在**跳板修复后不再成立**（现可存活）——
   说明 ACE 对"来自无后备内存的调用"的判定确实已被跳板机制绕过。

### 16.4 当前判断

在 ACE 游戏内使用**修改版 DLSS 运行时**，需要一个"未签名的 NVIDIA DLL"出现在进程里；
无论用 LoadLibrary 还是手动映射，ACE 都会（在某个时机）发现它。
要稳定通过，只能**让 ACE 看不到这个模块**——即内核层方案。
## 17. 第 18 轮：三项判定实验（排除法）

| 实验 | 设计 | 结果 |
|---|---|---|
| 大块私有可执行内存 | 在目标里申请 8 MB PAGE_EXECUTE_READWRITE 并填充 | ✅ 游戏存活 → ACE 不管大块可执行内存 |
| 内容特征扫描 | 把 bundle 的原始文件字节原样写进私有可执行内存（无 PE 语义） | ✅ 游戏存活 → ACE 不做简单的模块内容扫描 |
| 不调用 bundle 的 DllMain | 预映射 bundle 但 runEntry=false（--bundle-norun） | ❌ 崩（该次日志未见 bundle 映射记录，实验不够干净） |

**结论**：ACE 的判定既不是内存大小、也不是内容字节匹配，
更像是**基于行为/时序的启发式扫描**——这也解释了同样配置有时存活 20+ 秒、有时 5 秒内崩。

## 18. 当前最佳正面证据

| 配置 | 结果 |
|---|---|
| 注入器 + 小载荷（<=0x4000）+ 不映射 bundle | **稳定存活 20-30 秒**（多次复现） |
| 加载未签名 DLL（跳板修复后） | 存活 ✅（第 3 轮结论已作废） |
| 调被挂钩 API（CreateFileW） | 存活 ✅ |
| 涉及 bundle / 大映像映射 | 不稳定（有时存活，多数崩溃） |
## 19. 第 19 轮：找到真正的触发点（重大进展）

### 19.1 一致性验证

| 配置 | 结果 |
|---|---|
| bundle 预映射 + 调用它的 DllMain | 5/5 崩 |
| bundle 预映射 + 不调用 DllMain（--bundle-norun） | **4/4 存活 30 秒以上** |

两次都确认日志里 bundle 真的被映射（bundle 的导入解析行可见）。

### 19.2 排除掉的因素

| 假设 | 实验 | 结论 |
|---|---|---|
| 大块私有可执行内存 | 申请 8 MB RWX 并填充 | 不触发 |
| 内存内容匹配已知模块 | 把 bundle 原始字节写进私有内存 | 不触发 |
| 映射区可访问性 | 整块设为 PAGE_NOACCESS | 仍触发（不是这个） |
| PEB 可见性 | 不给 bundle 加 PEB 表项 | 仍触发（不是这个） |
| **调用 nvngx_dlssg.dll 的 DllMain** | --bundle-norun | **不触发** ← 真正的触发点 |

### 19.3 为什么

nvngx_dlssg.dll 的 DllMain 会做 DLSS 运行时初始化（GPU/驱动交互、可能创建线程），
在 ACE 眼里是「非游戏模块发起的运行时初始化」，因此被终止。

### 19.4 由此得到的可行设计

1. WMI 在游戏启动瞬间注入（早于游戏加载 DLSS）
2. 预映射版本补丁后的 bundle（不调用其 DllMain）
3. 拦截游戏对 nvngx_dlssg.dll 的 LoadLibrary，返回已映射基址
4. 初始化交给游戏自己的导出调用路径

全程不触碰任何已加载模块的代码/数据页、不加载未签名 DLL、不运行可疑的运行时初始化。

### 19.5 附带修复

UnlinkByEntry（按表项指针摘链）在本轮日志中显示「成功（按表项指针）」——
上一轮观察到的「失败」在 bundle 不跑 DllMain 时不再出现。
## 20. 第 20 轮：端到端跑通（WMI 早期注入 + 预映射 bundle + 拦截桩）

把「不调用 bundle 的 DllMain」设为默认后，用 WMI 事件驱动做端到端实测：

```
[12:50:55] [+] 目标: HTGame.exe  pid=7128  root=E:\Neverness To Everness\Client\WindowsNoEditor
    匹配: ...\StreamlineCore\Binaries\ThirdParty\Win64\nvngx_dlssg.dll
    映射基址=0x180000000                       <- 主载荷
    预映射 bundle: nvngx_dlssg.dll  -> 0x95500000
    预映射 bundle: sm86_backend.dll -> 0x9CB0000
    LoadLibrary 拦截桩=0x6DA0000 (表项 1) / 0x6DE0000 (表项 2)
    已临时插入 PEB 表项 base=0x180000000 entry=0x6DF0000
    已向 10/10 个线程排入 APC
    桩已在目标线程执行（APC）
    临时 PEB 表项摘除: 成功（按表项指针）
    已注入: base=0x180000000 size=0x3000 (无 LoadImage / 无 PEB 条目)
```

游戏存活检查：**after+5/10/20/30/45 全部 alive=True** ✅

### 20.1 这套流程与旧方案的差别

| 项 | 旧（代理/注入 mod） | 现在 |
|---|---|---|
| 游戏目录文件 | 需要 version.dll | **零文件** |
| mod payload | 必装（它负责重定向） | **不需要**（注入器自己完成） |
| 内联钩子（改代码页） | 必须 | **完全没有** |
| 加载未签名 DLL | 是（bundle） | **否**（手动映射，不落盘） |
| 调用 NVIDIA DLL 的 DllMain | 是 | **否**（这是第 19 轮定位到的触发点） |
| 版本校验 | 运行时钩版本 API | **静态资源补丁** |
| 内核 LoadImage 通知 | 触发 | **不触发** |

### 20.2 仍需确认的一点

游戏是否真的**使用**了我们映射的 DLL（即 `LoadLibrary` 拦截是否被命中、
以及 `GetProcAddress` 在我们映射的映像上是否正常工作——bundle 映射时保留了 PE 头，因此应当正常）。
这需要进入游戏渲染路径才能确认（本机《异环》需要登录）。
