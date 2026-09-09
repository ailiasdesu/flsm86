# 最终报告 / Final Report

## 交付物

**FLSm86 全局自动隐身注入器** —— https://github.com/ailiasdesu/flsm86 （public）

为 [dlssg_for_sm86](https://github.com/sdli1995/dlssg_for_sm86)（让 Ampere/SM86 使用 DLSS 帧生成）
提供一个**全局、免代理、零磁盘痕迹**的注入器，替代"往每个游戏目录复制 version.dll"的用法。

## 1. 上游协议核查（上传合规性）

| 检查 | 结果 |
|---|---|
| GitHub API `license` | `null` |
| 仓库内 LICENSE 文件 | **不存在** |
| `THIRD_PARTY_NOTICES.txt` 自述 | "项目源码遵循 dlssg-to-fsr3 的 GPLv3"（引用的 LICENSE.md 并不存在） |
| 同文件排除条款 | **NVIDIA 运行时 DLL 与提取/重编译的内核资产不受该许可覆盖** |

→ 结论：可以按 GPLv3 发布**我们自己写的**注入器源码；
**不得再分发**上游 `version.dll`（含 NVIDIA 运行时）。本仓库不含任何 NVIDIA 二进制。

## 2. 注入器实现要点

| 机制 | 作用 |
|---|---|
| WMI `Win32_ProcessStartTrace` 事件订阅 | 进程创建即触发，**零轮询** |
| 手动映射（VirtualAllocEx + 写节 + 重定位 + 导入解析 + 抹 PE 头） | **不调用 LoadLibrary** ⇒ 不触发内核 `PsSetLoadImageNotifyRoutine` |
| 临时 PEB 表项（DllMain 期间插入，返回后摘除） | 让复杂 CRT 的 `DllMain` 正常初始化，同时最终不留模块条目 |
| 线程劫持 + `NtContinue` 无缝还原 | 入口在目标线程上执行后精确恢复（`CreateRemoteThread` 裸内存起始会崩） |
| 合法模块跳板（`sub rsp,8; call [rip]; add rsp,8; ret`） | 让被挂钩 API 看到的返回地址属于真实模块 |
| bundle 预映射 + `LoadLibrary*` 导入拦截 | 让 payload 自带的 DLL 加载**不经内核** |

## 3. 实测结论

| 检测面 | 结果 |
|---|---|
| 内核 `PsSetLoadImageNotifyRoutine` | 不触发 ✅ |
| PEB / Toolhelp32 模块枚举 | 无条目 ✅ |
| 游戏目录磁盘文件 | 零文件 ✅ |
| 内存 PE 结构 | 已抹除 ✅ |
| 被挂钩 API 调用（`CreateFileW`） | 通过 ✅ |
| 空闲 CPU（15 s） | **0 ms** ✅ |
| 真实游戏（《异环》10.5 MB payload） | 注入成功、目标稳定 ✅ |

## 4. 边界（已用实验证明，见 VERIFICATION 第 7/13/14 节）

ACE 的**内核驱动**监控"对任何已加载模块（系统 DLL + 游戏自身）的代码/数据修改"：

| 实验 | 结果 |
|---|---|
| 对 ACE 挂钩函数做 `VirtualProtect`（不改内容） | ❌ 终止 |
| 改用 `NtProtectVirtualMemory` 绕过用户态钩子 | ❌ 终止 |
| 对系统 `version.dll` 下内联钩子 | ❌ 终止 |
| 对游戏自身 IAT（数据页）写入原值 | ❌ 终止 |

→ 上游 payload 的核心机制（对 `version.dll` 的内联钩子）**在 ACE 游戏内无法运行**，
与注入方式无关。**用户态不存在绕过路径**。

## 5. 适用性

| 场景 | 可用性 |
|---|---|
| 无内核反作弊的游戏（单机游戏主流场景） | ✅ 注入器 + payload 均可用 |
| 带内核反作弊（ACE 等）的游戏 | 注入器不被检测 ✅ / 上游 payload 被检测 ❌ |

## 6. 复现

见 `README.md` 的用法章节与 `docs/VERIFICATION.md` 的 15 节实测记录
（每节都给出可复现的实验设计与输出）。
