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

结论：可以按 GPLv3 发布**我们自己写的**注入器源码；**不得再分发**上游 `version.dll`。本仓库不含任何 NVIDIA 二进制。

## 2. 两条使用路径

| 场景 | 方案 | 实测 |
|---|---|---|
| 无内核反作弊的游戏 | **注入器**：零磁盘文件、不触发 LoadImage、0 ms CPU | ✅ 夹具 11/11；真实游戏注入后存活 45 s+ |
| 带内核反作弊（ACE 等） | **磁盘替换** `nvngx_dlssg.dll`（版本补丁 + SM86 运行时） | ✅ 启动阶段存活 45 s+，ACE 无反应 |

## 3. 注入器实现要点

| 机制 | 作用 |
|---|---|
| WMI `Win32_ProcessStartTrace` 事件订阅 | 进程创建即触发，**零轮询**（实测空闲 0 ms CPU / 15 s） |
| 手动映射（写节 + 重定位 + 导入解析 + 抹 PE 头） | **不调用 LoadLibrary** ⇒ 不触发内核 `PsSetLoadImageNotifyRoutine` |
| 临时 PEB 表项（DllMain 期间插入，返回后按指针摘除） | 让复杂 CRT 正常初始化，最终不留模块条目 |
| 线程劫持 + `NtContinue` 无缝还原 | 入口在目标线程上执行并精确恢复 |
| 合法模块跳板（`sub rsp,8; call [rip]; add rsp,8; ret`） | 被挂钩 API 看到的返回地址属于真实模块（实测绕过了"无后备内存调用"判定） |
| bundle 预映射（**不调用其 DllMain**） | 这是 ACE 场景下最关键的一条：调用 `nvngx_dlssg.dll` 的 DllMain 会被终止 |

## 4. 实测结论汇总

| 检测面 | 结果 |
|---|---|
| 内核 `PsSetLoadImageNotifyRoutine` | 不触发 ✅ |
| PEB / Toolhelp32 模块枚举 | 无条目 ✅ |
| 游戏目录磁盘文件 | 零文件 ✅ |
| 内存 PE 结构 | 已抹除 ✅ |
| 被挂钩 API 调用（`CreateFileW`） | 通过 ✅ |
| 加载未签名 DLL（跳板修复后） | 通过 ✅ |
| 空闲 CPU（15 s） | **0 ms** ✅ |
| 真实游戏注入 | 成功、稳定 45 s+ ✅ |
| ACE 游戏：磁盘替换 `nvngx_dlssg.dll` | 游戏存活 45 s+，ACE 无反应 ✅ |

## 5. ACE 的四道封锁（以及我们如何应对）

| ACE 会终止的行为 | 本项目的应对 |
|---|---|
| 对已挂钩函数代码页的写权限变更 / 写入 | 不用内联钩子（磁盘替换路径也不需要） |
| 对游戏自身 IAT（数据页）的写入 | 不改 IAT |
| 从无后备内存发起被挂钩 API 调用 | **合法模块跳板**（已验证绕过） |
| 调用 `nvngx_dlssg.dll` 的 `DllMain` | 预映射时**不调用入口**（已验证绕过） |

## 6. 复现

见 `README.md`（用法）与 `docs/VERIFICATION.md`（22 节实测记录，每节含可复现的实验设计与输出）。
