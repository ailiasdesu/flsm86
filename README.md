# FLSm86 — 全局自动隐身注入器（DLSS 帧生成 · SM86/Ampere）

> 一次安装，自动为**所有支持 DLSS 帧生成的游戏**注入上游 mod 的运行时。
> 注入过程：**不产生内核镜像加载通知、不在游戏目录留下任何文件、不留模块可见性、不常驻轮询**。

## 这是什么

[dlssg_for_sm86](https://github.com/sdli1995/dlssg_for_sm86) 让 Ampere（RTX 30 系 / SM86）能用 DLSS 帧生成，
但它的原始用法是**把 `version.dll` 代理 DLL 复制到每个游戏目录**——需要主 EXE 导入 `VERSION.dll`/`WINMM.dll`，
会触发内核镜像加载通知，且留下磁盘文件。

本项目把它改造成**全局注入器**：

| 维度 | 上游代理方式 | 本注入器 |
|---|---|---|
| 部署 | 每个游戏目录手工放 DLL | 一次安装，自动覆盖所有游戏 |
| 游戏要求 | 主 EXE 必须导入 version/winmm.dll | **无要求** |
| 磁盘痕迹 | 游戏目录里有 DLL + ini | **游戏目录零文件** |
| 内核镜像加载通知 | 触发 | **不触发**（手动映射，不走 Loader） |
| 模块枚举（PEB/Toolhelp32） | 可见 | **不可见** |
| 常驻开销 | — | 事件驱动，实测空闲 **0 ms CPU / 15 s** |

## 工作原理（详见 `docs/ARCHITECTURE.md`）

```
① 监视：WMI Win32_ProcessStartTrace（系统推送，自身零轮询）
② 判定：沿新进程 exe 的父目录向上查找 nvngx_dlssg.dll（UE/Streamline 布局走快查路径）
③ 注入（全隐身手动映射）：
     · 载荷 XTEA-CTR 加密存放，仅在内存中解密
     · VirtualAllocEx + 写节 + 重定位 + 解析导入（含转发器）
     · 抹除 MZ/PE 头
     · 临时插入 PEB 表项让复杂 CRT 的 DllMain 正常初始化，返回后立刻摘除
     · 入口在线程劫持的线程上执行，执行完 NtContinue 无缝还原
     · API 调用经"合法模块内的跳板"发起（含栈对齐修正）
     · 预映射 payload 自带的 bundle，并拦截其 LoadLibrary 导入
④ 结果：不调用 LoadLibrary ⇒ 无内核 LoadImage 通知；无 PEB 残留；无磁盘文件
```

## 用法

```bat
:: 1) 编译（需要 VS2022 + Windows SDK）
tools\build.bat

:: 2) 打包载荷（用你自己合法持有的 version.dll）
bin\flsm86_svc.exe --pack <你的 version.dll> %LOCALAPPDATA%\FlSm86\proxy\payload.enc

:: 3) 空跑一次，看会命中哪些游戏
bin\flsm86_svc.exe --once --dry

:: 4) 常驻（需要管理员：WMI 事件订阅 + 跨进程注入）
bin\flsm86_svc.exe --run --log %LOCALAPPDATA%\FlSm86\svc.log

:: 5) 开机自启（可选）
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

## 实测结论（详见 `docs/VERIFICATION.md`）

| 检测面 | 结果 |
|---|---|
| 内核 `PsSetLoadImageNotifyRoutine` | **不触发** |
| PEB / Toolhelp32 模块枚举 | **无条目** |
| 游戏目录磁盘文件 | **零文件** |
| 内存 PE 结构 | **已抹除** |
| ACE 挂钩 API 调用（`CreateFileW`） | **通过** |
| 空载荷 / 基础 API 载荷 | **通过** |
| 空闲 CPU（15 s） | **0 ms** |
| 真实游戏（《异环》10.5 MB payload）注入 | 注入成功、目标稳定 |

### 已知边界

- 上游 payload 的**内联钩子（Detours）**会被带内核代码完整性校验的反作弊（如 ACE）拦截——
  这是 payload 自身行为，与注入方式无关（本仓库已用"预映射 + LoadLibrary 拦截"绕过其**未签名 DLL 加载**，
  但钩子改写被保护代码页无法在用户态绕过）。
- 因此：本注入器适用于**没有内核级反作弊的游戏**；带内核反作弊的游戏需改造 payload 自身。

## 重要说明

- **本仓库不包含任何 NVIDIA 二进制**（`nvngx_dlssg.dll`、重编译内核等）。
  载荷由使用者自行 `--pack`，请确保你合法持有并遵守上游与 NVIDIA 的条款。
- 本项目**源码**遵循 **GPL-3.0-or-later**，见 `LICENSE`；来源与合规见 `NOTICE.md`。
