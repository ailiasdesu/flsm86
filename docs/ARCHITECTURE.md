# 架构与隐身原理

## 为什么"代理 DLL"会被检测

上游 mod 的工作方式是把 `version.dll` 放在游戏目录，由游戏进程 `LoadLibrary` 加载。
这会留下三类可观测痕迹：

1. **内核镜像加载通知** — `ACE-BOOT.sys` 等反作弊驱动注册 `PsSetLoadImageNotifyRoutine`，
   任何 `LoadImage` 都会带上映像路径回调给内核；
2. **模块枚举** — 模块进入 PEB 链表，Toolhelp32/PSAPI/PEB 都能看到；
3. **磁盘文件** — 游戏目录里多出 `version.dll` 与 `dlssg_sm86.ini`。

## 本注入器如何规避

### 1. 事件驱动监视（零轮询）

```
IWbemLocator -> ConnectServer(ROOT\CIMV2)
  -> ExecNotificationQueryAsync("SELECT * FROM Win32_ProcessStartTrace")
```

进程创建时由 WMI 推送事件，服务自身不做任何轮询。
实测空闲 15 秒 CPU 时间增量 **0 ms**（轮询回退版本实测 74% 单核，已废弃）。

### 2. 目标判定

沿新进程 exe 的父目录向上（≤4 层）查找 `nvngx_dlssg.dll`，并排除系统路径
（`C:\Windows`、`DriverStore`、`WinSxS`、`AppData`、mod 自身缓存 `DlssgSm86\bundles`）。
目录扫描有预算限制（深度 ≤5 / 单目录 ≤400 项 / 单次 ≤3000 目录），避免大目录拖慢系统。

### 3. 手动映射（不经过 Loader）

```
VirtualAllocEx(首选基址) → 写头部/节 → 应用重定位 → 解析导入表
  → 抹除 MZ/PE 签名 → 逐节设置保护属性
```

- **不调用 `LoadLibrary`/`LdrLoadDll`/`NtMapViewOfSection(SEC_IMAGE)`** ⇒ 内核 `LoadImage` 通知不触发；
- 映射区为 `MEM_PRIVATE`，`GetMappedFileName` 返回空 ⇒ 不是文件映射；
- 抹头后内存中没有完整 PE 结构。

### 4. 导入解析的两个关键点

- **依赖必须在目标进程内加载**：先用远程线程让目标 `LoadLibraryA` 依赖，
  再按"目标基址 + 本地解析出的导出 RVA"重算地址（不能直接写服务进程里的地址）；
- **转发器**：`kernel32` 的导出多为 `jmp [IAT]` 转发桩，
  RVA 落在导出目录范围内时必须识别为 `DLL.Func` 二次解析。

### 5. TLS

载荷若有 TLS 目录：在目标内 `TlsAlloc`，写入 TLS 模板，并在执行入口的桩里
为当前线程设置 TLS 槽（**必须先判空 `gs:[0x58]`**，线程从未用过 TLS 时该指针为 NULL）。

### 6. 入口执行：线程劫持 + NtContinue

`CreateRemoteThread` 用裸内存地址作起始函数时，ntdll 的函数表查询会失败（崩溃）。
因此改为：

```
SuspendThread(目标线程) → 保存 CONTEXT → 新栈 + RIP=桩
  → ResumeThread → 桩内：LdrLockLoaderLock(TRY_ONLY) → DllMain → 解锁
  → NtContinue(原始 CONTEXT)  // 无缝还原该线程
```

- 必须用 **TRY_ONLY**：劫持的线程自身可能持有加载器锁，等待会自死锁；
- 桩的尾部用 `NtContinue` 而不是 `ret`，被劫持线程的寄存器/栈完全恢复。

### 7. 临时 PEB 表项（让复杂 CRT 正常初始化）

复杂载荷（完整 CRT）的 `DllMain` 会触发 ntdll 的模块查找，
手动映射的映像不在模块表里 → 崩在 `ntdll!SbSelectProcedure`。

解法：**DllMain 期间临时把模块挂进 PEB 三个链表，DllMain 返回后立刻摘除**。

```
AddTempPebEntry()  → LDR_DATA_TABLE_ENTRY + UNICODE_STRING，挂到
                     InLoadOrder / InMemoryOrder / InInitializationOrder 三个链表头
DllMain(...)       → CRT 正常初始化
UnlinkFromPeb()    → 三个链表摘除（最终无模块可见性）
```

这样既**不触发内核 LoadImage 通知**，最终也**不留下模块条目**。

## 已知边界

- 手动映射不提供完整的加载器环境；极端依赖加载器内部状态的载荷仍可能失败
  （本项目通过"临时 PEB 表项 + 加载器锁 + TLS"覆盖了上游 `version.dll` 的实测需求）；
- 反作弊是持续对抗：本方案消除的是"加载行为与静态特征"，不是"运行期行为审计"。
  实测记录见 `VERIFICATION.md`。
