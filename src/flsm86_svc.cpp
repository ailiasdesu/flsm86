// flsm86_svc.cpp — FlSm86 全局注入服务
//
// 目标：装一次，所有支持 DLSS 帧生成的游戏自动生效，且不在游戏目录放任何文件。
//
// 工作方式：
//   1) 每 500ms 快照进程列表（Toolhelp32）
//   2) 对新进程取 exe 路径，向上逐级查找 nvngx_dlssg.dll（带缓存）→ 判定"支持帧生成"
//   3) 命中则把加密载荷手动映射进目标进程（不调用 LoadLibrary）
//        - 不产生内核 LoadImage 通知
//        - 不插入 PEB 模块链表（可选 --peb-entry 回退）
//        - 抹掉映射后的 MZ/PE 头
//   4) 记录已注入 PID，避免重复
//
// 用法：
//   flsm86_svc.exe --run  [--payload <file.enc>] [--roots <dir>] [--peb-entry] [--dry]
//   flsm86_svc.exe --pack <in.dll> <out.enc>
//   flsm86_svc.exe --once           仅扫描一次并列出目标，不注入

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <stdarg.h>

static std::wstring g_logFileFwd;
static void LOG(const char* fmt, ...);
static ULONG_PTR ResolveRemoteExport(HANDLE hProc, const char* module, const char* name);
static ULONG_PTR AddTempPebEntry(HANDLE hProc, ULONG_PTR base, ULONG_PTR entryPoint,
                                 SIZE_T sizeOfImage, const std::wstring& dllPath);
static bool UnlinkFromPeb(HANDLE hProc, ULONG_PTR moduleBase);
static ULONG_PTR GetRemotePeb(HANDLE hProc);
static bool g_forceReloc;   // 强制非首选基址（验证重定位路径）
static bool g_stomp;        // 模块踩踏：把载荷放进已加载模块的空白区
static bool g_blockProtect = false;   // 拦截载荷的 VirtualProtect（阻止它装内联钩子）

#pragma comment(lib, "psapi.lib")

// ============================ XTEA-CTR ============================
static const uint32_t KEY[4] = { 0x534D3836, 0x5F646C73, 0x00000067, 0x00000000 };
static void xtea_block(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
    for (int i = 0; i < 32; ++i) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
    v[0] = v0; v[1] = v1;
}
static void xcrypt(uint8_t* d, size_t n, uint64_t nonce) {
    for (size_t off = 0; off < n; off += 8) {
        uint32_t blk[2] = { (uint32_t)(nonce + off / 8), (uint32_t)((nonce + off / 8) >> 32) };
        xtea_block(blk, KEY);
        size_t m = (n - off < 8) ? (n - off) : 8;
        for (size_t i = 0; i < m; ++i) d[off + i] ^= ((uint8_t*)blk)[i];
    }
}

// ============================ 工具 ============================
static std::vector<BYTE> ReadAll(const std::wstring& path) {
    std::vector<BYTE> d;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return d;
    LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
    d.resize((size_t)sz.QuadPart);
    DWORD rd = 0; ReadFile(h, d.data(), (DWORD)d.size(), &rd, nullptr);
    CloseHandle(h); d.resize(rd);
    return d;
}
static std::wstring DirName(const std::wstring& p) {
    size_t k = p.find_last_of(L"\\/");
    return k == std::wstring::npos ? L"" : p.substr(0, k);
}
static std::wstring JoinPath(const std::wstring& a, const wchar_t* b) {
    if (a.empty()) return b;
    wchar_t last = a[a.size() - 1];
    return a + ((last == L'\\' || last == L'/') ? L"" : L"\\") + b;
}
static bool FileExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

// 系统路径排除（驱动仓库里也有 nvngx_dlssg.dll，不能算游戏）
static bool IsSystemPath(const std::wstring& p) {
    wchar_t win[MAX_PATH] = {0};
    GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring w = win, lp = p;
    for (auto& c : w) c = towlower(c);
    for (auto& c : lp) c = towlower(c);
    if (!w.empty() && lp.rfind(w, 0) == 0) return true;                     // C:\Windows\...
    if (lp.find(L"\\driverstore\\") != std::wstring::npos) return true;
    if (lp.find(L"\\winsxs\\") != std::wstring::npos) return true;
    if (lp.find(L"\\$recycle.bin\\") != std::wstring::npos) return true;
    if (lp.find(L"\\dlssgsm86\\") != std::wstring::npos) return true;   // mod 自己的 bundle 缓存
    if (lp.find(L"\\appdata\\") != std::wstring::npos) return true;      // 用户数据目录，不是游戏
    if (lp.find(L"\\programdata\\") != std::wstring::npos) return true;
    if (lp.find(L"\\windowsapps\\") != std::wstring::npos) return true;
    return false;
}

// 递归找 nvngx_dlssg.dll（带缓存，避免每进程重复扫盘）
static std::map<std::wstring, bool> g_fgCache;
static std::wstring g_lastHit;
static int g_scanBudget = 0;          // 单次检测的目录访问预算（防大目录拖慢 CPU）

static bool FindFrameGenRec(const std::wstring& dir, int depth) {
    if (depth > 5) return false;                       // 深度上限
    if (g_scanBudget <= 0) return false;               // 预算耗尽
    if (IsSystemPath(dir)) return false;
    g_scanBudget--;
    {
        std::wstring f = JoinPath(dir, L"nvngx_dlssg.dll");
        if (FileExists(f)) { g_lastHit = f; return true; }
    }
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(JoinPath(dir, L"*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool found = false;
    int entries = 0;
    do {
        if (++entries > 400) break;                    // 单目录条目上限
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        if (_wcsicmp(fd.cFileName, L"DriverStore") == 0 || _wcsicmp(fd.cFileName, L"WinSxS") == 0) continue;
        if (FindFrameGenRec(JoinPath(dir, fd.cFileName), depth + 1)) { found = true; break; }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return found;
}
// 从 exe 目录向上逐级找（游戏根目录通常在上层）
static bool HasFrameGen(const std::wstring& exeDir, std::wstring* rootOut) {
    // 快查：UE / Streamline 常见布局（避免在大目录树上耗尽预算）
    static const wchar_t* kFastPaths[] = {
        L"Engine\\Plugins\\Runtime\\Nvidia\\StreamlineCore\\Binaries\\ThirdParty\\Win64\\nvngx_dlssg.dll",
        L"Engine\\Binaries\\ThirdParty\\Win64\\nvngx_dlssg.dll",
        L"nvngx_dlssg.dll",
        L"bin\\nvngx_dlssg.dll",
        L"binaries\\win64\\nvngx_dlssg.dll",
    };
    {
        std::wstring probe = exeDir;
        for (int up = 0; up < 6 && probe.size() > 4; ++up) {
            for (const wchar_t* fp : kFastPaths) {
                std::wstring cand = JoinPath(probe, fp);
                if (FileExists(cand)) { g_lastHit = cand; if (rootOut) *rootOut = probe; return true; }
            }
            std::wstring up2 = DirName(probe);
            if (up2 == probe) break;
            probe = up2;
        }
    }

    g_scanBudget = 20000;                              // 递归兜底预算
    std::wstring cur = exeDir;
    for (int i = 0; i < 4 && cur.size() > 4; ++i) {
        auto it = g_fgCache.find(cur);
        bool hit;
        if (it != g_fgCache.end()) hit = it->second;
        else { hit = FindFrameGenRec(cur, 0); g_fgCache[cur] = hit; }
        if (hit) { if (rootOut) *rootOut = cur; return true; }
        std::wstring up = DirName(cur);
        if (up == cur) break;
        cur = up;
    }
    return false;
}

// ============================ 远程手动映射 ============================
struct Mapped { void* base = nullptr; SIZE_T size = 0; bool ok = false; };

static DWORD RvaToOff(IMAGE_NT_HEADERS64* nt, DWORD rva) {
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++s) {
        DWORD sz = s->Misc.VirtualSize; if (sz < s->SizeOfRawData) sz = s->SizeOfRawData;
        if (rva >= s->VirtualAddress && rva < s->VirtualAddress + sz)
            return rva - s->VirtualAddress + s->PointerToRawData;
    }
    return 0;
}

// 在目标进程里调用一个"无参、返回 DWORD"的 API（用退出码取结果）
static DWORD CallRemoteDword(HANDLE hProc, const char* k32name) {
    LPTHREAD_START_ROUTINE fn = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), k32name);
    if (!fn) return 0xFFFFFFFF;
    HANDLE th = CreateRemoteThread(hProc, nullptr, 0, fn, nullptr, 0, nullptr);
    if (!th) return 0xFFFFFFFF;
    WaitForSingleObject(th, 15000);
    DWORD ec = 0; GetExitCodeThread(th, &ec);
    CloseHandle(th);
    return ec;
}

// 手动映射的 TLS 初始化：分配索引、写 TLS 模板、返回 (index, block)
static bool SetupRemoteTls(HANDLE hProc, void* base, IMAGE_NT_HEADERS64* nt,
                           const std::vector<BYTE>& file, DWORD* outIndex, ULONG_PTR* outBlock) {
    IMAGE_DATA_DIRECTORY td = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!td.Size) return false;
    DWORD off = RvaToOff(nt, td.VirtualAddress);
    if (!off || off + sizeof(IMAGE_TLS_DIRECTORY64) > file.size()) return false;
    IMAGE_TLS_DIRECTORY64 tls;
    memcpy(&tls, file.data() + off, sizeof(tls));

    DWORD idx = CallRemoteDword(hProc, "TlsAlloc");
    if (idx == 0xFFFFFFFF) { printf("      !! TlsAlloc 失败\n"); return false; }

    DWORD rawSize = (DWORD)(tls.EndAddressOfRawData - tls.StartAddressOfRawData);
    SIZE_T total = rawSize + tls.SizeOfZeroFill;
    if (total == 0) total = 8;
    void* block = VirtualAllocEx(hProc, nullptr, total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!block) return false;
    if (rawSize) {
        DWORD roff = RvaToOff(nt, (DWORD)(tls.StartAddressOfRawData - nt->OptionalHeader.ImageBase));
        if (roff && roff + rawSize <= file.size())
            WriteProcessMemory(hProc, block, file.data() + roff, rawSize, nullptr);
    }
    // AddressOfIndex 指向映像里的一个 DWORD，写入索引
    ULONG_PTR idxAddr = (ULONG_PTR)base + (DWORD)(tls.AddressOfIndex - nt->OptionalHeader.ImageBase);
    WriteProcessMemory(hProc, (LPVOID)idxAddr, &idx, sizeof(idx), nullptr);

    *outIndex = idx;
    *outBlock = (ULONG_PTR)block;
    printf("      TLS: index=%lu block=%p raw=%lu zero=%lu\n", idx, block, rawSize, tls.SizeOfZeroFill);
    return true;
}

// 写 APC 桩：加加载器锁 -> DllMain -> 解锁 -> 置标志 -> ret（APC 执行完线程自然继续）
static void* WriteApcStub(HANDLE hProc, void* imageBase, void* entry, void* flagAddr, void* cookieAddr,
                          DWORD tlsIndex, ULONG_PTR tlsBlock) {
    unsigned char code[256]; size_t n = 0;
    auto emit = [&](std::initializer_list<unsigned char> b) { for (auto x : b) code[n++] = x; };
    auto emit64 = [&](std::initializer_list<unsigned char> op, uint64_t imm) {
        for (auto x : op) code[n++] = x;
        memcpy(code + n, &imm, 8); n += 8;
    };
    // 先给"当前线程"补 TLS 槽（载荷若用 __declspec(thread) 才不会崩）
    if (tlsIndex != 0xFFFFFFFF && tlsBlock) {
        // TEB->ThreadLocalStoragePointer 可能为 NULL（线程从未用过 TLS）——必须先判空
        emit({ 0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00 });   // mov rax,gs:[0x58]
        emit({ 0x48, 0x85, 0xC0 });                                       // test rax,rax
        emit({ 0x74, 0x13 });                                             // jz +12 (跳过)
        emit({ 0xB9 }); uint32_t vi = tlsIndex; memcpy(code + n, &vi, 4); n += 4;  // mov ecx,index
        emit64({ 0x48, 0xBA }, (uint64_t)tlsBlock);                       // mov rdx,block
        emit({ 0x48, 0x89, 0x14, 0xC8 });                                 // mov [rax+rcx*8],rdx
    }
    ULONG_PTR lockFn = ResolveRemoteExport(hProc, "ntdll.dll", "LdrLockLoaderLock");
    ULONG_PTR unlockFn = ResolveRemoteExport(hProc, "ntdll.dll", "LdrUnlockLoaderLock");

    if (lockFn && unlockFn) {
        emit({ 0xB9, 0x01, 0x00, 0x00, 0x00 });                       // mov ecx,1 (TRY_ONLY)
        emit64({ 0x48, 0xBA }, (uint64_t)cookieAddr + 8);             // mov rdx,&disposition
        emit64({ 0x49, 0xB8 }, (uint64_t)cookieAddr);                 // mov r8,&cookie
        emit64({ 0x48, 0xB8 }, lockFn);                               // mov rax,lock
        emit({ 0xFF, 0xD0 });                                         // call rax
    }
    emit64({ 0x48, 0xB9 }, (uint64_t)imageBase);                      // mov rcx,base
    emit({ 0xBA, 0x01, 0x00, 0x00, 0x00 });                           // mov edx,1
    emit({ 0x45, 0x33, 0xC0 });                                       // xor r8d,r8d
    emit64({ 0x48, 0xB8 }, (uint64_t)entry);                          // mov rax,entry
    emit({ 0xFF, 0xD0 });                                             // call rax
    if (lockFn && unlockFn) {
        emit64({ 0x48, 0xB8 }, (uint64_t)cookieAddr + 8);             // mov rax,&disposition
        emit({ 0x48, 0x8B, 0x00 });                                   // mov rax,[rax]
        emit({ 0x48, 0x83, 0xF8, 0x01 });                             // cmp rax,1
        emit({ 0x75, 0x10 });                                         // jne +16
        emit({ 0x33, 0xC9 });                                         // xor ecx,ecx
        emit64({ 0x48, 0xBA }, (uint64_t)cookieAddr);                 // mov rdx,&cookie
        emit({ 0x48, 0x8B, 0x12 });                                   // mov rdx,[rdx]
        emit64({ 0x48, 0xB8 }, unlockFn);                             // mov rax,unlock
        emit({ 0xFF, 0xD0 });                                         // call rax
    }
    emit64({ 0x48, 0xB8 }, (uint64_t)flagAddr);                       // mov rax,flag
    emit({ 0xC7, 0x00, 0x4D, 0x53, 0x4C, 0x46 });                     // mov dword [rax],'MSLF'
    emit({ 0xC3 });                                                   // ret

    void* mem = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;
    if (!WriteProcessMemory(hProc, mem, code, n, nullptr)) return nullptr;
    return mem;
}

// ============================ APC 注入（比线程劫持安全） ============================
// 把桩作为 APC 排入目标的所有线程：线程从"可警告等待"返回时执行桩，执行完自然继续，
// 不需要修改任何线程上下文（线程劫持会破坏被挂起线程的内核态）。
static bool RunViaApc(HANDLE hProc, DWORD pid, void* stubAddr, void* flagAddr) {
    // 先清零标志
    DWORD zero = 0;
    WriteProcessMemory(hProc, flagAddr, &zero, sizeof(zero), nullptr);

    std::vector<DWORD> tids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; ZeroMemory(&te, sizeof(te)); te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) tids.push_back(te.th32ThreadID);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    if (tids.empty()) { LOG("      !! 目标没有可排 APC 的线程\n"); return false; }

    int queued = 0;
    for (DWORD tid : tids) {
        HANDLE ht = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
        if (!ht) continue;
        if (QueueUserAPC((PAPCFUNC)stubAddr, ht, 0)) queued++;
        CloseHandle(ht);
    }
    LOG("      已向 %d/%zu 个线程排入 APC，等待执行...\n", queued, tids.size());
    if (!queued) return false;

    // 等待桩执行（最多 10 秒）
    for (int i = 0; i < 100; ++i) {
        DWORD flag = 0;
        if (ReadProcessMemory(hProc, flagAddr, &flag, sizeof(flag), nullptr) && flag == 0x464C534D) {
            LOG("      桩已在目标线程执行（APC）\n");
            return true;
        }
        Sleep(100);
    }
    LOG("      !! 等待 APC 执行超时（线程可能都不在可警告等待）\n");
    return false;
}

// 线程劫持执行：在目标"自己的线程"上跑桩，执行完用 NtContinue 还原该线程
// （避开 CreateRemoteThread 裸内存起始地址导致 ntdll 函数表查询失败的问题）
static bool RunOnHijackedThread(HANDLE hProc, DWORD pid, void* stubAddr) {
    DWORD tid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; ZeroMemory(&te, sizeof(te)); te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    if (!tid) { printf("      !! 找不到可劫持的线程\n"); return false; }
    HANDLE ht = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!ht) { printf("      !! OpenThread 失败 %lu\n", GetLastError()); return false; }

    SuspendThread(ht);
    CONTEXT ctx; ZeroMemory(&ctx, sizeof(ctx)); ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(ht, &ctx)) { ResumeThread(ht); CloseHandle(ht); return false; }

    // 把原始 CONTEXT 写到目标里，供 NtContinue 还原
    void* ctxRemote = VirtualAllocEx(hProc, nullptr, sizeof(CONTEXT),
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!ctxRemote) { ResumeThread(ht); CloseHandle(ht); return false; }
    WriteProcessMemory(hProc, ctxRemote, &ctx, sizeof(ctx), nullptr);

    ULONG_PTR ntContinue = ResolveRemoteExport(hProc, "ntdll.dll", "NtContinue");
    if (!ntContinue) { ResumeThread(ht); CloseHandle(ht); return false; }

    // 关键：必须用"线程自己的栈"，不能用新分配的栈。
    // ACE 的钩子会检查调用方栈指针是否落在线程栈范围内（TEB StackBase/StackLimit），
    // 用外部栈会被判定为异常调用。
    ULONG_PTR sp = (ctx.Rsp - 0x2000) & ~(ULONG_PTR)0xF;
    // 校验是否在线程栈范围内（TEB 0x08=StackBase, 0x10=StackLimit）
    {
        ULONG_PTR teb = 0;
        typedef NTSTATUS(NTAPI* pNtQIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        static pNtQIT qit = (pNtQIT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
        struct { NTSTATUS ExitStatus; PVOID TebBaseAddress; PVOID UniqueProcess; PVOID UniqueThread; } tbi{};
        if (qit && qit(ht, 0, &tbi, sizeof(tbi), nullptr) == 0) teb = (ULONG_PTR)tbi.TebBaseAddress;
        ULONG_PTR stackBase = 0, stackLimit = 0;
        if (teb) {
            ReadProcessMemory(hProc, (LPCVOID)(teb + 0x08), &stackBase, sizeof(stackBase), nullptr);
            ReadProcessMemory(hProc, (LPCVOID)(teb + 0x10), &stackLimit, sizeof(stackLimit), nullptr);
        }
        if (stackLimit && sp < stackLimit) sp = (stackLimit + 0x1000) & ~(ULONG_PTR)0xF;   // 越界则回落到栈内
        LOG("      使用线程栈: RSP=%p (栈范围 %p..%p)\n", (void*)sp, (void*)stackLimit, (void*)stackBase);
    }

    // 桩尾部：NtContinue(原 CONTEXT, FALSE) —— 无缝恢复该线程
    BYTE* code = (BYTE*)stubAddr;
    BYTE tail[96]; size_t tn = 0;
    auto emit = [&](std::initializer_list<unsigned char> b) { for (auto x : b) tail[tn++] = x; };
    emit({ 0x48, 0xB9 }); uint64_t c0 = (uint64_t)ctxRemote; memcpy(tail + tn, &c0, 8); tn += 8;   // mov rcx, ctx
    emit({ 0x33, 0xD2 });                                                                            // xor edx,edx
    emit({ 0x48, 0xB8 }); uint64_t c1 = ntContinue;          memcpy(tail + tn, &c1, 8); tn += 8;   // mov rax, NtContinue
    emit({ 0xFF, 0xE0 });                                                                            // jmp rax
    WriteProcessMemory(hProc, code + 0x800, tail, tn, nullptr);   // 桩区域预留 0x1000，尾部放还原代码

    // 改写桩：先调 DllMain，再跳到尾部还原
    ctx.Rip = (ULONG_PTR)stubAddr;
    ctx.Rsp = sp;
    if (!SetThreadContext(ht, &ctx)) { ResumeThread(ht); CloseHandle(ht); return false; }
    ResumeThread(ht);
    CloseHandle(ht);
    printf("      已在劫持线程 tid=%lu 上执行（执行后自动还原）\n", tid);
    return true;
}

// 在目标进程里写一段桩：设置本线程 TLS 槽 -> 调用 DllMain(base, DLL_PROCESS_ATTACH, 0)
static bool WriteEntryStub(HANDLE hProc, void* imageBase, void* entry, void** stubOut,
                           DWORD tlsIndex, ULONG_PTR tlsBlock) {
    unsigned char code[128];
    size_t n = 0;
    auto emit = [&](std::initializer_list<unsigned char> b) { for (auto x : b) code[n++] = x; };
    // 只有镜像真的有 TLS 目录时才设置 TLS 槽（否则会写野地址 -> AV）
    if (tlsIndex != 0xFFFFFFFF && tlsBlock) {
        emit({ 0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00 });   // mov rax,gs:[0x58]
        emit({ 0x48, 0x85, 0xC0 });                                       // test rax,rax
        emit({ 0x74, 0x13 });                                             // jz +12
        emit({ 0xB9 }); uint32_t vi = tlsIndex; memcpy(code + n, &vi, 4); n += 4;
        emit({ 0x48, 0xBA }); uint64_t vb = tlsBlock; memcpy(code + n, &vb, 8); n += 8;
        emit({ 0x48, 0x89, 0x14, 0xC8 });                                 // mov [rax+rcx*8],rdx
    }
    // ---- LdrLockLoaderLock(0, NULL, &cookie) ----
    ULONG_PTR lockFn = ResolveRemoteExport(hProc, "ntdll.dll", "LdrLockLoaderLock");
    ULONG_PTR unlockFn = ResolveRemoteExport(hProc, "ntdll.dll", "LdrUnlockLoaderLock");
    ULONG_PTR cookieAddr = 0;
    if (lockFn && unlockFn) {
        // 结构：{cookie, disposition}
        void* ck = VirtualAllocEx(hProc, nullptr, 0x100, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        cookieAddr = (ULONG_PTR)ck;
        // LdrLockLoaderLock(TRY_ONLY, &disposition, &cookie) —— 必须用 TRY_ONLY：
        // 劫持的线程自己可能正持有加载器锁，等待会自死锁
        emit({ 0xB9, 0x01, 0x00, 0x00, 0x00 });             // mov ecx, 1 (TRY_ONLY)
        emit({ 0x48, 0xBA }); uint64_t vd = cookieAddr + 8; memcpy(code + n, &vd, 8); n += 8; // mov rdx, &disposition
        emit({ 0x49, 0xB8 }); uint64_t vc = cookieAddr;     memcpy(code + n, &vc, 8); n += 8; // mov r8, &cookie
        emit({ 0x48, 0xB8 }); uint64_t vf = lockFn;         memcpy(code + n, &vf, 8); n += 8; // mov rax, LdrLockLoaderLock
        emit({ 0xFF, 0xD0 });                               // call rax
    }
    // ---- DllMain(base, DLL_PROCESS_ATTACH, 0) ----
    emit({ 0x48, 0xB9 }); uint64_t v1 = (uint64_t)imageBase; memcpy(code + n, &v1, 8); n += 8;
    emit({ 0xBA, 0x01, 0x00, 0x00, 0x00 });
    emit({ 0x45, 0x33, 0xC0 });
    emit({ 0x48, 0xB8 }); uint64_t v2 = (uint64_t)entry;     memcpy(code + n, &v2, 8); n += 8;
    emit({ 0xFF, 0xD0 });                                   // call DllMain
    // ---- LdrUnlockLoaderLock(0, cookie) ----
    if (lockFn && unlockFn) {
        // 仅当 disposition == 1（成功获取）才解锁
        emit({ 0x48, 0xA1 }); uint64_t vd2 = cookieAddr + 8; memcpy(code + n, &vd2, 8); n += 8; // mov rax,[disposition]
        emit({ 0x48, 0x83, 0xF8, 0x01 });                   // cmp rax, 1
        emit({ 0x75, 0x16 });                               // jne +22 (跳过解锁：2+8+10+2)
        emit({ 0x33, 0xC9 });                               // xor ecx,ecx
        emit({ 0x48, 0x8B, 0x14, 0x25 });                   // mov rdx, [abs32]
        uint32_t ca = (uint32_t)cookieAddr; memcpy(code + n, &ca, 4); n += 4;
        emit({ 0x48, 0xB8 }); uint64_t vf2 = unlockFn;  memcpy(code + n, &vf2, 8); n += 8;
        emit({ 0xFF, 0xD0 });                               // call rax
    }
    // 跳转到 +0x800 的还原尾（NtContinue 恢复被劫持线程），不返回
    emit({ 0x48, 0xB8 }); uint64_t vj = (uint64_t)stubOut + 0x800; memcpy(code + n, &vj, 8); n += 8;
    emit({ 0xFF, 0xE0 });

    void* mem = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem) return false;
    if (!WriteProcessMemory(hProc, mem, code, n, nullptr)) return false;
    // 诊断：确认桩的地址、保护属性与内容
    MEMORY_BASIC_INFORMATION mi; ZeroMemory(&mi, sizeof(mi));
    VirtualQueryEx(hProc, mem, &mi, sizeof(mi));
    BYTE back[16] = {0};
    ReadProcessMemory(hProc, mem, back, 16, nullptr);
    LOG("      [stub] addr=%p protect=0x%lX state=%lu type=%lu bytes=%02X %02X %02X %02X (len=%zu)\n",
        mem, mi.Protect, mi.State, mi.Type, back[0], back[1], back[2], back[3], n);
    *stubOut = mem;
    return true;
}

// 导出解析结果：可能是普通函数 RVA，也可能是转发器（forwarder: "DLL.Func"）
struct ExportRef {
    bool ok = false;
    bool forwarder = false;
    ULONG_PTR rva = 0;
    char fwdDll[64] = {0};
    char fwdFunc[128] = {0};
};

static ExportRef GetExportRef(HMODULE mod, const char* name, WORD ordinal) {
    ExportRef r;
    if (!mod) return r;
    BYTE* b = (BYTE*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return r;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(b + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.Size) return r;
    IMAGE_EXPORT_DIRECTORY* ex = (IMAGE_EXPORT_DIRECTORY*)(b + ed.VirtualAddress);
    DWORD* funcs = (DWORD*)(b + ex->AddressOfFunctions);
    DWORD rva = 0;
    if (name) {
        DWORD* names = (DWORD*)(b + ex->AddressOfNames);
        WORD* ords = (WORD*)(b + ex->AddressOfNameOrdinals);
        for (DWORD i = 0; i < ex->NumberOfNames; ++i) {
            if (strcmp((char*)(b + names[i]), name) == 0) {
                WORD o = ords[i];
                if (o < ex->NumberOfFunctions) rva = funcs[o];
                break;
            }
        }
    } else if (ordinal >= ex->Base) {
        DWORD idx = ordinal - ex->Base;
        if (idx < ex->NumberOfFunctions) rva = funcs[idx];
    }
    if (!rva) return r;
    r.ok = true;
    // RVA 落在导出目录范围内 => 转发器字符串 "DLL.Func"
    if (rva >= ed.VirtualAddress && rva < ed.VirtualAddress + ed.Size) {
        const char* fwd = (const char*)(b + rva);
        const char* dot = strchr(fwd, '.');
        if (dot) {
            size_t dl = (size_t)(dot - fwd);
            if (dl < sizeof(r.fwdDll) - 5) {
                memcpy(r.fwdDll, fwd, dl);
                r.fwdDll[dl] = 0;
                strncat(r.fwdDll, ".dll", sizeof(r.fwdDll) - dl - 1);
                strncpy(r.fwdFunc, dot + 1, sizeof(r.fwdFunc) - 1);
                r.forwarder = true;
            }
        }
        return r;
    }
    r.rva = rva;
    return r;
}

// 在目标进程里确保某 DLL 已加载，返回它在目标地址空间里的基址
static ULONG_PTR EnsureRemoteModule(HANDLE hProc, const char* dllName) {
    // 先查目标已有模块
    HMODULE mods[1024]; DWORD need = 0;
    BOOL ok = EnumProcessModulesEx(hProc, mods, sizeof(mods), &need, LIST_MODULES_ALL);
    if (ok) {
        DWORD cnt = need / sizeof(HMODULE);
        if (cnt > 1024) cnt = 1024;
        for (DWORD i = 0; i < cnt; ++i) {
            char nm[MAX_PATH] = {0};
            if (GetModuleBaseNameA(hProc, mods[i], nm, MAX_PATH) && _stricmp(nm, dllName) == 0)
                return (ULONG_PTR)mods[i];
        }
    }
    // 让目标自己 LoadLibraryA
    SIZE_T len = strlen(dllName) + 1;
    void* remoteStr = VirtualAllocEx(hProc, nullptr, len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remoteStr) return 0;
    WriteProcessMemory(hProc, remoteStr, dllName, len, nullptr);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoad = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryA");
    HANDLE th = CreateRemoteThread(hProc, nullptr, 0, pLoad, remoteStr, 0, nullptr);
    if (th) { WaitForSingleObject(th, 15000); CloseHandle(th); }
    VirtualFreeEx(hProc, remoteStr, 0, MEM_RELEASE);
    // 再从目标模块列表取基址
    if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &need, LIST_MODULES_ALL)) {
        DWORD cnt = need / sizeof(HMODULE);
        if (cnt > 1024) cnt = 1024;
        for (DWORD i = 0; i < cnt; ++i) {
            char nm[MAX_PATH] = {0};
            if (GetModuleBaseNameA(hProc, mods[i], nm, MAX_PATH) && _stricmp(nm, dllName) == 0)
                return (ULONG_PTR)mods[i];
        }
    }
    return 0;
}

// 注册异常表：让 ntdll 的函数表机制认识这块手动映射的映像
// （缺这一步时，ntdll!SbSelectProcedure 会读到野指针 -> 0xC0000005）
// 解析一个导出在"目标进程"里的地址（自动跟随转发器）
static ULONG_PTR ResolveRemoteExport(HANDLE hProc, const char* module, const char* name) {
    HMODULE lm = LoadLibraryA(module);
    if (!lm) return 0;
    ExportRef er = GetExportRef(lm, name, 0);
    if (!er.ok) return 0;
    if (er.forwarder) {
        ULONG_PTR fb = EnsureRemoteModule(hProc, er.fwdDll);
        HMODULE fl = LoadLibraryA(er.fwdDll);
        ExportRef er2 = GetExportRef(fl, er.fwdFunc, 0);
        if (fb && er2.ok && !er2.forwarder) return fb + er2.rva;
        return 0;
    }
    ULONG_PTR mb = EnsureRemoteModule(hProc, module);
    return mb ? mb + er.rva : 0;
}

static bool RegisterRemoteExceptionTable(HANDLE hProc, void* base, IMAGE_NT_HEADERS64* nt,
                                         const std::vector<BYTE>& file) {
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!ed.Size) { printf("      (无 .pdata，跳过异常表注册)\n"); return true; }

    ULONG_PTR addFn = ResolveRemoteExport(hProc, "ntdll.dll", "RtlAddFunctionTable");
    if (!addFn) addFn = ResolveRemoteExport(hProc, "kernel32.dll", "RtlAddFunctionTable");
    if (!addFn) { printf("      !! 无法定位 RtlAddFunctionTable\n"); return false; }
    {
        // 先用同样的桩模式调用一个"无害"的导出，验证桩与解析是否正确
        ULONG_PTR gcp = ResolveRemoteExport(hProc, "kernel32.dll", "GetCurrentProcessId");
        if (gcp) {
            unsigned char c2[32]; size_t n2 = 0;
            auto e2 = [&](std::initializer_list<unsigned char> b) { for (auto x : b) c2[n2++] = x; };
            e2({ 0x48, 0xB8 }); uint64_t vv = gcp; memcpy(c2 + n2, &vv, 8); n2 += 8;
            e2({ 0xFF, 0xD0, 0xC3 });
            void* s2 = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (s2) {
                WriteProcessMemory(hProc, s2, c2, n2, nullptr);
                HANDLE t2 = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)s2, nullptr, 0, nullptr);
                if (t2) {
                    WaitForSingleObject(t2, 10000);
                    DWORD ec2 = 0; GetExitCodeThread(t2, &ec2);
                    DWORD tpid = GetProcessId(hProc);
                    printf("      [dbg] 桩自检: GetCurrentProcessId() 返回 %lu (目标 PID=%lu) %s\n",
                           ec2, tpid, ec2 == tpid ? "OK" : "异常");
                    CloseHandle(t2);
                }
                VirtualFreeEx(hProc, s2, 0, MEM_RELEASE);
            }
        }
    }

    DWORD count = ed.Size / sizeof(RUNTIME_FUNCTION);
    void* table = (BYTE*)base + ed.VirtualAddress;

    // stub: mov rcx,<table> ; mov edx,<count> ; mov r8,<base> ; mov rax,<fn> ; call rax ; ret
    unsigned char code[64]; size_t n = 0;
    auto emit = [&](std::initializer_list<unsigned char> b) { for (auto x : b) code[n++] = x; };
    emit({ 0x48, 0xB9 }); uint64_t v1 = (uint64_t)table; memcpy(code + n, &v1, 8); n += 8;
    emit({ 0xBA });       uint32_t v2 = count;           memcpy(code + n, &v2, 4); n += 4;
    emit({ 0x49, 0xB8 }); uint64_t v3 = (uint64_t)base;  memcpy(code + n, &v3, 8); n += 8;
    emit({ 0x48, 0xB8 }); uint64_t v4 = addFn;           memcpy(code + n, &v4, 8); n += 8;
    emit({ 0xFF, 0xD0 });
    emit({ 0x33, 0xC0 });
    emit({ 0xC3 });

    void* stub = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!stub) return false;
    WriteProcessMemory(hProc, stub, code, n, nullptr);
    HANDLE th = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)stub, nullptr, 0, nullptr);
    if (!th) { printf("      !! 异常表注册线程创建失败 %lu\n", GetLastError()); return false; }
    WaitForSingleObject(th, 15000);
    DWORD ec = 0; GetExitCodeThread(th, &ec);
    CloseHandle(th);
    printf("      RtlAddFunctionTable(%p, %lu 项, base=%p) 完成 (exit=%lu)\n", table, count, base, ec);
    return ec == 0;
}

// ============================ 合法模块跳板（对抗"返回地址检查"） ============================
// ACE 的钩子会检查调用方的返回地址是否属于某个模块映像。载荷在手动映射的内存里，
// 直接调用被挂钩 API 会被判定为"无后备内存调用"。
// 解法：把调用改为从"合法模块的可执行区尾部空白"发起的跳板：
//     trampoline:  call qword ptr [rip+0]   ; 返回地址落在合法模块内
//                  ret                       ; 返回载荷
static ULONG_PTR g_trampBase = 0;
static SIZE_T    g_trampUsed = 0;
static SIZE_T    g_trampSize = 0;

static bool FindTrampolineSpace(HANDLE hProc, SIZE_T need) {
    HMODULE mods[512]; DWORD cbNeeded = 0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &cbNeeded, LIST_MODULES_ALL)) return false;
    DWORD cnt = cbNeeded / sizeof(HMODULE);
    if (cnt > 512) cnt = 512;
    for (DWORD i = 0; i < cnt; ++i) {
        BYTE hdr[0x1000] = {0};
        if (!ReadProcessMemory(hProc, mods[i], hdr, sizeof(hdr), nullptr)) continue;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hdr;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        if (dos->e_lfanew <= 0 || dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(hdr)) continue;
        IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(hdr + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s, ++sec) {
            if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            SIZE_T vsize = sec->Misc.VirtualSize;
            if (vsize < need + 0x100) continue;
            SIZE_T scan = vsize < 0x8000 ? vsize : 0x8000;
            std::vector<BYTE> tail(scan);
            ULONG_PTR secEnd = (ULONG_PTR)mods[i] + sec->VirtualAddress + vsize;
            if (!ReadProcessMemory(hProc, (LPCVOID)(secEnd - scan), tail.data(), scan, nullptr)) continue;
            SIZE_T run = 0;
            for (SIZE_T k = scan; k > 0; --k) {
                BYTE b = tail[k - 1];
                if (b == 0xCC || b == 0x00) run++; else break;
            }
            if (run >= need) {
                // 记录最大的空白区（跳板越多越好，避免退化成直连）
                static SIZE_T bestRun2 = 0;
                if (run > bestRun2) {
                    bestRun2 = run;
                    g_trampBase = secEnd - run;
                    g_trampSize = run;
                    g_trampUsed = 0;
                    char mn[MAX_PATH] = {0};
                    GetModuleFileNameExA(hProc, mods[i], mn, MAX_PATH);
                    printf("      TRAMPOLINE-AREA: %p (%zu bytes) in %s\n", (void*)g_trampBase, run, mn);
                }
            }
        }
    }
    return g_trampBase != 0;   // 取到了最大的空白区就算成功
}

// 找一个能容纳 need 字节的"模块可执行节尾部空白"（模块踩踏落点）
static ULONG_PTR FindStompSpace(HANDLE hProc, SIZE_T need, SIZE_T* outSize) {
    HMODULE mods[1024]; DWORD cb = 0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &cb, LIST_MODULES_ALL)) return 0;
    DWORD cnt = cb / sizeof(HMODULE); if (cnt > 1024) cnt = 1024;
    ULONG_PTR best = 0; SIZE_T bestSize = 0;
    for (DWORD i = 0; i < cnt; ++i) {
        BYTE hdr[0x1000] = {0};
        if (!ReadProcessMemory(hProc, mods[i], hdr, sizeof(hdr), nullptr)) continue;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hdr;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(hdr + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s, ++sec) {
            if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            SIZE_T vsize = sec->Misc.VirtualSize;
            if (vsize < need + 0x200) continue;
            SIZE_T scan = vsize < 0x40000 ? vsize : 0x40000;
            std::vector<BYTE> tail(scan);
            ULONG_PTR secEnd = (ULONG_PTR)mods[i] + sec->VirtualAddress + vsize;
            if (!ReadProcessMemory(hProc, (LPCVOID)(secEnd - scan), tail.data(), scan, nullptr)) continue;
            SIZE_T run = 0;
            for (SIZE_T k = scan; k > 0; --k) {
                BYTE b = tail[k - 1];
                if (b == 0xCC || b == 0x00) run++; else break;
            }
            if (run >= need && run > bestSize) {
                best = secEnd - run; bestSize = run;
            }
        }
    }
    if (best && outSize) *outSize = bestSize;
    return best;
}

// 跳板：sub rsp,8 ; call [rip+0] ; add rsp,8 ; ret ; <目标地址>
// 注意栈对齐：调用方进入跳板时 RSP≡8 (mod 16)，被调 API 入口也要求 RSP≡8，
// 因此 call 前必须先 sub rsp,8，否则 API 内的 movaps 会因未对齐而 AV。
static ULONG_PTR MakeTrampoline(HANDLE hProc, ULONG_PTR target) {
    if (!g_trampBase || g_trampUsed + 24 > g_trampSize) return 0;
    BYTE code[24] = {0};
    code[0] = 0x48; code[1] = 0x83; code[2] = 0xEC; code[3] = 0x08;              // sub rsp,8
    code[4] = 0xFF; code[5] = 0x15; code[6] = 0; code[7] = 0; code[8] = 0; code[9] = 0; // call [rip+0]
    code[10] = 0x48; code[11] = 0x83; code[12] = 0xC4; code[13] = 0x08;          // add rsp,8
    code[14] = 0xC3;                                                              // ret
    memcpy(code + 16, &target, 8);
    ULONG_PTR addr = g_trampBase + g_trampUsed;
    DWORD old = 0;
    if (!VirtualProtectEx(hProc, (LPVOID)addr, 24, PAGE_EXECUTE_READWRITE, &old)) return 0;
    if (!WriteProcessMemory(hProc, (LPVOID)addr, code, 24, nullptr)) return 0;
    DWORD old2 = 0;
    VirtualProtectEx(hProc, (LPVOID)addr, 24, PAGE_EXECUTE_READ, &old2);
    g_trampUsed += 24;
    return addr;
}

// ============================ 拦截 LoadLibrary（让 bundle 加载不经内核） ============================
// 上游 mod 会把它内嵌的 nvngx_dlssg.dll / sm86_backend.dll 释放到磁盘再 LoadLibrary，
// 这会触发内核镜像加载通知 + 签名校验（ACE 会终止进程）。
// 解法：注入时先把这些 DLL 手动映射进目标，再把载荷的 LoadLibrary* 导入换成
// "按路径子串匹配返回已映射基址"的桩 —— 内核完全看不到这次加载。
static std::vector<std::pair<std::wstring, ULONG_PTR>> g_bundleMap;
static bool g_inPremap = false;   // 防重入：预映射自身也会调用 MapRemote

static void* WriteLoadLibraryStub(HANDLE hProc, ULONG_PTR tableAddr, DWORD count) {
    unsigned char code[256]; size_t n = 0;
    auto emit = [&](std::initializer_list<unsigned char> b) { for (auto x : b) code[n++] = x; };
    auto emit64 = [&](std::initializer_list<unsigned char> op, uint64_t imm) {
        for (auto x : op) code[n++] = x;
        memcpy(code + n, &imm, 8); n += 8;
    };
    emit({ 0x53 });                                        // push rbx
    emit64({ 0x48, 0xB8 }, tableAddr);                     // mov rax, table
    emit({ 0x49, 0x89, 0xC0 });                            // mov r8, rax
    emit({ 0x41, 0xB9 }); uint32_t c = count; memcpy(code + n, &c, 4); n += 4;   // mov r9d, count
    size_t entryLoop = n;
    emit({ 0x45, 0x85, 0xC9 });                            // test r9d,r9d
    emit({ 0x74, 0x00 }); size_t jzFail = n - 1;
    emit({ 0x48, 0x89, 0xC8 });                            // mov rsi, rcx
    size_t scanLoop = n;
    emit({ 0x0F, 0xB7, 0x06 });                            // movzx eax, word [rsi]
    emit({ 0x66, 0x85, 0xC0 });                            // test ax,ax
    emit({ 0x74, 0x00 }); size_t jzNext = n - 1;
    emit({ 0x4C, 0x89, 0xC7 });                            // mov rdi, r8
    emit({ 0x48, 0x89, 0xF2 });                            // mov rdx, rsi
    size_t cmpLoop = n;
    emit({ 0x0F, 0xB7, 0x1F });                            // movzx ebx, word [rdi]
    emit({ 0x66, 0x85, 0xDB });                            // test bx,bx
    emit({ 0x74, 0x00 }); size_t jzMatched = n - 1;
    emit({ 0x0F, 0xB7, 0x02 });                            // movzx eax, word [rdx]
    emit({ 0x66, 0x39, 0xD8 });                            // cmp ax,bx
    emit({ 0x75, 0x00 }); size_t jneNotThis = n - 1;
    emit({ 0x48, 0x83, 0xC7, 0x02 });                      // add rdi,2
    emit({ 0x48, 0x83, 0xC2, 0x02 });                      // add rdx,2
    { int back = (int)(n - cmpLoop); emit({ 0xEB, (unsigned char)(-back - 1) }); }
    size_t notThis = n;
    emit({ 0x48, 0x83, 0xC6, 0x02 });                      // add rsi,2
    { int back = (int)(n - scanLoop); emit({ 0xEB, (unsigned char)(-back - 1) }); }
    size_t nextEntry = n;
    emit({ 0x49, 0x83, 0xC0, 0x28 });                      // add r8,40
    emit({ 0x41, 0xFF, 0xC9 });                            // dec r9d
    { int back = (int)(n - entryLoop); emit({ 0xEB, (unsigned char)(-back - 1) }); }
    size_t matched = n;
    emit({ 0x49, 0x8B, 0x40, 0x20 });                      // mov rax,[r8+32]
    emit({ 0x5B, 0xC3 });                                  // pop rbx; ret
    size_t fail = n;
    emit({ 0x33, 0xC0 });                                  // xor eax,eax
    emit({ 0x5B, 0xC3 });                                  // pop rbx; ret
    code[jzFail + 1]     = (unsigned char)(fail - (jzFail + 2));
    code[jzNext + 1]     = (unsigned char)(nextEntry - (jzNext + 2));
    code[jzMatched + 1]  = (unsigned char)(matched - (jzMatched + 2));
    code[jneNotThis + 1] = (unsigned char)(notThis - (jneNotThis + 2));

    void* mem = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;
    if (!WriteProcessMemory(hProc, mem, code, n, nullptr)) return nullptr;
    return mem;
}

static Mapped MapRemote(HANDLE hProc, std::vector<BYTE>& file, bool strip, bool runEntry) {
    Mapped out;
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) return out;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)file.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return out;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return out;

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    ULONG_PTR preferred = nt->OptionalHeader.ImageBase;

    void* base = nullptr;
    if (g_stomp) {
        // 模块踩踏：把载荷整个放进"已加载合法模块的可执行节尾部空白"
        SIZE_T slack = 0;
        ULONG_PTR sp = FindStompSpace(hProc, imageSize, &slack);
        if (sp) {
            DWORD old = 0;
            if (VirtualProtectEx(hProc, (LPVOID)sp, imageSize, PAGE_EXECUTE_READWRITE, &old))
                base = (void*)sp;
            LOG("      模块踩踏落点=%p (空白 %zu 字节, 需求 0x%zX)\n", (void*)sp, slack, imageSize);
        } else LOG("      !! 未找到足够大的模块空白（需要 0x%zX）\n", imageSize);
    }
    if (!base && !g_forceReloc)
        base = VirtualAllocEx(hProc, (void*)preferred, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!base) base = VirtualAllocEx(hProc, nullptr, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!base) return out;
    LOG("      映射基址=%p 首选=%p 偏移=%lld\n", base, (void*)preferred,
        (long long)((ULONG_PTR)base - preferred));

    SIZE_T hdrSize = nt->OptionalHeader.SizeOfHeaders;
    if (hdrSize > file.size()) hdrSize = file.size();
    std::vector<BYTE> hdr(hdrSize, 0);
    memcpy(hdr.data(), file.data(), hdrSize);
    if (strip) {
        hdr[0] = 0; hdr[1] = 0;
        IMAGE_NT_HEADERS64* hnt = (IMAGE_NT_HEADERS64*)(hdr.data() + dos->e_lfanew);
        hnt->Signature = 0;
    }
    if (!WriteProcessMemory(hProc, base, hdr.data(), hdr.size(), nullptr)) return out;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) continue;
        if ((SIZE_T)sec->PointerToRawData + sec->SizeOfRawData > file.size()) continue;
        WriteProcessMemory(hProc, (BYTE*)base + sec->VirtualAddress,
                           file.data() + sec->PointerToRawData, sec->SizeOfRawData, nullptr);
    }

    ULONG_PTR delta = (ULONG_PTR)base - preferred;
    if (delta) {
        IMAGE_DATA_DIRECTORY rd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rd.Size) {
            std::vector<BYTE> rel(rd.Size);
            ReadProcessMemory(hProc, (BYTE*)base + rd.VirtualAddress, rel.data(), rel.size(), nullptr);
            IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)rel.data();
            while ((BYTE*)blk < rel.data() + rel.size() && blk->SizeOfBlock) {
                int cnt = (int)((blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
                WORD* e = (WORD*)((BYTE*)blk + sizeof(IMAGE_BASE_RELOCATION));
                for (int k = 0; k < cnt; ++k) {
                    if ((e[k] >> 12) != IMAGE_REL_BASED_DIR64) continue;
                    ULONG_PTR addr = (ULONG_PTR)base + blk->VirtualAddress + (e[k] & 0x0FFF);
                    ULONG_PTR val = 0;
                    ReadProcessMemory(hProc, (LPVOID)addr, &val, sizeof(val), nullptr);
                    val += delta;
                    WriteProcessMemory(hProc, (LPVOID)addr, &val, sizeof(val), nullptr);
                }
                blk = (IMAGE_BASE_RELOCATION*)((BYTE*)blk + blk->SizeOfBlock);
            }
        }
    }

    // ① 预映射 mod 的 bundle（让它后续的 LoadLibrary 直接命中已映射模块，不经内核）
    ULONG_PTR loadLibStub = 0;
    {
        wchar_t base[MAX_PATH] = {0};
        DWORD nb = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
        if (nb && g_bundleMap.empty() && !g_inPremap) {
            g_inPremap = true;
            std::wstring dir = std::wstring(base) + L"\\DlssgSm86\\bundles";
            WIN32_FIND_DATAW fd;
            HANDLE hf = FindFirstFileW((dir + L"\\*").c_str(), &fd);
            if (hf != INVALID_HANDLE_VALUE) {
                std::vector<std::wstring> dirs;
                do {
                    if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                        wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L".."))
                        dirs.push_back(dir + L"\\" + fd.cFileName);
                } while (FindNextFileW(hf, &fd));
                FindClose(hf);
                for (const auto& d : dirs) {
                    WIN32_FIND_DATAW fd2;
                    HANDLE h2 = FindFirstFileW((d + L"\\*.dll").c_str(), &fd2);
                    if (h2 == INVALID_HANDLE_VALUE) continue;
                    do {
                        std::wstring path = d + L"\\" + fd2.cFileName;
                        std::vector<BYTE> bd = ReadAll(path);
                        if (bd.empty()) continue;
                        Mapped bm = MapRemote(hProc, bd, /*strip=*/false, /*runEntry=*/true);
                        if (bm.ok) {
                            g_bundleMap.push_back({ fd2.cFileName, (ULONG_PTR)bm.base });
                            LOG("      预映射 bundle: %ls -> %p\n", fd2.cFileName, bm.base);
                        }
                    } while (FindNextFileW(h2, &fd2));
                    FindClose(h2);
                }
            }
            g_inPremap = false;
        }
    }
    if (!g_bundleMap.empty()) {
        // ② 在目标里建查找表并生成 LoadLibrary 桩
        const SIZE_T entrySize = 40;
        SIZE_T tblSize = entrySize * g_bundleMap.size();
        ULONG_PTR tbl = (ULONG_PTR)VirtualAllocEx(hProc, nullptr, tblSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (tbl) {
            for (size_t k = 0; k < g_bundleMap.size(); ++k) {
                wchar_t key[16] = {0};
                wcsncpy_s(key, g_bundleMap[k].first.c_str(), 15);
                WriteProcessMemory(hProc, (LPVOID)(tbl + k * entrySize), key, sizeof(key), nullptr);
                ULONG_PTR b = g_bundleMap[k].second;
                WriteProcessMemory(hProc, (LPVOID)(tbl + k * entrySize + 32), &b, sizeof(b), nullptr);
            }
            loadLibStub = (ULONG_PTR)WriteLoadLibraryStub(hProc, tbl, (DWORD)g_bundleMap.size());
            LOG("      LoadLibrary 拦截桩=%p (表项 %zu)\n", (void*)loadLibStub, g_bundleMap.size());
        }
    }

    // 准备跳板区（把 API 调用改为从合法模块发起，对抗 ACE 的返回地址检查）
    if (!FindTrampolineSpace(hProc, 0x400))
        LOG("      !! 未找到合法模块跳板区（将直接写函数地址）\n");

    IMAGE_DATA_DIRECTORY id = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (id.Size) {
        // 导入解析：在"服务进程"里 LoadLibrary 取得函数地址，再写进目标 IAT
        // 注意：导入描述符必须从"目标进程"读取，不能本地解引用远程地址
        for (DWORD idx = 0; ; ++idx) {
            IMAGE_IMPORT_DESCRIPTOR desc{};
            if (!ReadProcessMemory(hProc, (BYTE*)base + id.VirtualAddress + idx * sizeof(desc),
                                   &desc, sizeof(desc), nullptr)) break;
            if (!desc.Name) break;
            char dllName[256] = {0};
            ReadProcessMemory(hProc, (BYTE*)base + desc.Name, dllName, sizeof(dllName) - 1, nullptr);
            if (!dllName[0]) break;
            // 关键：依赖必须由"目标进程"加载，函数地址 = 目标内基址 + 本地解析出的 RVA
            ULONG_PTR remoteBase = EnsureRemoteModule(hProc, dllName);
            // 手动映射的模块不在模块表里，载荷调用 GetModuleFileName* 查自身路径会让 ntdll 崩
            // （ntdll!SbSelectProcedure）。这里把这两个导入替换为"返回 0"的桩，先验证假设。
            ULONG_PTR retZero = 0;
            {
                BYTE zc[3] = { 0x33, 0xC0, 0xC3 };   // xor eax,eax; ret
                void* zs = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (zs) { WriteProcessMemory(hProc, zs, zc, sizeof(zc), nullptr); retZero = (ULONG_PTR)zs; }
            }
            HMODULE localMod = LoadLibraryA(dllName);   // 只用于解析 RVA
            int resolved = 0;
            printf("      import %-16s targetBase=%p\n", dllName, (void*)remoteBase);
            DWORD oftRva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
            ULONG_PTR oftAddr = (ULONG_PTR)base + oftRva;
            ULONG_PTR ftAddr  = (ULONG_PTR)base + desc.FirstThunk;
            for (;;) {
                IMAGE_THUNK_DATA64 t{};
                ReadProcessMemory(hProc, (LPVOID)oftAddr, &t, sizeof(t), nullptr);
                if (!t.u1.AddressOfData) break;
                char curName[256] = {0};
                if (!(t.u1.Ordinal & IMAGE_ORDINAL_FLAG64))
                    ReadProcessMemory(hProc, (LPVOID)((ULONG_PTR)base + t.u1.AddressOfData + 2), curName, 255, nullptr);
                // 拦截 LoadLibrary*：改为查表返回已映射的 bundle 基址（不经内核）
                if (loadLibStub && (strcmp(curName, "LoadLibraryA") == 0 ||
                                    strcmp(curName, "LoadLibraryW") == 0 ||
                                    strcmp(curName, "LoadLibraryExA") == 0 ||
                                    strcmp(curName, "LoadLibraryExW") == 0)) {
                    ULONG_PTR st = loadLibStub;
                    WriteProcessMemory(hProc, (LPVOID)ftAddr, &st, sizeof(st), nullptr);
                    resolved++;
                    oftAddr += sizeof(ULONG64); ftAddr += sizeof(ULONG64);
                    continue;
                }
                // 拦截 VirtualProtect*：让载荷的 Detours 装不上内联钩子。
                // ACE 内核层会检测"对被挂钩代码页的写权限变更"，直接放行会被终止；
                // bundle 的重定向改由上面的 LoadLibrary 拦截桩完成。
                if (retZero && g_blockProtect &&
                    (strcmp(curName, "VirtualProtect") == 0 ||
                     strcmp(curName, "VirtualProtectEx") == 0)) {
                    WriteProcessMemory(hProc, (LPVOID)ftAddr, &retZero, sizeof(retZero), nullptr);
                    resolved++;
                    oftAddr += sizeof(ULONG64); ftAddr += sizeof(ULONG64);
                    continue;
                }
                if (retZero && (strcmp(curName, "GetModuleFileNameW") == 0 ||
                                strcmp(curName, "GetModuleFileNameA") == 0 ||
                                strcmp(curName, "GetModuleFileNameExW") == 0)) {
                    WriteProcessMemory(hProc, (LPVOID)ftAddr, &retZero, sizeof(retZero), nullptr);
                    resolved++;
                    oftAddr += sizeof(ULONG64); ftAddr += sizeof(ULONG64);
                    continue;
                }
                ExportRef er;
                if (t.u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    er = GetExportRef(localMod, nullptr, (WORD)(t.u1.Ordinal & 0xFFFF));
                } else {
                    char nm[256] = {0};
                    ReadProcessMemory(hProc, (LPVOID)((ULONG_PTR)base + t.u1.AddressOfData + 2), nm, sizeof(nm) - 1, nullptr);
                    er = GetExportRef(localMod, nm, 0);
                }
                ULONG_PTR fn = 0;
                if (er.ok) {
                    if (er.forwarder) {
                        // 转发器：换成目标 DLL 再解析一次
                        ULONG_PTR fb = EnsureRemoteModule(hProc, er.fwdDll);
                        HMODULE fl = LoadLibraryA(er.fwdDll);
                        ExportRef er2 = GetExportRef(fl, er.fwdFunc, 0);
                        if (fb && er2.ok && !er2.forwarder) fn = fb + er2.rva;
                    } else if (remoteBase) {
                        fn = remoteBase + er.rva;
                    }
                }
                if (fn) {
                    ULONG_PTR tramp = g_trampBase ? MakeTrampoline(hProc, fn) : 0;
                    ULONG_PTR writeVal = tramp ? tramp : fn;   // 优先经跳板调用
                    WriteProcessMemory(hProc, (LPVOID)ftAddr, &writeVal, sizeof(writeVal), nullptr);
                    resolved++;
                }
                oftAddr += sizeof(ULONG64);
                ftAddr  += sizeof(ULONG64);
            }
            printf("        -> resolved %d functions (trampolines=%zu)\n", resolved, g_trampUsed / 16);
        }
    }

    sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        DWORD prot = PAGE_READONLY;
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            prot = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) prot = PAGE_READWRITE;
        SIZE_T sz = sec->Misc.VirtualSize;
        if (sz < sec->SizeOfRawData) sz = sec->SizeOfRawData;
        DWORD old = 0;
        VirtualProtectEx(hProc, (BYTE*)base + sec->VirtualAddress, sz, prot, &old);
    }

    if (runEntry && nt->OptionalHeader.AddressOfEntryPoint) {
        DWORD tlsIdx = 0xFFFFFFFF; ULONG_PTR tlsBlock = 0;
        SetupRemoteTls(hProc, base, nt, file, &tlsIdx, &tlsBlock);   // 手动映射必须自己做 TLS
        // 优先 APC 注入（线程上下文零改动），失败再退回线程劫持
        DWORD tpid = GetProcessId(hProc);
        void* entryAddr = (BYTE*)base + nt->OptionalHeader.AddressOfEntryPoint;
        // 先临时挂上 PEB 表项，让复杂 CRT 的 DllMain 能正常工作
        std::wstring fakePath = L"C:\\Windows\\System32\\version.dll";
        ULONG_PTR tempEntry = AddTempPebEntry(hProc, (ULONG_PTR)base,
                                              (ULONG_PTR)entryAddr, imageSize, fakePath);
        void* flag = VirtualAllocEx(hProc, nullptr, 0x100, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        void* cookie = VirtualAllocEx(hProc, nullptr, 0x100, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        bool ran = false;
        if (flag && cookie) {
            void* apcStub = WriteApcStub(hProc, base, entryAddr, flag, cookie, tlsIdx, tlsBlock);
            if (apcStub) ran = RunViaApc(hProc, tpid, apcStub, flag);
        }
        if (!ran) {
            LOG("      回退到线程劫持方式...\n");
            void* stub = nullptr;
            if (WriteEntryStub(hProc, base, entryAddr, &stub, tlsIdx, tlsBlock)) {
                if (RunOnHijackedThread(hProc, tpid, stub)) {
                    Sleep(3000);
                    LOG("      DllMain 已在目标线程上执行（劫持+还原）\n");
                    ran = true;
                } else LOG("      !! 线程劫持失败\n");
            }
        }
        if (tempEntry) { UnlinkFromPeb(hProc, tempEntry); LOG("      临时 PEB 表项已摘除\n"); }
    }

    out.base = base; out.size = imageSize; out.ok = true;
    return out;
}

// ============================ 方案 B：正常加载 + PEB 摘链 ============================
// 加载器会完成全部初始化（TLS、异常表、CRT），随后把模块从 PEB 三个链表里摘掉，
// 使 Toolhelp32 / PSAPI / PEB 枚举都看不到它。代价：内核 LoadImage 通知会触发一次。

static ULONG_PTR GetRemotePeb(HANDLE hProc) {
    // NtQueryInformationProcess(ProcessBasicInformation) 的 PebBaseAddress
    typedef NTSTATUS(NTAPI* pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static pNtQIP fn = nullptr;
    if (!fn) fn = (pNtQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!fn) return 0;
    struct { PVOID Reserved1; PVOID PebBaseAddress; PVOID Reserved2[2]; ULONG_PTR UniqueProcessId; PVOID Reserved3; } pbi{};
    if (fn(hProc, 0, &pbi, sizeof(pbi), nullptr) != 0) return 0;
    return (ULONG_PTR)pbi.PebBaseAddress;
}

// 临时插入 PEB 模块表项：让载荷的 DllMain（复杂 CRT）在"看起来像正常模块"的环境里初始化，
// 初始化完成后立刻摘除 —— 既不触发内核 LoadImage 通知，也不留下模块可见性。
static ULONG_PTR AddTempPebEntry(HANDLE hProc, ULONG_PTR base, ULONG_PTR entryPoint,
                                 SIZE_T sizeOfImage, const std::wstring& dllPath) {
    ULONG_PTR peb = GetRemotePeb(hProc);
    if (!peb) return 0;
    ULONG_PTR ldr = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)(peb + 0x18), &ldr, sizeof(ldr), nullptr) || !ldr) return 0;

    // 分配 LDR_DATA_TABLE_ENTRY（0x200 足够） + 两个 UNICODE_STRING 缓冲
    const SIZE_T entrySize = 0x200;
    ULONG_PTR entry = (ULONG_PTR)VirtualAllocEx(hProc, nullptr, entrySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!entry) return 0;
    SIZE_T pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    ULONG_PTR pathBuf = (ULONG_PTR)VirtualAllocEx(hProc, nullptr, pathBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pathBuf) return 0;
    WriteProcessMemory(hProc, (LPVOID)pathBuf, dllPath.c_str(), pathBytes, nullptr);

    const wchar_t* baseName = wcsrchr(dllPath.c_str(), L'\\');
    baseName = baseName ? baseName + 1 : dllPath.c_str();
    SIZE_T baseBytes = (wcslen(baseName) + 1) * sizeof(wchar_t);
    ULONG_PTR baseBuf = (ULONG_PTR)VirtualAllocEx(hProc, nullptr, baseBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!baseBuf) return 0;
    WriteProcessMemory(hProc, (LPVOID)baseBuf, baseName, baseBytes, nullptr);

    // 逐字段写入（偏移按 x64 LDR_DATA_TABLE_ENTRY）
    auto wq = [&](ULONG_PTR off, ULONG_PTR v) { WriteProcessMemory(hProc, (LPVOID)(entry + off), &v, sizeof(v), nullptr); };
    auto ws = [&](ULONG_PTR off, USHORT v) { WriteProcessMemory(hProc, (LPVOID)(entry + off), &v, sizeof(v), nullptr); };
    wq(0x30, base);                 // DllBase
    wq(0x38, entryPoint);           // EntryPoint
    ws(0x40, (USHORT)sizeOfImage);  // SizeOfImage（低 16 位足够）
    // FullDllName (UNICODE_STRING @0x48)
    ws(0x48, (USHORT)(pathBytes - sizeof(wchar_t)));
    ws(0x4A, (USHORT)pathBytes);
    wq(0x50, pathBuf);
    // BaseDllName (UNICODE_STRING @0x58)
    ws(0x58, (USHORT)(baseBytes - sizeof(wchar_t)));
    ws(0x5A, (USHORT)baseBytes);
    wq(0x60, baseBuf);

    // 挂到三个链表头部
    const int listOffsets[3] = { 0x00, 0x10, 0x20 };
    for (int i = 0; i < 3; ++i) {
        ULONG_PTR head = ldr + 0x10 + listOffsets[i];
        ULONG_PTR first = 0, headBack = 0;
        ReadProcessMemory(hProc, (LPCVOID)head, &first, sizeof(first), nullptr);          // head->Flink
        ReadProcessMemory(hProc, (LPCVOID)(head + 8), &headBack, sizeof(headBack), nullptr); // head->Blink
        ULONG_PTR node = entry + listOffsets[i];
        // node->Flink = first; node->Blink = head
        WriteProcessMemory(hProc, (LPVOID)node, &first, sizeof(first), nullptr);
        WriteProcessMemory(hProc, (LPVOID)(node + 8), &head, sizeof(head), nullptr);
        // first->Blink = node; head->Flink = node
        WriteProcessMemory(hProc, (LPVOID)(first + 8), &node, sizeof(node), nullptr);
        WriteProcessMemory(hProc, (LPVOID)head, &node, sizeof(node), nullptr);
    }
    LOG("      已临时插入 PEB 表项 base=%p（DllMain 后摘除）\n", (void*)base);
    return base;
}

static bool UnlinkFromPeb(HANDLE hProc, ULONG_PTR moduleBase) {
    ULONG_PTR peb = GetRemotePeb(hProc);
    if (!peb) { printf("      !! 取不到目标 PEB\n"); return false; }
    ULONG_PTR ldr = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)(peb + 0x18), &ldr, sizeof(ldr), nullptr) || !ldr) return false;

    // PEB_LDR_DATA 里三个 LIST_ENTRY 的偏移：InLoadOrder 0x10, InMemoryOrder 0x20, InInitOrder 0x30
    // 链表头偏移 与 各链表下 DllBase 相对该链表节点的偏移
    const int listOffsets[3]  = { 0x10, 0x20, 0x30 };
    const int dllBaseOffs[3]  = { 0x30, 0x20, 0x10 };
    int unlinked = 0;
    for (int li = 0; li < 3; ++li) {
        ULONG_PTR head = ldr + listOffsets[li];
        ULONG_PTR cur = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)head, &cur, sizeof(cur), nullptr)) continue;
        for (int guard = 0; guard < 512 && cur && cur != head; ++guard) {
            // LDR_DATA_TABLE_ENTRY: InLoadOrderLinks 在 0x00, DllBase 在 0x30
            ULONG_PTR dllBase = 0, flink = 0, blink = 0;
            ReadProcessMemory(hProc, (LPCVOID)(cur + dllBaseOffs[li]), &dllBase, sizeof(dllBase), nullptr);
            if (dllBase == moduleBase) {
                ReadProcessMemory(hProc, (LPCVOID)cur, &flink, sizeof(flink), nullptr);
                ReadProcessMemory(hProc, (LPCVOID)(cur + 8), &blink, sizeof(blink), nullptr);
                // 摘链：blink->Flink = flink ; flink->Blink = blink
                WriteProcessMemory(hProc, (LPVOID)blink, &flink, sizeof(flink), nullptr);
                WriteProcessMemory(hProc, (LPVOID)(flink + 8), &blink, sizeof(blink), nullptr);
                unlinked++;
                break;
            }
            ULONG_PTR next = 0;
            if (!ReadProcessMemory(hProc, (LPCVOID)cur, &next, sizeof(next), nullptr)) break;
            cur = next;
        }
    }
    LOG("      PEB 摘链: %d/3 个链表\n", unlinked);
    return unlinked > 0;
}

static bool InjectLoadHide(DWORD pid, const std::vector<BYTE>& payloadBytes, const std::wstring& tmpDll) {
    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
                               PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) { printf("    !! OpenProcess 失败 %lu\n", GetLastError()); return false; }

    // 1) 落到临时文件（随机名），供目标加载
    // FILE_SHARE_DELETE 很关键：加载后仍能删除目录项（模块继续驻留内存）
    HANDLE hf = CreateFileW(tmpDll.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { CloseHandle(hProc); printf("    !! 写临时 DLL 失败\n"); return false; }
    DWORD wr = 0; WriteFile(hf, payloadBytes.data(), (DWORD)payloadBytes.size(), &wr, nullptr);
    CloseHandle(hf);

    // 2) 让目标 LoadLibraryW(路径)
    SIZE_T bytes = (tmpDll.size() + 1) * sizeof(wchar_t);
    void* remotePath = VirtualAllocEx(hProc, nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remotePath) { CloseHandle(hProc); return false; }
    WriteProcessMemory(hProc, remotePath, tmpDll.c_str(), bytes, nullptr);

    ULONG_PTR llAddr = ResolveRemoteExport(hProc, "kernel32.dll", "LoadLibraryW");
    HANDLE th = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)llAddr, remotePath, 0, nullptr);
    if (!th) { printf("    !! LoadLibraryW 远程调用失败 %lu\n", GetLastError()); CloseHandle(hProc); return false; }
    WaitForSingleObject(th, 30000);
    DWORD hm = 0; GetExitCodeThread(th, &hm);
    CloseHandle(th);
    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    LOG("    LoadLibraryW 返回 HMODULE=0x%lX\n", hm);
    if (!hm) { CloseHandle(hProc); return false; }

    // 3) 取真实基址（退出码是 32 位，可能被截断）：按文件名在目标模块列表里找
    {
        wchar_t want[MAX_PATH] = {0};
        const wchar_t* slash = wcsrchr(tmpDll.c_str(), L'\\');
        wcscpy_s(want, slash ? slash + 1 : tmpDll.c_str());
        HMODULE mods[1024]; DWORD need = 0;
        ULONG_PTR realBase = 0;
        if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &need, LIST_MODULES_ALL)) {
            DWORD cnt = need / sizeof(HMODULE); if (cnt > 1024) cnt = 1024;
            for (DWORD i = 0; i < cnt; ++i) {
                wchar_t nm[MAX_PATH] = {0};
                if (GetModuleFileNameExW(hProc, mods[i], nm, MAX_PATH) &&
                    _wcsicmp(wcsrchr(nm, L'\\') ? wcsrchr(nm, L'\\') + 1 : nm, want) == 0) {
                    realBase = (ULONG_PTR)mods[i]; break;
                }
            }
        }
        LOG("    真实基址=%p (枚举比对)\n", (void*)realBase);
        UnlinkFromPeb(hProc, realBase ? realBase : (ULONG_PTR)hm);
    }
    CloseHandle(hProc);

    // 4) 删除策略：加载器持有文件句柄，运行期删不掉；
    //    先试一次（有 FILE_SHARE_DELETE 的场景），失败则等目标进程退出后自动删。
    if (DeleteFileW(tmpDll.c_str())) {
        printf("    临时文件已删除（模块仍驻留内存）\n");
    } else {
        LOG("    临时文件将在目标进程退出后自动删除\n");
        HANDLE hp = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (hp) {
            std::thread([hp, tmpDll]() {
                WaitForSingleObject(hp, INFINITE);
                CloseHandle(hp);
                for (int i = 0; i < 20; ++i) {           // 进程退出后文件可能还被释放中，重试
                    if (DeleteFileW(tmpDll.c_str())) break;
                    Sleep(500);
                }
            }).detach();
        } else {
            MoveFileExW(tmpDll.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }
    return true;
}

// ============================ WMI 事件驱动（不轮询） ============================
// 用 Win32_ProcessStartTrace 永久事件订阅：进程创建时由系统推送，服务自身零轮询开销。
#define _WIN32_DCOM
#include <comdef.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

static volatile LONG g_pendingPid = 0;   // 最近一次"进程创建"事件的 PID

class ProcessSink : public IWbemObjectSink {
    LONG m_ref = 1;
public:
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) { *ppv = (IWbemObjectSink*)this; AddRef(); return S_OK; }
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return r;
    }
    STDMETHODIMP Indicate(LONG objCount, IWbemClassObject** obj) override {
        for (LONG i = 0; i < objCount && obj && obj[i]; ++i) {
            VARIANT v; VariantInit(&v);
            if (SUCCEEDED(obj[i]->Get(L"ProcessID", 0, &v, nullptr, nullptr)) && v.vt == VT_I4) {
                LOG("      [wmi] 进程创建事件 pid=%ld\n", (long)v.lVal);
                InterlockedExchange(&g_pendingPid, (LONG)v.lVal);
            }
            VariantClear(&v);
        }
        return WBEM_S_NO_ERROR;
    }
    STDMETHODIMP SetStatus(LONG, HRESULT, BSTR, IWbemClassObject*) override { return WBEM_S_NO_ERROR; }
};

// 启动 WMI 订阅；成功返回 true（此后无需轮询）
static bool StartWmiWatch() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) { printf("      [wmi] CoInitializeEx 失败 0x%08lX\n", hr); return false; }
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) { printf("      [wmi] CoInitializeSecurity 失败 0x%08lX\n", hr); return false; }

    IWbemLocator* loc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&loc);
    if (FAILED(hr)) { printf("      [wmi] CoCreateInstance 失败 0x%08lX\n", hr); return false; }
    IWbemServices* svc = nullptr;
    hr = loc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
    loc->Release();
    if (FAILED(hr)) { printf("      [wmi] ConnectServer 失败 0x%08lX\n", hr); return false; }
    hr = CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) { printf("      [wmi] CoSetProxyBlanket 失败 0x%08lX\n", hr); svc->Release(); return false; }

    ProcessSink* sink = new ProcessSink();
    hr = svc->ExecNotificationQueryAsync(_bstr_t("WQL"),
            _bstr_t("SELECT * FROM Win32_ProcessStartTrace"),
            WBEM_FLAG_SEND_STATUS, nullptr, sink);
    sink->Release();
    svc->Release();
    if (FAILED(hr)) { printf("      [wmi] ExecNotificationQueryAsync 失败 0x%08lX\n", hr); return false; }
    return true;
}

// ============================ 进程快照 ============================
static std::vector<DWORD> SnapshotPids() {
    std::vector<DWORD> v;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return v;
    PROCESSENTRY32W pe; ZeroMemory(&pe, sizeof(pe)); pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do { v.push_back(pe.th32ProcessID); } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return v;
}
static std::wstring ProcessPath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return L"";
    wchar_t buf[MAX_PATH * 2] = {0};
    DWORD sz = MAX_PATH * 2;
    std::wstring out;
    if (QueryFullProcessImageNameW(h, 0, buf, &sz)) out = buf;
    CloseHandle(h);
    return out;
}

// ============================ 主流程 ============================
static std::wstring g_payload = L"";
static std::wstring g_logFile = L"";
static bool g_dry = false, g_pebEntry = false, g_debug = false;

// 统一输出：同时写 stdout 与日志文件（服务场景必需）
static void LOG(const char* fmt, ...) {
    char buf[2048];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    fputs(buf, stdout);
    fflush(stdout);
    if (!g_logFile.empty()) {
        FILE* fp = nullptr;
        // 二进制写入：避免 CRT 的 ccs=UTF-8 转换在非法字节序列上崩溃
        if (_wfopen_s(&fp, g_logFile.c_str(), L"ab") == 0 && fp) {
            SYSTEMTIME st; GetLocalTime(&st);
            char line[2200];
            int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
                                "[%02d:%02d:%02d] %s", st.wHour, st.wMinute, st.wSecond, buf);
            if (n > 0) fwrite(line, 1, (size_t)n, fp);
            fclose(fp);
        }
    }
}
static int g_mode = 0;   // 0=手动映射（隐身） 1=加载+PEB摘链（兼容性优先）
static bool g_forcePoll = false;

// 在本地模块的导出表里找"不大于 rva 的最近导出"，用于符号化
static const char* NearestExport(HMODULE mod, ULONG_PTR rva) {
    static char buf[128];
    buf[0] = 0;
    if (!mod) return buf;
    BYTE* b = (BYTE*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return buf;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(b + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.Size) return buf;
    IMAGE_EXPORT_DIRECTORY* ex = (IMAGE_EXPORT_DIRECTORY*)(b + ed.VirtualAddress);
    DWORD* funcs = (DWORD*)(b + ex->AddressOfFunctions);
    DWORD* names = (DWORD*)(b + ex->AddressOfNames);
    WORD* ords = (WORD*)(b + ex->AddressOfNameOrdinals);
    DWORD best = 0; const char* bestName = nullptr;
    for (DWORD i = 0; i < ex->NumberOfFunctions; ++i) {
            DWORD fr = funcs[i];
            if (!fr || fr > rva) continue;
            if (fr >= best) { best = fr; bestName = nullptr; }
        }
        for (DWORD i = 0; i < ex->NumberOfNames; ++i) {
            if (funcs[ords[i]] == best) { bestName = (const char*)(b + names[i]); break; }
        }
        if (bestName) sprintf_s(buf, "%s+0x%llX", bestName, (unsigned long long)(rva - best));
        else sprintf_s(buf, "sub_%llX", (unsigned long long)rva);
        return buf;
    }

    static void DebugPump(DWORD pid, int ms) {
        if (!DebugActiveProcess(pid)) { printf("      [dbg] DebugActiveProcess 失败 %lu\n", GetLastError()); return; }
        DebugSetProcessKillOnExit(FALSE);
        printf("      [dbg] 已附加调试器，监听异常...\n");
        ULONGLONG end = GetTickCount64() + ms;
        DEBUG_EVENT de;
        while (GetTickCount64() < end) {
            if (!WaitForDebugEvent(&de, 200)) continue;
            DWORD st = DBG_EXCEPTION_NOT_HANDLED;
            if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                EXCEPTION_RECORD& er = de.u.Exception.ExceptionRecord;
                if (er.ExceptionCode == EXCEPTION_BREAKPOINT) st = DBG_CONTINUE;
                printf("      [dbg] 异常 code=0x%08lX addr=%p\n", er.ExceptionCode, er.ExceptionAddress);
                if (er.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er.NumberParameters >= 2)
                    printf("      [dbg]   访问地址=%p  类型=%s\n", (void*)er.ExceptionInformation[1],
                           er.ExceptionInformation[0] == 0 ? "读" : (er.ExceptionInformation[0] == 1 ? "写" : "执行"));
                HANDLE ht = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, de.dwThreadId);
                if (ht) {
                    CONTEXT ctx; ZeroMemory(&ctx, sizeof(ctx)); ctx.ContextFlags = CONTEXT_FULL;
                    if (GetThreadContext(ht, &ctx))
                        printf("      [dbg]   RIP=%p RSP=%p RBP=%p RAX=%p RCX=%p RDX=%p\n",
                               (void*)ctx.Rip, (void*)ctx.Rsp, (void*)ctx.Rbp,
                               (void*)ctx.Rax, (void*)ctx.Rcx, (void*)ctx.Rdx);
                    CloseHandle(ht);
                }
                BYTE code[16] = {0}; SIZE_T rd = 0;
                HANDLE hp = OpenProcess(PROCESS_VM_READ, FALSE, pid);
                if (hp) {
                    ReadProcessMemory(hp, er.ExceptionAddress, code, sizeof(code), &rd);
                    printf("      [dbg]   指令:");
                    for (SIZE_T i = 0; i < rd; ++i) printf(" %02X", code[i]);
                    printf("\n");
                    CloseHandle(hp);
                }
            }
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st);
        }
        DebugActiveProcessStop(pid);
        printf("      [dbg] 停止调试\n");
    }

    static std::set<DWORD> g_injected;
    static int g_ok = 0, g_fail = 0;

    static void TryInject(DWORD pid, const std::wstring& exePath, const std::wstring& root) {
        std::wstring exeName = exePath.substr(exePath.find_last_of(L"\\/") + 1);
        LOG("[+] 目标: %-28ls pid=%-6lu root=%ls\n    匹配: %ls\n",
            exeName.c_str(), pid, root.c_str(), g_lastHit.c_str());
        if (g_dry) { LOG("    (dry-run) 跳过注入\n"); return; }

        HANDLE h = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
                               PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!h) { LOG("    !! OpenProcess 失败 %lu\n", GetLastError()); g_fail++; return; }
        if (g_debug) { std::thread(DebugPump, pid, 15000).detach(); Sleep(300); }

        std::vector<BYTE> enc = ReadAll(g_payload);
        if (enc.empty()) { LOG("    !! 读取载荷失败: %ls\n", g_payload.c_str()); CloseHandle(h); g_fail++; return; }
        xcrypt(enc.data(), enc.size(), 0x464C524F4F543230ULL);

        if (g_mode == 1) {
            CloseHandle(h);
            wchar_t tmp[MAX_PATH] = {0}, tmpDir[MAX_PATH] = {0};
            GetTempPathW(MAX_PATH, tmpDir);
            swprintf_s(tmp, L"%sflsm86_%lu_%lu.dll", tmpDir, pid, GetTickCount());
            bool ok2 = InjectLoadHide(pid, enc, tmp);
            SecureZeroMemory(enc.data(), enc.size());
            if (ok2) { LOG("    已注入（加载+摘链模式）\n"); g_ok++; } else g_fail++;
            return;
        }

        Mapped m = MapRemote(h, enc, /*strip=*/true, /*runEntry=*/true);
        SecureZeroMemory(enc.data(), enc.size());
        CloseHandle(h);
        if (m.ok) { LOG("    已注入: base=%p size=0x%llX (无 LoadImage / 无 PEB 条目)\n", m.base, (unsigned long long)m.size); g_ok++; }
        else { LOG("    !! 注入失败\n"); g_fail++; }
    }

    int wmain(int argc, wchar_t** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::wstring mode;
    std::vector<std::wstring> roots;
    int intervalMs = 2000;
    {
        wchar_t buf[MAX_PATH] = {0};
        DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
        if (n) g_payload = std::wstring(buf) + L"\\FlSm86\\proxy\\payload.enc";
    }

    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--run") mode = L"run";
        else if (a == L"--once") mode = L"once";
        else if (a == L"--dry") g_dry = true;
        else if (a == L"--debug") g_debug = true;
        else if (a == L"--poll") g_forcePoll = true;
        else if (a == L"--force-reloc") g_forceReloc = true;
        else if (a == L"--stomp") g_stomp = true;
        else if (a == L"--block-protect") g_blockProtect = true;
        else if (a == L"--scan-slack" && i + 1 < argc) {
            // 扫描目标进程各模块的可执行节尾部空白（找模块踩踏的落点）
            DWORD pid = _wtoi(argv[++i]);
            HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!hp) { printf("OpenProcess 失败 %lu\n", GetLastError()); return 1; }
            HMODULE mods[1024]; DWORD need = 0;
            EnumProcessModulesEx(hp, mods, sizeof(mods), &need, LIST_MODULES_ALL);
            DWORD cnt = need / sizeof(HMODULE); if (cnt > 1024) cnt = 1024;
            printf("模块数=%lu\n", cnt);
            for (DWORD m = 0; m < cnt; ++m) {
                BYTE hdr[0x1000] = {0};
                if (!ReadProcessMemory(hp, mods[m], hdr, sizeof(hdr), nullptr)) continue;
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hdr;
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
                IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(hdr + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
                IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
                for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s, ++sec) {
                    if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                    SIZE_T vsize = sec->Misc.VirtualSize;
                    if (vsize < 0x1000) continue;
                    SIZE_T scan = vsize < 0x20000 ? vsize : 0x20000;
                    std::vector<BYTE> tail(scan);
                    ULONG_PTR secEnd = (ULONG_PTR)mods[m] + sec->VirtualAddress + vsize;
                    if (!ReadProcessMemory(hp, (LPCVOID)(secEnd - scan), tail.data(), scan, nullptr)) continue;
                    SIZE_T run = 0;
                    for (SIZE_T k = scan; k > 0; --k) {
                        BYTE b = tail[k - 1];
                        if (b == 0xCC || b == 0x00) run++; else break;
                    }
                    if (run >= 0x800) {
                        char mn[MAX_PATH] = {0};
                        GetModuleFileNameExA(hp, mods[m], mn, MAX_PATH);
                        printf("  slack=%-8zu  %s  (节 %u, vsize=0x%zX)\n", run, mn, s, vsize);
                    }
                }
            }
            CloseHandle(hp);
            return 0;
        }
        else if (a == L"--mode" && i + 1 < argc) g_mode = _wtoi(argv[++i]);
        else if (a == L"--log" && i + 1 < argc) g_logFile = argv[++i];
        else if (a == L"--payload" && i + 1 < argc) g_payload = argv[++i];
        else if (a == L"--roots" && i + 1 < argc) roots.push_back(argv[++i]);
        else if (a == L"--interval" && i + 1 < argc) intervalMs = _wtoi(argv[++i]);
        else if (a == L"--sym" && i + 2 < argc) {
            char mod[128] = {0};
            WideCharToMultiByte(CP_ACP, 0, argv[++i], -1, mod, 127, nullptr, nullptr);
            ULONG_PTR rva = wcstoull(argv[++i], nullptr, 0);
            HMODULE m = LoadLibraryA(mod);
            printf("%s+0x%llX -> %s\n", mod, (unsigned long long)rva, NearestExport(m, rva));
            return 0;
        }
        else if (a == L"--rtl-local") {
            typedef BOOLEAN(NTAPI* pAdd)(PRUNTIME_FUNCTION, DWORD, DWORD64);
            pAdd add = (pAdd)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddFunctionTable");
            BYTE table[64] = {0};
            printf("RtlAddFunctionTable = %p, 本进程调用 -> %d\n", (void*)add,
                   add((PRUNTIME_FUNCTION)table, 0, (DWORD64)GetModuleHandleW(nullptr)));
            return 0;
        }
        else if (a == L"--pack" && i + 2 < argc) {
            std::wstring in = argv[++i], out = argv[++i];
            std::vector<BYTE> d = ReadAll(in);
            if (d.empty()) { printf("read failed\n"); return 1; }
            xcrypt(d.data(), d.size(), 0x464C524F4F543230ULL);
            HANDLE hf = CreateFileW(out.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
            DWORD wr = 0; WriteFile(hf, d.data(), (DWORD)d.size(), &wr, nullptr); CloseHandle(hf);
            printf("packed %zu -> %ls\n", d.size(), out.c_str());
            return 0;
        }
    }
    if (mode.empty()) {
        printf("usage: flsm86_svc.exe --run [--mode 1] [--payload x.enc] [--roots D] [--log f] [--dry]\n");
        printf("       flsm86_svc.exe --once | --pack <in.dll> <out.enc> | --sym <dll> <rva>\n");
        return 1;
    }

    LOG("=== FlSm86 全局注入服务 ===\n");
    LOG("载荷: %ls\n", g_payload.c_str());
    LOG("模式: %ls%s\n", mode.c_str(), g_dry ? " (dry-run)" : "");
    if (!FileExists(g_payload) && !g_dry) { LOG("!! 载荷不存在，先 --pack 生成\n"); return 1; }

    DWORD self = GetCurrentProcessId();
    static std::set<std::wstring> seenPaths;

    auto handlePid = [&](DWORD pid) {
        if (pid == self || pid == 0 || pid == 4) return;
        if (g_injected.count(pid)) return;
        std::wstring path = ProcessPath(pid);
        if (path.empty()) return;
        if (IsSystemPath(path)) return;
        std::wstring low = path;
        for (auto& c : low) c = towlower(c);
        if (seenPaths.count(low)) return;
        seenPaths.insert(low);
        std::wstring dir = DirName(path), root;
        if (!HasFrameGen(dir, &root)) return;
        g_injected.insert(pid);
        TryInject(pid, path, root);
    };

    if (mode == L"once") {
        for (DWORD pid : SnapshotPids()) handlePid(pid);
    } else {
        bool wmiOk = StartWmiWatch();
        if (!wmiOk) {
            LOG("!! WMI 事件订阅失败（需要管理员权限）。\n");
            LOG("   注入器只使用事件驱动监视，不提供常驻轮询（轮询会占用大量 CPU）。\n");
            if (!g_forcePoll) return 2;
        }
        LOG("监视方式: %s\n", wmiOk ? "WMI 事件驱动（进程创建时系统推送，自身零轮询）"
                                    : "低频轮询（--poll，实测高占用，不推荐）");
        for (DWORD pid : SnapshotPids()) handlePid(pid);
        for (;;) {
            if (wmiOk) {
                LONG pid = InterlockedExchange(&g_pendingPid, 0);
                if (pid) handlePid((DWORD)pid);
                Sleep(500);
            } else {
                Sleep(intervalMs);
                for (DWORD pid : SnapshotPids()) handlePid(pid);
            }
        }
    }
    LOG("=== 结束: 成功 %d, 失败 %d ===\n", g_ok, g_fail);
    return 0;
}
