// fake_game.cpp — 测试夹具：模拟游戏进程，定期列出自己的模块（观察注入效果）
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "version.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "kernel32.lib")

static void DumpModules(const char* tag) {
    printf("[%s] modules:", tag);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me; ZeroMemory(&me, sizeof(me)); me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                char n[128] = {0};
                WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, n, 127, nullptr, nullptr);
                printf(" %s", n);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    printf("\n");
    // 检查是否有"无 PEB 条目的可执行私有内存"（手动映射的痕迹）
    int priv = 0;
    SYSTEM_INFO si; GetSystemInfo(&si);
    BYTE* a = (BYTE*)si.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    while (a < (BYTE*)si.lpMaximumApplicationAddress && VirtualQuery(a, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
            mbi.RegionSize >= 0x100000) priv++;
        a = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    printf("[%s] 大型私有可执行内存块(>=1MB): %d\n", tag, priv);

    // 关键隐身证据：枚举"私有可执行且 >=256KB"的区域，检查它是否是文件映射
    // （LoadLibrary 加载的模块必然有映射文件名；手动映射的区域没有）
    BYTE* a2 = (BYTE*)si.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION m2;
    int unmappedImg = 0, mappedImg = 0;
    while (a2 < (BYTE*)si.lpMaximumApplicationAddress && VirtualQuery(a2, &m2, sizeof(m2)) == sizeof(m2)) {
        if (m2.State == MEM_COMMIT && m2.Type == MEM_PRIVATE &&
            (m2.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            m2.RegionSize >= 0x40000) {
            wchar_t name[MAX_PATH] = {0};
            DWORD n = GetMappedFileNameW(GetCurrentProcess(), m2.BaseAddress, name, MAX_PATH);
            if (n == 0) unmappedImg++; else mappedImg++;
        }
        a2 = (BYTE*)m2.BaseAddress + m2.RegionSize;
    }
    printf("[%s] 私有可执行区域: 无映射名(手动映射痕迹)=%d, 有映射名=%d\n", tag, unmappedImg, mappedImg);
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    DWORD sz = GetFileVersionInfoSizeW(L"FakeGame.exe", nullptr);
    printf("FakeGame 启动 pid=%lu (version.dll query=%lu)\n", GetCurrentProcessId(), sz);
    DumpModules("t=0");
    for (int i = 1; i <= 6; ++i) {
        Sleep(5000);
        DumpModules(i == 1 ? "t=5s" : (i == 2 ? "t=10s" : (i == 3 ? "t=15s" : "t=+")));
    }
    return 0;
}
