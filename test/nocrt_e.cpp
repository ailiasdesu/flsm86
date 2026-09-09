// nocrt_e.cpp — 只对 ACE 挂钩的函数做一次 VirtualProtect（不修改内容）
#include <windows.h>
extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        HMODULE k = GetModuleHandleW(L"kernel32.dll");
        if (k) {
            LPVOID p = (LPVOID)GetProcAddress(k, "CreateFileW");
            DWORD old = 0;
            if (p) {
                VirtualProtect(p, 8, PAGE_EXECUTE_READWRITE, &old);
                VirtualProtect(p, 8, old, &old);
            }
        }
    }
    return TRUE;
}
