// nocrt_f.cpp — 用 ntdll!NtProtectVirtualMemory 代替 kernel32!VirtualProtect
#include <windows.h>
typedef NTSTATUS(NTAPI* pNtPVM)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        HMODULE n = GetModuleHandleW(L"ntdll.dll");
        pNtPVM f = (pNtPVM)GetProcAddress(n, "NtProtectVirtualMemory");
        HMODULE k = GetModuleHandleW(L"kernel32.dll");
        if (f && k) {
            PVOID p = (PVOID)GetProcAddress(k, "CreateFileW");
            SIZE_T sz = 8; ULONG old = 0;
            if (p) {
                f(GetCurrentProcess(), &p, &sz, PAGE_EXECUTE_READWRITE, &old);
                f(GetCurrentProcess(), &p, &sz, old, &old);
            }
        }
    }
    return TRUE;
}
