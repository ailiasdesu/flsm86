// nocrt_b.cpp — 只调用 GetCurrentProcessId（ACE 通常不挂钩的基础 API）
#include <windows.h>
extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        volatile DWORD pid = GetCurrentProcessId();
        (void)pid;
    }
    return TRUE;
}
