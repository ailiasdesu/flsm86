// nocrt_a.cpp — 只调用 CreateFileW + CloseHandle（二分定位）
#include <windows.h>
extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE f = CreateFileW(L"C:\\temp\\flsm86\\marker_a.txt",
                               GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
        if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    }
    return TRUE;
}
