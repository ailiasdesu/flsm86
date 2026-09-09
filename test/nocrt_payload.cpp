// nocrt_payload.cpp — 最小载荷（不链接 CRT），用于验证手动映射本身
#include <windows.h>

extern "C" BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE f = CreateFileW(L"C:\\temp\\flsm86\\injected_marker.txt",
                               GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            WriteFile(f, "INJECTED-OK", 11, &w, nullptr);
            CloseHandle(f);
        }
    }
    return TRUE;
}
