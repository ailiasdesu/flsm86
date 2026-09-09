// nocrt_c.cpp — 只以只读方式打开一个系统文件（不创建/不写入）
#include <windows.h>
extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE f = CreateFileW(L"C:\\Windows\\win.ini", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    }
    return TRUE;
}
