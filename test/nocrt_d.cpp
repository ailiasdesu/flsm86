// nocrt_d.cpp — 调用 LoadLibraryW 加载一个未签名 DLL（模拟 mod 加载自己的 bundle）
#include <windows.h>
extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        HMODULE h = LoadLibraryW(L"C:\\temp\\flsm86\\svc\\nocrt_a.dll");
        (void)h;
    }
    return TRUE;
}
