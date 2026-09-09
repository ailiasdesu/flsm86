// empty_payload.cpp — 空 DllMain，无导入，用于隔离映射/桩本身的问题
#include <windows.h>
extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    return TRUE;
}
