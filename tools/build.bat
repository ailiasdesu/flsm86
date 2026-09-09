@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d C:\temp\flsm86\svc
cl /nologo /O2 /EHsc /W3 /utf-8 flsm86_svc.cpp /link /out:flsm86_svc.exe /subsystem:console
if errorlevel 1 exit /b 1
echo BUILD_OK
