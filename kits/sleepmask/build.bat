@echo off
rem ===================================================================
rem  cs_dev :: build_sleepmask.bat
rem  编译自定义 Sleep Mask 为 CS 可加载的 COFF 对象文件 (x64 / x86)
rem ===================================================================
setlocal
set MINGW=%~dp0..\..\..\_tools\mingw64\bin
if not exist "%MINGW%\gcc.exe" set MINGW=D:\mingw64\bin

set SRC=%~dp0sleepmask.c
set OUT=%~dp0..\..\build

if not exist "%OUT%" mkdir "%OUT%"

echo [*] 编译 sleepmask.x64.o ...
"%MINGW%\gcc.exe" -DWIN_X64 -shared -Wall -Wno-pointer-arith -O2 ^
    -fno-asynchronous-unwind-tables -fno-ident ^
    -c "%SRC%" -o "%OUT%\sleepmask.x64.o"
if errorlevel 1 goto :fail

echo [*] 编译 sleepmask.x86.o ...
"%MINGW%\gcc.exe" -DWIN_X86 -shared -Wall -Wno-pointer-arith -O2 -m32 ^
    -fno-asynchronous-unwind-tables -fno-ident ^
    -c "%SRC%" -o "%OUT%\sleepmask.x86.o" 2>nul
if errorlevel 1 echo    [!] 32 位编译跳过 (缺 i686 工具链, 不影响 x64 部署)

echo [+] 构建完成:
dir /b "%OUT%"
goto :eof

:fail
echo [-] 编译失败
exit /b 1
