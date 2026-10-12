@echo off
rem ============================================================
rem  AES-128-CTR / CMAC performance comparison - quick run
rem  Runs both groups (hardware / pure software) and prints to
rem  the console ONLY. No file is written (--csv is not passed).
rem  Double-click this file, or run it from cmd.exe.
rem ============================================================
chcp 65001 >nul
setlocal
set "PATH=D:\AppGallery\dev-tools\msys64\mingw64\bin;%PATH%"
cd /d "%~dp0"

set "MAXMB=10"

echo ============================================================
echo  1/2  Default group - libraries use AES-NI when available
echo ============================================================
echo.
build-win\crypto_benchmark.exe --max-mb %MAXMB%
echo.

echo ============================================================
echo  2/2  Pure software group - AES-NI disabled
echo ============================================================
echo.
set "OPENSSL_ia32cap=~0x200000200000000"
build-win\crypto_benchmark_soft.exe --max-mb %MAXMB%
echo.

echo ============================================================
echo  Done. No file was written - --csv was not passed.
echo ============================================================
echo.
echo Press any key to close this window...
pause >nul
