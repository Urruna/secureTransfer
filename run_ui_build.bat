@echo off
rem ============================================================================
rem  SecureTransfer - 双击启动 build-win 里的图形界面
rem
rem  作用：临时把 MSYS2 的 mingw64\bin 加进本进程的 PATH（Qt5 DLL 与 MinGW
rem        运行时 DLL 都在那里），然后启动 build-win\st_ui.exe。
rem        只影响这个窗口，**不修改系统环境变量**。
rem
rem  用法：直接双击本文件；也可以带参数，例如：
rem        run_ui_build.bat --server --port 9000
rem        run_ui_build.bat --help
rem ============================================================================
chcp 65001 >nul
setlocal
set "MSYS_BIN=D:\AppGallery\dev-tools\msys64\mingw64\bin"
set "PROJECT_DIR=%~dp0"

if not exist "%MSYS_BIN%\Qt5Core.dll" (
    echo [警告] 找不到 %MSYS_BIN%\Qt5Core.dll
    echo        如果程序报 0xC0000135，请确认 MSYS2 的 qt5 已安装：
    echo        pacman -S mingw-w64-x86_64-qt5
)
set "PATH=%MSYS_BIN%;%PATH%"

cd /d "%PROJECT_DIR%"
if not exist "build-win\st_ui.exe" (
    echo [错误] 找不到 build-win\st_ui.exe，请先编译：
    echo        cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
    echo        cmake --build build-win
    echo.
    pause
    exit /b 1
)

echo 正在启动图形界面（工作目录 = 项目根目录，按 configs\keys.conf 读取密钥）...
echo 关闭这个窗口即结束程序。
echo.
"%PROJECT_DIR%build-win\st_ui.exe" %*
set "EXIT_CODE=%ERRORLEVEL%"

echo.
echo 界面已退出（退出码 %EXIT_CODE%）。
if not "%1"=="--help" pause
endlocal
