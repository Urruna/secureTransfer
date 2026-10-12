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
set "PROJECT_DIR=%~dp0"

rem ---- 自动探测 MSYS2 的 mingw64（不再写死某一台机器的路径）----
rem  优先级：环境变量 MSYS2_ROOT → 本项目常用位置 → 默认安装位置
set "MSYS_ROOT="
if defined MSYS2_ROOT if exist "%MSYS2_ROOT%\mingw64\bin\Qt5Core.dll" set "MSYS_ROOT=%MSYS2_ROOT%"
if not defined MSYS_ROOT if exist "D:\AppGallery\dev-tools\msys64\mingw64\bin\Qt5Core.dll" set "MSYS_ROOT=D:\AppGallery\dev-tools\msys64"
if not defined MSYS_ROOT if exist "C:\msys64\mingw64\bin\Qt5Core.dll" set "MSYS_ROOT=C:\msys64"
if not defined MSYS_ROOT if exist "%USERPROFILE%\msys64\mingw64\bin\Qt5Core.dll" set "MSYS_ROOT=%USERPROFILE%\msys64"
if not defined MSYS_ROOT (
    echo [错误] 没找到 MSYS2 的 mingw64（缺 Qt5Core.dll）。
    echo        可以设一个环境变量 MSYS2_ROOT 指向 msys64 目录，例如：
    echo            set MSYS2_ROOT=D:\AppGallery\dev-tools\msys64
    echo        若还没装 Qt5：pacman -S mingw-w64-x86_64-qt5
    pause
    exit /b 1
)
set "MSYS_BIN=%MSYS_ROOT%\mingw64\bin"
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
