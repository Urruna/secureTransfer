# 界面截图（实验证据）

本目录保存图形界面的实际截图，用于实验报告。

| 文件 | 场景 | 说明 |
| --- | --- | --- |
| `ui_server.png` | 图形界面作为**服务端**（Bob，角色 admin） | 命令行 Alice（管理员）驱动界面完成一次会话：4 条短消息 + WHOAMI + 查看审计日志 + 1 MB 文件（16 块）+ 图像（单包） |
| `ui_client.png` | 图形界面作为**客户端**（Alice，角色 admin） | 界面自动发送：中文短消息 + WHOAMI + 1 MB 文件 + 图像，对端为命令行 Bob |
| `windows_ui_client.png` | **Windows 主机**上的图形界面（客户端，Qt 5.15.19 / MSYS2 MinGW-w64） | 迁移后的界面：另一个 `st_ui` 实例作服务端，界面自动发送短消息 + 64 KB 文件 + WHOAMI，握手 7 步与传输结果都记在界面日志里 |
| `ui_redesign_server.png` | **2026-10-09 改版后** · 图形界面作为**服务端** | 标题条 / 工具条 / 三栏 / 状态栏；左栏握手 7 步全绿，右栏统计数字块 + 分级着色日志 |
| `ui_redesign_client.png` | **2026-10-09 改版后** · 图形界面作为**客户端** | 同上；中栏短消息为左右气泡，文件/图像传输结果与 Eve 攻击面板可见 |

## 截图是怎么产生的（可复现）

1. 在虚拟机的桌面会话里启动界面（`DISPLAY=:0`）：

   ```bash
   cd /home/securityTransfer/build
   ./st_ui --server --id bob --peer alice --port 9400 --auto \
       --out-dir /home/securityTransfer/experiment_data/received
   ```

2. 用命令行客户端驱动它：

   ```bash
   ./alice 127.0.0.1 9400 --id alice --whoami --view-log \
       --file test_file_1MB.bin --image test_image_256x256.png
   ```

3. 在虚拟机里用 `xwd` 抓取窗口，然后在主机上转成 PNG：

   ```bash
   DISPLAY=:0 xwd -id <窗口id> -silent > /tmp/ui_server.xwd
   # 主机侧：python xwd2png.py ui_server.xwd ui_server.png
   ```

   窗口 id 可用 `DISPLAY=:0 xwininfo -root -tree | grep SecureTransfer` 查到。

> 说明：`vmrun captureScreen` 抓的是虚拟机控制台画面，桌面处于黑屏/锁屏状态时只能抓到单色图；
> 从 X 会话里用 `xwd` 抓窗口更可靠（本目录的两张图就是这么来的，已验证颜色数 > 1000，不是空白图）。

一键复现脚本见 [`../../scripts/ui_demo.sh`](../../scripts/ui_demo.sh)。

## Windows 侧的截图（2026-10-01）

迁移到 Windows 后，界面用 MSYS2 的 `mingw-w64-x86_64-qt5`（Qt 5.15.19）编译，
在 Windows 桌面会话里可以正常显示与运行。截图由脚本启动两个 `st_ui` 实例
（一个 `--server --auto`，一个 `--client --auto` 并自动发送短消息 + 文件 + `WHOAMI`），
会话完成后用 `PrintWindow` 抓取客户端窗口：

```powershell
# 主机侧（PowerShell）
$env:PATH = "D:\AppGallery\dev-tools\msys64\mingw64\bin;" + $env:PATH
cd <项目目录>
.\build-win\st_ui.exe --server --auto --port 9821 --out-dir experiment_data\received_ui
.\build-win\st_ui.exe --client --auto --host 127.0.0.1 --port 9821 `
    --send-text "Hello-from-Windows-Qt5-UI" `
    --send-file experiment_data\test_file_64KB.bin --cmd WHOAMI
```

> 注意：`st_ui.exe` 依赖 `Qt5Core.dll` 等 DLL，运行前需要把
> `D:\AppGallery\dev-tools\msys64\mingw64\bin` 加进 `PATH`；
> 若要脱离 MSYS2 环境单独分发，需要用 `windeployqt` 打包（见 §23.8 剩余项）。

## 改版后的截图（2026-10-09）

改版后仍用 `PrintWindow` 抓取，但改成"同时开两个 `st_ui` 实例、两个窗口各抓一张"：

```powershell
# 1) 服务端（先起，等待接入）
.\build-win\st_ui.exe --server --auto --port 9000 --id bob --peer alice `
    --out-dir experiment_data\received_ui --access-log experiment_data\access_log_ui.txt
# 2) 客户端（自动发短消息 + 1 MB 文件 + 图像 + WHOAMI）
.\build-win\st_ui.exe --client --auto --id alice --peer bob --port 9000 `
    --send-text "你好，Bob，这是加密传输的消息" `
    --send-file experiment_data\test_file_1MB.bin `
    --send-image experiment_data\test_image_256x256.png --cmd WHOAMI
# 3) 抓窗口：Get-Process st_ui → MainWindowHandle → user32!PrintWindow(flag=2) → PNG
```

> 抓图脚本要先调用 `SetProcessDPIAware()`：本机是 200% 缩放，
> 非 DPI 感知的进程拿到的窗口尺寸会被系统缩放，抓出来的图会缺一块
> （实测会从 2186×1466 变成 1457×977）。
