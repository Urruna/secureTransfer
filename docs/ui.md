# 图形界面（课程要求 8）

> 课程要求 8：**有良好的人机交互界面、合适的应用需求分析、合理的应用设计**（加分项）。
> 本文说明界面的方案选择、功能设计、运行方式与已知限制。
>
> **2026-10-01 更新**：项目已迁移到 Windows，界面在 Windows 上也能编译运行
> （MSYS2 `mingw-w64-x86_64-qt5`，Qt 5.15.19），见本文 §10。

---

## 1. 结论摘要

| 项目 | 内容 |
| --- | --- |
| 技术栈 | **Qt 5.12 Widgets（C++）**，与安全内核同一进程，直接调用 `SecureSession` / `FileSender` / `AccessController` |
| 代码量 | 3 个源文件约 1100 行（`apps/ui/main.cpp`、`main_window.*`、`session_worker.*`） |
| 界面语言 | 中文（少量通用术语用英文，如 SessionId、CRC32、IMAGE） |
| 运行位置 | 虚拟机桌面（`DISPLAY=:0`） |
| 截图 | [`docs/screenshots/`](screenshots/README.md)（服务端视角 + 客户端视角各一张） |
| 关键设计 | **界面不实现任何密码学逻辑**：加密 / 完整性 / 认证 / 密钥分发 / 防重放 / 访问控制全部复用已有模块 |

## 2. 需求分析（界面要解决什么问题）

课程要求"使上述安全操作尽量对用户透明"。所以界面要解决三件事：

1. **用户不需要敲命令**：连接对象、端口、身份、策略都能在界面上选；
2. **安全过程可见但不需要理解**：握手每一步、会话标识、算法、角色权限、收发包统计都自动显示，
   用户只看到"已建立安全会话 / 已安全发送"；
3. **能演示与验证**：文件 / 图像传输有进度与校验结果，攻击演示有一键按钮，
   被访问控制拒绝时给出明确原因。

## 3. 界面分区

| 区域 | 控件 | 作用 |
| --- | --- | --- |
| 1. 连接与身份 | 角色（客户端/服务端）、对端地址、端口、本端身份、对端身份、密钥配置、访问策略、接收目录、审计日志、[启动/连接] [断开] | 一个界面既能当 Alice 也能当 Bob；身份可从 alice / eve / mallory / bob 里选 |
| 2. 安全会话状态 | 状态灯 + 会话信息（SessionId、NonceA/B、我的角色与权限） | 会话是否建立一目了然；SessionId 与 Nonce 是"本次会话"的指纹 |
| 3. 统计与访问控制 | 收发统计（收发包数、拒绝计数）+ [查询我的角色] [查看审计日志] | 对应 `CMD WHOAMI` / `CMD VIEW_LOG`；后者仅管理员可用 |
| 4. 短消息 | 历史记录 + 输入框 + [发送] | 明文直接输入，加密在后台完成 |
| 5. 文件 / 图像传输 | [选择文件…] [选择图像…] + 进度条 + 结果标签 | 走第四轮实现的分块 / 单包传输，显示 CRC32 校验结果 |
| 6. Eve 攻击演示 | [篡改上一个数据包并重发] [原样重放上一个数据包] | 一键验证完整性保护与防重放（对端会拒绝并记录） |
| 7. 运行日志 | 滚动日志 | 握手每一步、访问控制判定、传输细节都写在这里 |

## 4. 关键设计决策

### 4.1 线程模型：安全会话跑在独立线程

`SecureSession::receiveMessage()` 是阻塞调用，直接放在 GUI 线程里会让界面卡死。
因此：

* **GUI 线程**只画界面，把"发消息 / 发文件 / 发命令"塞进一个加锁队列；
* **工作线程**独占 `SecureSession`（该对象不是线程安全的），循环做
  "先执行队列里的命令 → 再调用 `tryReceiveMessage(type, body, 100)` 等数据"；
* 结果通过 Qt 信号发回 GUI 线程（自动跨线程排队），界面始终可交互。

**消息延迟**：`tryReceiveMessage()` 内部用 `select()` 等"可读"，对端一发数据就立刻返回，
所以消息的显示延迟不受那个 100 ms 空闲等待限制；100 ms 只是"没有数据时，最多隔多久
再回头看一眼命令队列"的上限，也就是说点击"发送"最多延迟 100 ms 执行。

> 2026-10-01 之前这里是"用 250 ms 超时接收 + 把超时当没有数据"：
> 既让消息最多晚 250 ms 显示，又会为每次超时打一行 ERROR 日志（空闲几秒就是几百行）。
> 现在这版实现消除了这两个问题，见 `Part2_transfer.md` §24。

### 4.2 界面与安全内核解耦

界面**没有**任何加密、MAC、密钥派生代码，只是调用：

```cpp
SecureSession      // 握手 + 加密数据通道
transfer::FileSender / TransferReceiver   // 文件 / 图像
access::AccessController                  // 访问控制与审计
```

这样既满足课程要求 4（密码算法必须自己写，且不会被界面"绕过"），
也意味着界面代码量小（约 1100 行）而功能完整。

### 4.3 可脚本化（`--auto`）

界面支持命令行参数，便于演示与自动截图：

```bash
./st_ui --help
./st_ui --server --id bob --peer alice --port 9400 --auto
./st_ui --client --auto --send-text "你好" --cmd WHOAMI \
    --send-file /path/test_file_1MB.bin --send-image /path/test_image_256x256.png
```

## 5. 界面截图

![服务端视角](screenshots/ui_server.png)

上图：图形界面作为**服务端**接收命令行 Alice 的消息、ACCESS/审计、1 MB 文件与图像。

![客户端视角](screenshots/ui_client.png)

上图：图形界面作为**客户端**，自动发送中文短消息、查询角色、发 1 MB 文件与图像。

（截图的获取方式见 [`screenshots/README.md`](screenshots/README.md)。）

## 6. 实测结果

在虚拟机桌面里跑完整流程（`scripts/ui_demo.sh`）：

| 场景 | 结果 |
| --- | --- |
| 图形界面作服务端（Bob, admin） | 命令行 Alice 驱动：4 条短消息 + `WHOAMI` + `VIEW_LOG` + 1 MB 文件（16 块，CRC32 校验通过）+ 图像（单包，147 KB），界面日志完整记录握手 7 步 |
| 图形界面作客户端（Alice, admin） | 界面自动发送：中文短消息（对端显示 `你好，Bob，这是从图形界面发出的安全消息。`）+ `WHOAMI` + 1 MB 文件 + 图像，全部成功 |
| 访问控制 | 界面显示角色与权限；被拒绝的操作在日志里给出 `【访问控制拒绝】…` 并说明原因 |
| 审计日志 | 本轮共 51 条 ALLOW/DENY 记录（与命令行版本行为一致） |

## 7. 运行方式

```bash
# 1. 虚拟机里安装 Qt 开发包（只需一次，约 100 MB）
sudo apt install -y qtbase5-dev

# 2. 编译（Qt 不存在时该目标会自动跳过，不影响命令行程序）
cd /home/securityTransfer && mkdir -p build && cd build
cmake .. && cmake --build . -j4
ls -l st_ui

# 3. 在桌面会话里运行
DISPLAY=:0 ./st_ui
```

一键演示（含自动截图）：

```bash
bash scripts/ui_demo.sh          # 需要虚拟机桌面会话（DISPLAY=:0）
```

## 8. 已知限制

1. ~~接收采用 250 ms 轮询、消息最多延迟 250 ms~~ —— 已解决（2026-10-01）：
   `SecureSession::tryReceiveMessage()` 内部用 `select()` 等可读，数据一到立即返回；
2. ~~判断"接收失败是不是超时"依赖错误文本~~ —— 已解决：
   新接口把结果分成 `kMessage` / `kNothing` / `kClosed` 三种，不再靠错误文本猜测；
3. 界面一次只服务一个会话（与命令行版本一致，服务端单连接）；
4. 文件发送在界面上是"选一个发一个"，没有做发送队列 / 断点续传；
5. 攻击演示按钮会**导致对端拒绝并终止会话**（这正是演示目的），演示后需要重新连接。

## 9. 本轮发现并修复的问题（值得写进复盘）

第一次用"图形界面作客户端 + 命令行 Bob"联调时，出现了**消息死循环**：
界面收到 Bob 的确认消息后又自动回了一条确认，Bob 再回确认……短时间内产生了
**34,000+ 条消息、12.8 MB 审计日志**。

原因：两端都对"收到的消息"自动回确认，而确认本身也是消息。

修复：约定**自动回复统一以 `ACK:` 开头**，收到 `ACK:` / `FILE OK` / `ROLE ` /
`AUDIT LOG` 等"回复型"消息时不再自动回复（`include/common/demo_reply.h`）。
修复后同样的演示只产生 51 条审计记录。

教训：**任何"自动回应"机制都必须有终止条件**；演示用的自动回复虽然与安全性无关，
但同样会把系统打爆。这也说明"端到端联调"不能只测理想路径。

---

## 10. Windows 侧运行（2026-10-01，迁移后）

| 项 | Linux（原） | Windows（迁移后） |
| --- | --- | --- |
| Qt | Qt 5.12 Widgets（`qtbase5-dev`） | Qt **5.15.19**（MSYS2 `mingw-w64-x86_64-qt5`） |
| 编译器 | g++ 9.4.0 | MinGW-w64 g++ 16.2.0 |
| 构建 | `cmake .. && cmake --build .` | `cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build-win` |
| 结果 | 可运行，截图 `ui_client.png` / `ui_server.png` | **0 错误 0 警告**；可运行，截图 `windows_ui_client.png` |
| 代码改动 | — | **界面代码零改动**（只加了 `stconsole::ensureUtf8()` 一行，解决控制台中文乱码） |

**运行注意**：`st_ui.exe` 依赖 `Qt5Core.dll / Qt5Gui.dll / Qt5Widgets.dll`，
直接双击会因为找不到 DLL 而失败（错误码 `0xC0000135`）。把
`D:\AppGallery\dev-tools\msys64\mingw64\bin` 加进 `PATH` 即可；
或者用 `windeployqt` 打包后单独分发。

**自动化验证**（不需要人工点击）：界面支持 `--auto` 与 `--send-text / --send-file / --cmd`，
两个实例就能跑完整会话（离屏平台 `QT_QPA_PLATFORM=offscreen` 也行）：

```bash
./build-win/st_ui.exe --server --auto --port 9820 --out-dir experiment_data/received_ui &
./build-win/st_ui.exe --client --auto --host 127.0.0.1 --port 9820 \
    --send-text "Hello from Qt UI on Windows" \
    --send-file experiment_data/test_file_64KB.bin --cmd WHOAMI
```

实测：握手 7 步全部完成；`ALLOW alice(admin) send_message / send_file`；
文件 65536 字节、1 块、CRC32 校验通过，接收文件 sha256 与源文件一致。

**日志噪声问题（已解决）**：早期版本空闲时每 250 ms 就会打一行
`recv() 超时，已接收 0/4 字节`（ERROR 级），几秒钟几百行。
现已改为 `SecureSession::tryReceiveMessage()`：没有数据时返回 `kNothing`，
不产生任何错误日志。同一场景实测：客户端日志从 **352 行降到 11 行、超时行 0 条**
（服务端 15 行、超时 0 条），文件传输与访问控制判定不受影响。

---

## 11. 2026-10-06 修复的五个使用问题

### 11.1 非最大化时"选项框文字只显示一半"

**现象**：窗口不是最大化时，下拉框/按钮里的文字看起来被压扁、只剩半行。

**根因**：默认窗口是 1180×760，在小屏幕（或被系统缩放过的桌面）上会被压缩；
而布局在空间不足时会继续把控件往下压（按钮被压到 28 px，而它自身需要 34 px），
文字就被裁掉了；左列又没有滚动区，只能硬挤。

**修法**：

1. 默认尺寸改为 1120×700，并设 `setMinimumSize(960, 640)`——再小也不会压变形；
2. 每个输入类控件的最小高度设成**它自己的 `sizeHint().height()`**（按钮 34 px、输入框 28 px），
   布局不可能再把文字压掉；
3. 左列（连接/状态/统计）放进 `QScrollArea`：高度不够时出现滚动条，而不是挤压；
4. 消息历史与运行日志在垂直方向设 `QSizePolicy::Ignored`：
   它们的 `sizeHint`（内容越长越大）不再撑大布局，长度增长只影响自身滚动条。

**怎么验证**（新增诊断开关，任何人都能自查）：

```powershell
.\build-win\st_ui.exe --print-geometry                 # 默认尺寸
.\build-win\st_ui.exe --geometry 960x640 --print-geometry   # 最小尺寸
```

输出每个控件的实际高/最小高/建议高。实测结果：默认与最小尺寸下，
所有按钮与输入控件的实际高度都 ≥ 自身 sizeHint（只有两个可滚动的文本区低于 sizeHint，
那是有意为之）。截图见 `docs/screenshots/windows_ui_layout_default.png` 与
`windows_ui_layout_min.png`。

### 11.2 只能传英文路径，中文路径的文件发不出去

**根因**：Windows 上 `std::ifstream` / `std::ofstream` / `::_mkdir` 的窄字符接口
按 **ANSI 代码页（简体中文系统 = GBK）** 解释路径，而本工程内部统一用 UTF-8，
于是"带中文的文件名/目录名"打不开（Linux 下路径本身就是字节串，所以没这个问题）。

**修法**（`include/common/path_utils.h`）：

* 新增 `openInputFile()` / `openOutputFile()`：Windows 下先把 UTF-8 转成宽字符再打开；
* `ensureDirectory()` 改用 `_wmkdir`，并正确处理盘符（`D:\...` 不再尝试创建 "D:"）；
* 命令行参数改用 `GetCommandLineW + CommandLineToArgvW` 转 UTF-8
  （`include/common/text_encoding.h`），所以 `--file D:\测试\图像.png` 也能用。

**验证**：新增用例「中文文件名与中文接收目录也能传输」，
在 Windows 与 Ubuntu 两边都通过；界面里也实测跑通
（一个界面实例从中文目录发中文名文件，另一个界面实例收进中文目录，sha256 一致）。

### 11.3 点"断开"后一直停在"正在结束会话…"，只能重启程序

**两个根因（都修了）**：

1. **服务端线程卡死在 `accept()`**：以前的 `accept()` 是永久阻塞的，
   在"等待客户端接入"时点断开没有任何效果，线程不退出；
2. **界面收不到结束通知**：主动断开时工作线程退出循环后没有发 `sessionStopped`，
   所以界面状态与按钮永远停在"会话中"，看起来像死机。

**修法**：

* `Network` 新增 `waitAcceptable(timeoutMs)`（在监听 socket 上 select）；
* `SecureSession::acceptOneClient(waitMs)` 支持分片等待：超时返回 `false`
  但**监听保持有效**，可以继续重试（`lastAcceptTimedOut()` 区分"超时"与"真失败"）；
* 界面工作线程用 200 ms 分片等待客户端，每片都检查"是否点了断开"，
  并在退出循环时**统一补发** `sessionStopped`，界面立即复位。

**验证**：新增用例「`acceptOneClient(超时)` 可被打断，且监听保持有效」
（Windows + Linux 都通过）：先超时返回、确认 state 未失败、随后仍能成功接受真实客户端并完成握手。

### 11.4 运行日志里的 `WSA error ...(乱码)` 

**根因**：Windows 上 `std::system_category().message(code)` 返回的是**本地代码页（GBK）**文本，
被当成 UTF-8 输出就变成乱码。

**修法**：`Network::describeError()` 的 Windows 分支改用 `FormatMessageW` 取宽字符，
再转成 UTF-8。现在会正常显示为：

```text
connect() 失败: WSA error 10061 (由于目标计算机积极拒绝，无法连接。)
```

**验证**：新增用例「连接失败的错误信息是合法 UTF-8」（Windows + Linux 都通过）。

### 11.5 支持两台主机通信吗？

**支持**，这也是课程要求 6。两种用法都在 `docs/lan_test.md` 里有实测记录：

* **命令行**：A 机跑 `bob <端口>`（监听），B 机跑 `alice <A机IP> <端口>`；
* **图形界面**：一端角色选"服务端（Bob）"点"启动/连接"等待；另一端选"客户端（Alice）"，
  "对端地址"填对方的 IP、端口两边一致，点"启动/连接"。

需要注意三件事：

1. **K_master 必须相同**：两端 `configs/keys.conf` 里的 `master_key` 要一致，
   否则握手会报"认证失败"（这是设计如此，不是 bug）；
2. **身份要对得上**：服务端的"对端身份"应等于客户端的"本端身份"（默认 bob / alice）；
3. **网络要通**：两台机器能互相 ping 通；Windows 首次监听会弹防火墙提示，要选"允许"，
   或提前放行该端口（跨网段/路由器还需要端口映射）。

已实测：Windows（物理机）↔ Ubuntu 621（虚拟机）双向通信成功，
接收文件 sha256 与源文件一致；Linux 侧还有网络命名空间模拟的两台独立主机测试。
