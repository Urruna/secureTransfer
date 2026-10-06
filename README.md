# SecureTransfer — 安全的信息传输套件

> 课程项目《安全的信息传输套件》的工程实现。
> 本仓库当前覆盖 **第一部分（AES 成果的接入与回归）** 与 **第二部分（安全通信协议与网络）**；
> 第三部分（UI / 文件 / 图像 / 访问控制 / Eve 演示界面）已在
> `apps/ui/`、`src/application/`、`src/security/access_control.cpp` 中实现并实测；
> 另外本项目**已从 Linux 运行环境迁移到 Windows**（MSYS2 MinGW-w64），
> 两端各有一套实测数据（见 `Part2_transfer.md` §23）。

**验证状态**

> **只想拿 Windows 图形界面来用？** 不用编译、不用装 Qt/MSYS2：
> 到 **[Releases](https://github.com/Urruna/secureTransfer/releases/latest)**
> 下载 `securityTransfer-ui-win64.zip`（约 32 MB），解压后把
> `configs\keys.conf.example` 复制成 `configs\keys.conf` 并填好 K_master，
> 双击 `run_ui.bat` 即可。也可以用一行命令自动获取：
> `powershell -ExecutionPolicy Bypass -File scripts\get_ui.ps1 -Token <你的GitHub token>`
> （仓库是私有的，需要 token 或登录；脚本细节见 §4.4）

| 环境 | 编译 | 测试 | 端到端 | 备注 |
| --- | --- | --- | --- | --- |
| Ubuntu 20.04 虚拟机（Ubuntu6.21，g++ 9.4.0） | 0 错误 0 警告 | `ctest` **16/16** | 4 条测试消息 + 4 个文件/图像逐字节一致 | 局域网双机 + 抓包证据；性能对比（OpenSSL 1.1.1） |
| Windows 主机（MSYS2 MinGW-w64，g++ 16.2.0） | 0 错误 0 警告 | `ctest` **16/16** | 4 条测试消息 + 4 个文件/图像逐字节一致 | 跨系统双机（Windows Alice ↔ Ubuntu Bob，双向）；性能对比（OpenSSL 3.6.5）；Qt 界面（Qt 5.15.19）已编译并跑通一次会话 |

篡改 / 伪造 / 重放 / 窃听四项安全测试在两端全部通过；
密码算法与 OpenSSL 完成 1 KB ~ 100 MB 的性能对比（含"禁用 AES-NI 的纯软件对比"）。

**想了解什么，看哪个文件：**

| 想了解什么                                   | 文件                                                                                      |
| -------------------------------------------- | ----------------------------------------------------------------------------------------- |
| 项目总览、架构、运行方式                     | 本文件（`README.md`）                                                                   |
| **当前进展、决策记录、每一轮做了什么** | **[`Part2_transfer.md`](Part2_transfer.md)**                                       |
| 功能测试与攻击测试的实测数据                 | [`docs/test_report.md`](docs/test_report.md)                                             |
| 与库实现的性能对比（要求 5）                 | [`docs/performance.md`](docs/performance.md)                                             |
| 局域网双机通信测试（要求 6）                 | [`docs/lan_test.md`](docs/lan_test.md)                                                   |
| **文件与图像传输（要求 9）与实验数据** | **[`docs/file_transfer.md`](docs/file_transfer.md)**、[`experiment_data/`](experiment_data/)    |
| **访问控制（要求 7）**                 | **[`docs/access_control.md`](docs/access_control.md)**                             |
| **图形界面（要求 8）与截图**           | **[`docs/ui.md`](docs/ui.md)**、[`docs/screenshots/`](docs/screenshots/README.md) |
| **Windows 迁移：改了什么、两端实测数据** | **[`Part2_transfer.md`](Part2_transfer.md) 的 §23（M2–M6）**                   |
| **窃听攻击证据（Eve 只能看到密文，Windows/tshark 跨机抓包）** | **[`docs/eavesdrop.md`](docs/eavesdrop.md)**、[`experiment_data/captures/`](experiment_data/captures/) |
| 课程要求逐条对照                             | [`docs/requirements.md`](docs/requirements.md)                                           |
| 协议格式与流程细节                           | [`docs/protocol.md`](docs/protocol.md)、[`docs/interfaces.md`](docs/interfaces.md)      |

**密码算法状态：AES-128 与 CMAC 均已由第一部分交付并集成**——
CMAC 通过 RFC 4493 的 4 条标准向量验证，AES 通过 FIPS-197 与 NIST SP 800-38A 向量验证
（见 `tests/unit/test_aes_cmac.cpp`），数据通道的完整性保护具备真实密码学强度。

---

## 1. 这个项目解决什么问题

Alice 和 Bob 只能通过不安全的网络通信，Eve 可以窃听、篡改、假冒、重放。
本项目让 Alice 和 Bob 在**完全不可信的网络**上安全交换信息，达到四个目标：

| 目标                       | 手段                                                                   | 对应课程要求 |
| -------------------------- | ---------------------------------------------------------------------- | ------------ |
| 机密性（Eve 看不懂）       | AES-128-CTR（自己实现，不用库）                                        | 要求 2       |
| 完整性（改一个字节就发现） | CMAC（RFC 4493，Encrypt-then-MAC）                                     | 要求 3       |
| 身份认证（Eve 假冒不了）   | `K_master` 预共享 + Challenge-Response                               | 要求 7       |
| 会话密钥分发（要求 1）     | `K_session` 用 `K_master` 包裹传输 + 双方 `KEY_CONFIRM` 确认     | 要求 1       |
| 防重放                     | Sequence 严格递增 + SessionId 绑定 + 结构化 Nonce                      | 要求 7       |
| 真实网络传输               | TCP（本机 loopback 或局域网两台主机）                                  | 要求 6       |
| 多种信息                   | 短消息 / 文件（64 KiB 分块）/ 图像（小图单包、大图分块），同一安全通道 | 要求 9       |
| 访问控制                   | 身份 → 角色 → 权限（服务端权威判定 + 审计日志，改策略不改代码）      | 要求 7       |

1. AES-128-CTR：采用AES算法，128位分组，CTR工作模式。保证密钥不重复（nonce+counter），但无法实现密钥不可篡改+认证（confidentiality）
2. AES-CMAC：**T**=**CMACk**(**M**)(integrity)，针对密文的认证。bob先验证CMAC，再解密。基于 **CBC-MAC** 思想构造的，注意最后一个message block不满足128bits的情况
3. K-master：通信之前，双方就已经安全地共享，PSK（Pre-Shared Key，预共享密钥）。B发送Nonce_B，A回复Response = CMAC(K_master, N_B)，B同样的方法验证。
4. Challenge：随机 Challenge 防止旧认证信息被重复使用，mutual authentication。
5. context binding（上下文绑定）：CMACK(Alice∥AnotherServer∥N)，更强的认证，比如知道对方是Alice
6. `K_session` 用 `K_master` 包裹传输：指用K-master作为密钥，用CMAC将K-session传出。当然可以考虑K-master+Nonce（本次通信需要产生的随机数）+context代替K-session（因为K-session的本质是保证每次会话是独立的不同的会话，且能够进行验证）防止旧会话的消息混入新会话
7. 每条消息：SessionId + Sequence + Nonce + Ciphertext + Tag
   1. 此处sequence就是对话序号，标识对话进行到哪一步，必需严格递增，防止当前会话出现处理过的旧消息。
   2. sessionid不同会话间的重放
   3. 结构化nonce：例如sessionid-specific random prefix || sequence
8. 未来UI设计：在windows利用Qt实现，但实际网络传输在linux中

## 2. 当前的实现状态

**已完成并验证**

* 统一数据包格式（41 字节包头 + 16 字节 MAC），编解码与全部非法输入拒绝；
* 握手状态机：`HELLO → HELLO_ACK → AUTH → KEY_REQUEST → KEY_EXCHANGE → KEY_CONFIRM → KEY_CONFIRM_ACK`；
* 基于 `K_master` 的双向身份认证（Nonce 挑战-响应 + 方向标签，防重放与反射）；
* 会话密钥 `K_session = 000102...0F` 的包裹分发与双向确认；
* 数据通道：AES-128-CTR 加密 + MAC 完整性 + Sequence 防重放 + SessionId 绑定；
* 会话状态机、握手超时、协议统计（拒绝计数）；
* 4 条课程要求的测试消息端到端验证（短文本 / 英文 / 长文本特殊字符 / 中文 UTF-8 + 二进制）；
* 安全测试：篡改、身份伪造、数据包重放、窃听（tcpdump 抓包检索明文）；
* **文件与图像安全传输**：文件走 `FILE_START/CHUNK/END` 分块，小图像走单包 `IMAGE`，
  大图像自动分块；接收端重组后校验总字节数与整文件 CRC32，实测逐字节一致
  （64 KB / 1 MB 文件、147 KB / 2.2 MB 图像，见 `docs/file_transfer.md`）；
* **访问控制**：身份 → 角色 → 权限（`configs/access_policy.conf`），服务端权威判定；
  越权操作被拒绝但不影响会话，全部允许/拒绝写审计日志；管理员可用 `--view-log` 查看
  （见 `docs/access_control.md`）；
* **图形界面（Qt5）**：连接与身份配置、会话状态、短消息、文件与图像传输（进度条 +
  校验结果）、访问控制查询、Eve 攻击演示按钮、运行日志；**界面不实现任何密码学逻辑**，
  只调用已有模块（见 `docs/ui.md`）；
* 与库实现的性能对比：AES-CTR / CMAC × 1 KB ~ 100 MB，含禁用 AES-NI 的纯软件对比（`docs/performance.md`）；
* 局域网双机通信：两台独立主机（独立 IP 栈）经以太网链路完成握手与传输，附抓包证据（`docs/lan_test.md`）。

**状态与明确限制**

| 项                          | 现状                                               | 备注                                                                          |
| --------------------------- | -------------------------------------------------- | ----------------------------------------------------------------------------- |
| 要求的 1~7 项功能           | ✅ 已实现并实测                                    | 见`docs/requirements.md` 的逐条对照                                         |
| AES-128 / AES-CTR           | ✅ 已集成（第一部分交付，`src/crypto/aes.cpp`）  | FIPS-197 + NIST SP 800-38A 向量验证                                           |
| CMAC                        | ✅ 已集成（第一部分交付，`src/crypto/cmac.cpp`） | RFC 4493 的 4 条标准向量验证                                                  |
| 性能对比 benchmark          | ✅ 已完成（`tools/crypto_benchmark`）            | 与 OpenSSL 对比，覆盖 1 KB~100 MB：`docs/performance.md`                    |
| 局域网 / 双机测试           | ✅ 已完成（`scripts/lan_test.sh`）               | 两台独立主机 + 抓包证据；真机双机命令见`docs/lan_test.md`                   |
| 文件 / 图像传输             | ✅ 已完成（`src/application/`）                  | 分块 + 单包两条路径，含整文件 CRC32 校验与实验数据：`docs/file_transfer.md` |
| 访问控制（Role/Permission） | ✅ 已完成（`src/security/access_control.cpp`）   | 策略可配置、服务端权威判定、审计日志：`docs/access_control.md`              |
| Qt/图形界面                 | ✅ Linux 已完成（`apps/ui/`，Qt 5.12 Widgets）   | 需要`qtbase5-dev`；截图见 `docs/screenshots/`，说明见 `docs/ui.md`    |
| Windows 侧编译与测试 | ✅ 已完成（MSYS2 MinGW-w64） | 0 错误 0 警告，`ctest` 16/16；见 `Part2_transfer.md` §23.3 |
| Windows 侧 Qt 界面 | ✅ 已完成（MSYS2 Qt 5.15.19） | 0 错误 0 警告；截图 `docs/screenshots/windows_ui_client.png`；说明见 `docs/ui.md` §10 |
| 跨系统双机（Windows ↔ Ubuntu） | ✅ 已完成（双向） | 两个方向各跑完整会话，接收文件 sha256 逐字节一致；见 `Part2_transfer.md` §23.6 |
| 前向保密                    | 不支持                                             | 预共享密钥方案的固有限制（`K_master` 泄露则历史会话可解）                   |
| 抗 DoS                      | 不设计                                             | 未认证的 HELLO 也会被处理                                                     |

> 算法与协议是解耦的：`CryptoProvider` / `MacEngine` 是唯一接缝。
> 若需要演示"算法可替换"，可用 `--placeholder` 参数切换到占位 MAC
> （此时程序会打印警告，说明完整性保护不具备密码学强度）。

## 3. 目录结构

```text
securityTransfer/
├── CMakeLists.txt
├── README.md
├── configs/
│   ├── keys.conf.example     # K_master 与身份配置模板（提交进版本管理）
│   ├── keys.conf             # 实际使用的密钥文件（600 权限，已被 .gitignore 排除）
│   ├── access_policy.conf    # 访问控制策略（角色 / 权限 / 身份映射）
│   └── demo_config.conf      # 协议与演示参数记录
├── Part2_transfer.md         # 第二部分的完整方案与实施进度记录
├── include/
│   ├── application/          # 文件 / 图像传输（第三部分）：crc32 / transfer_meta / file_transfer
│   ├── common/               # types / byte_buffer / random / hex / constant_time / log
│   ├── crypto/               # AES / CMAC（第一部分成果）+ CryptoProvider / MacEngine 接缝
│   ├── network/              # 第一阶段成果：Frame / Network（未改动）
│   ├── protocol/             # message_type / packet / transcript
│   └── security/             # keystore / replay_guard / session
├── src/                      # 与 include 对应的实现（application / crypto / network / protocol / security）
├── apps/
│   ├── alice/main.cpp        # 客户端：握手 + 4 条测试消息
│   ├── bob/main.cpp          # 服务端：握手 + 校验 + 回复 + 统计
│   └── ui/                   # 图形界面（Qt5）：main / main_window / session_worker
├── tests/
│   ├── unit/                 # aes_cmac / packet / transcript / replay_guard / session_state / transfer_meta / frame / network
│   └── integration/          # tcp_roundtrip / secure_roundtrip / file_transfer / tamper / forge / replay
├── experiment_data/                  # 实验数据（文本 / 二进制文件 / 两张 PNG）+ received/（接收结果，主机与虚拟机各一份）
├── scripts/
│   ├── verify_in_vm.sh       # 一键：编译 + ctest + 演示 + 攻击测试
│   ├── capture_eve.sh        # 抓包演示（Eve 窃听）
│   ├── lan_test.sh           # 局域网双机测试（单机模拟两台主机 / 真机双机）
│   └── deploy_to_home.sh     # 部署到 /home/securityTransfer
├── tools/
│   ├── cmac_benchmark.cpp    # CMAC 性能测试（第一部分成果的加工程序）
│   └── crypto_benchmark.cpp  # 与 OpenSSL 的性能对比（要求 5；⚠ 只有它链接密码库）
├── reference/
│   ├── part1-aes-cmac/       # 第一部分交付原件存档（Windows 工程，不参与构建）
│   └── aes-c-legacy/         # 更早的 C 版 AES 实现（已被 C++ 版取代，留档）
└── docs/
    ├── project_q1.md         # 课程原始需求文档
    ├── team_interfaces_original.md                # 组内接口约定
    ├── requirements.md       # 课程要求 vs 实现状态对照
    ├── architecture.md       # 分层、模块、依赖方向
    ├── protocol.md           # 数据包格式与协议流程（核心）
    ├── interfaces.md         # 对外接口说明
    ├── development.md        # 编译、运行、扩展指南
    ├── test_report.md        # 实测结果（含攻击测试数据）
    ├── performance.md        # 性能对比报告（自实现 vs OpenSSL，要求 5）
    ├── lan_test.md           # 局域网双机测试报告（要求 6）
    ├── file_transfer.md      # 文件与图像传输说明 + 实测数据（要求 9）
    ├── access_control.md     # 访问控制：策略、判定流程、实测数据（要求 7）
    ├── ui.md                 # 图形界面：方案选择、功能设计、截图、已知限制（要求 8）
    ├── screenshots/          # 界面截图（服务端视角 / 客户端视角）+ 获取方法
    └── stage1/               # 第一阶段（纯 TCP）文档存档（含历史说明，见其中的 README）
```

## 4. 编译与运行（Ubuntu）

```bash
cd /home/securityTransfer
mkdir -p build && cd build
cmake .. && cmake --build . -j4
ctest --output-on-failure
```

一键脚本（编译 + 测试 + 演示 + 攻击测试）：

```bash
bash scripts/verify_in_vm.sh
```

手工演示（两个终端）：

```bash
# 终端 1
cd /home/securityTransfer/build && ./bob 9000
# 终端 2
cd /home/securityTransfer/build && ./alice 127.0.0.1 9000
```

> `bob` 默认是**常驻服务**：可以连续服务多个客户端，用 `Ctrl+C` 结束；
> 单个客户端握手失败（例如别人连上就断）不会再让服务退出，整次握手还有总时长上限。
> 只想服务一个客户端就退出（脚本/测试用）加 `--once`；服务 N 次后退出用 `--max-sessions N`。

窃听演示：

```bash
bash scripts/capture_eve.sh 9000 "Hello Bob"
```

### 4.1 Windows（MSYS2 MinGW-w64）

```bash
# 在 MSYS2 的 MinGW64 shell 中执行
cd /d/AppGallery/codex/Urruna_codex_OS/projects/securityTransfer
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-win -j8
ctest --test-dir build-win --output-on-failure

./build-win/bob.exe 9000
./build-win/alice.exe 127.0.0.1 9000
```

说明：

* Windows 用 `build-win/`，Linux 用 `build/`，两者都在 `.gitignore` 里，互不干扰；
* 控制台中文不会乱码（程序启动时自动把代码页切到 UTF-8）；
* 需要 MSYS2 的 `mingw-w64-x86_64-gcc / cmake / ninja`；性能对比工具还需要 `mingw-w64-x86_64-openssl`；
* Qt 界面（`st_ui`）需要 MSYS2 的 `mingw-w64-x86_64-qt5`（已安装，Qt 5.15.19）；
  找不到 Qt5 时 CMake 会自动跳过该目标，不影响 `alice` / `bob` 与全部测试。
  运行 `st_ui.exe` 前要把 `D:\AppGallery\dev-tools\msys64\mingw64\bin` 加进 `PATH`
  （否则会因缺少 `Qt5Core.dll` 等报 `0xC0000135`）。
  嫌麻烦就直接**双击项目根目录的 `run_ui_build.bat`**：它只在当前窗口临时设好 PATH，
  然后启动 `build-win\st_ui.exe`（不改系统环境变量，也可带参数，如
  `run_ui_build.bat --server --port 9000`）。

### 4.2 Windows 打包（脱离 MSYS2 独立运行）

```bash
# 在 MSYS2 的 MinGW64 shell 中执行
bash scripts/package_windows.sh
```

输出到 `dist/securityTransfer/`（约 75 MB），内容：

* `alice.exe` / `bob.exe` / `st_ui.exe`；
* Qt5 DLL（由 `windeployqt-qt5` 部署）＋ `platforms/qwindows.dll` 等插件；
* MinGW 运行时 DLL（`libstdc++-6` / `libgcc_s_seh-1` / `libwinpthread-1`，
  以及 Qt 自己依赖的 `icu*`、`zlib1`、`harfbuzz`、`pcre2` 等，脚本用"依赖传递闭包"自动补齐）；
* `configs/`（只含 `keys.conf.example`，**不含真实密钥**）与 `experiment_data/`；
* 双击即可用的 `run_bob.bat` / `run_alice.bat` / `run_ui.bat`。

使用前把 `configs/keys.conf.example` 复制成 `configs/keys.conf` 并填好 K_master。
`dist/` 已被 `.gitignore` 排除（几十 MB 的 DLL 不入库），需要时重新跑脚本即可。
已验证：在**只有系统目录的 PATH** 下（不依赖 MSYS2）三个程序都能正常跑完整会话。

### 4.3 Windows 窃听演示（Wireshark / tshark）

```powershell
# 管理员权限运行；默认在 Ubuntu 虚拟机里启动 Bob，在本机跑 Alice 并抓 VMnet8 的包
python scripts/capture_eve_windows.py --file experiment_data/test_file_64KB.bin
```

会把 `.pcapng` 与解析报告写进 `experiment_data/captures/`，
报告里逐包列出 Type / SessionId / Sequence / Nonce / 密文 / CMAC，
并检索"明文关键字、文件内容、K_master、K_session"，期望命中 0 次
（实测结论见 [`docs/eavesdrop.md`](docs/eavesdrop.md)）。

### 4.4 让别人拿到界面：Release 分发 + CI 自动出包

**给别人用的下载入口**（仓库为私有，需要对方是 collaborator 并登录 GitHub）：

* 固定链接：`https://github.com/Urruna/secureTransfer/releases/latest`
* 直接下最新包：
  `https://github.com/Urruna/secureTransfer/releases/latest/download/securityTransfer-ui-win64.zip`

**一行命令自动获取并解压**（PowerShell，需要 repo 权限的 token）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\get_ui.ps1 -Token ghp_xxx
# 结果：.\dist\securityTransfer\（含 run_ui.bat），脚本会打印 zip 的 SHA-256
```

**发布新版本（维护者）**：

1. 打 tag 并发布 Release，例如 `git tag v1.2-windows-ui && git push origin v1.2-windows-ui`，
   再在 GitHub 上点 "Draft a new release" 发布；
2. 工作流 `.github/workflows/windows-ui.yml` 会自动：装 MSYS2 + Qt5 → 跑
   `scripts/package_windows.sh` → 检查依赖完整性 → 打 zip → **把 zip 挂到这个 Release 上**；
3. 平时 push 到 `main` 也会自动构建并上传 artifact（保留 90 天），
   方便随时取最新界面验证，而不必等发版。

## 5. 关键设计决策（写报告时可以直接引用）

1. **安全逻辑全部放在 `Frame::payload` 内部**——网络层（`Network` / `Frame`）一行都不用改，
   第一阶段的 27 个用例继续作为回归基线。
2. **Encrypt-then-MAC**，且 `PayloadLen`、`Sequence`、`Direction`、`SessionId` 全部参与 MAC，
   所以截断、拼接、反射都会被检测出来。
3. **握手阶段的 MAC 输入是显式转录串**（TLV 编码 + 域分离标签 + 方向标签），
   避免字段拼接歧义、用途混用与反射攻击。
4. **`K_session` 真的被传输**（用 `K_master` 做 CTR 包裹），而不是本地推导——
   因为课程要求"安全地分发会话密钥"，而规定的密钥是固定值。
5. **Nonce 结构保证不重复**：`随机前缀(8) || 0x00000000(4) || 消息计数(4)`。
   计数区隔离在低 32 位，是因为 `AES::ctrXor` 会把整个 128 位计数器大端自增，
   一条长消息会占用连续多个计数器值（若沿用 `prefix||seq` 会造成密钥流复用）。
6. **防重放先判断、后提交**：`wouldAccept()` 不推进水位，MAC 通过后才 `commit()`，
   因此攻击者无法用伪造的大序号包把合法包"挤掉"。

## 6. 与其它部分的接口

```text
第一部分（密码算法）              第二部分（本仓库）                第三部分（应用）
────────────────────            ─────────────────────           ─────────────────
AES-128 / CMAC   ──────────▶    CmacEngine → MacEngine      ──▶  SecureSession
（已交付并集成）                 CryptoProvider / Packet / 握手     UI、文件、图像、访问控制
```

* 第三部分只需要 `SecureSession`：`connectToServer()` / `acceptOneClient()` /
  `sendMessage(type, bytes)` / `receiveMessage(type, bytes)` / `stats()`；
  （界面这类需要"边等数据边干别的"的调用方用非阻塞版
  `tryReceiveMessage(type, bytes, waitMs)`，见 `docs/interfaces.md`）
* 第一部分成果通过 `CmacEngine`（把 `CMAC` 适配成 `MacEngine`）接入，
  算法实现文件 `aes.cpp` / `cmac.cpp` 保持原样，未做任何修改；
* 若第一部分将来替换算法实现，只需要替换 `MacEngine` / `CryptoProvider` 的实现，
  协议层与第三部分代码不受影响（见 `docs/development.md` §5）。
