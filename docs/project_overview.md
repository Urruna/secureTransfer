# SecureTransfer 项目全景梳理

> **用途**：整体回顾、答辩准备、对外介绍的一页式入口。
> **生成日期**：2026-10-06
> **依据**：直接阅读源码（`src/` `include/` `apps/` `tests/`）+ 核实 `docs/` 全部文档，
> 不是对 README 的复述。**核实到的文档过时点在附录 C 列出**。

---

## 0. 一页速览

| 项 | 内容 |
| --- | --- |
| 项目 | 《安全的信息传输套件》课程大作业 |
| 目标 | Alice / Bob 在**完全不可信的网络**上安全交换信息，抗 Eve 的窃听 / 篡改 / 假冒 / 重放 |
| 技术栈 | C++17 + CMake；Qt 5 Widgets（界面，可选）；MSYS2 MinGW-w64 或 g++ |
| 密码算法 | **自己手写 AES-128-CTR + CMAC**（RFC 4493）。系统本体**不链接任何密码库** |
| 唯一例外 | `tools/crypto_benchmark` 链接 OpenSSL —— 只为做"要求 5 的性能对比" |
| 代码规模 | `src/` + `include/` **6067 行**；`apps/` 2331 行；`tests/` 3711 行；`tools/` 459 行 |
| 测试 | `ctest` **16/16 通过**（80+ 用例），Linux 与 Windows 两端一致 |
| 当前状态 | 课程要求 1–9 **全部实现并实测**；要求 10 部分达成 |
| 运行环境 | Ubuntu 20.04 虚拟机（Linux netns 模拟双机）+ Windows 物理机（MSYS2 / Qt 5.15.19） |

**一句话定位**：这不是"调库拼一个加密聊天"，而是**从 AES 的 S 盒开始手写、一路搭到 Qt 图形界面的完整协议栈**，
每一层都有明确边界、可替换接缝和独立测试。

---

## 1. 课程要求完成情况

### 1.1 十条评分点

| 编号 | 课程要求 | 分值 | 状态 | 证据位置 |
| --- | --- | --- | --- | --- |
| 1 | 安全分发会话密钥 `K_session = 000102…0F` | 10 | ✅ | `KEY_EXCHANGE` 用 `K_master` 做 CTR 包裹后**真的传输**；`docs/protocol.md` §4–§5 |
| 2 | 用该密钥 + AES 加密传输，≥4 条测试消息 | 10 | ✅ | AES-128-CTR；4 条消息（10B / 39B / 75B / 85B）端到端验证 |
| 3 | 完整性保护 + 标准数据做算法正确性测试 | 10 | ✅ | CMAC（RFC 4493，4 条标准向量）；FIPS-197 / NIST SP 800-38A |
| 4 | 必须自己写，不能用库 | 10 | ✅ | 本体零密码库依赖；`aes.cpp` / `cmac.cpp` 自写 |
| 5 | 与库/他人实现做性能对比 | 10 | ✅ | AES-CTR + CMAC × 1KB~100MB，含**禁用 AES-NI 的纯软件对比**；`docs/performance.md` |
| 6 | 信息必须经过网络传输 | 10 | ✅ | 真实 TCP；netns 双机 + Windows↔Ubuntu 跨系统双机；`docs/lan_test.md` |
| 7 | 完整安全协议（加密/认证/密钥交换/访问控制），对用户透明 | 10 | ✅ | 全部四项完成；访问控制见 `docs/access_control.md` |
| 8 | 良好人机交互界面 + 需求分析 + 应用设计 | 10 | ✅ | Qt5 界面（8 个分区 + `--auto` 脚本化）；`docs/ui.md` |
| 9 | 支持短消息 / 文件 / 图像多种信息 | 10 | ✅ | `DATA` + `FILE_*` 分块 64 KiB + `IMAGE` 单包；`docs/file_transfer.md` |
| 10 | 其他扩充功能 | 10 | 🟡 部分 | 协议统计、密钥指纹、`--mock`/`--placeholder`、Eve 攻击测试、性能工具、双机脚本、CI 自动出包 |

### 1.2 课程流程要求

| 要求 | 落实方式 |
| --- | --- |
| 先用 TCP 建连，再做认证与会话建立 | `connectToServer()` / `acceptOneClient()` 内部顺序完成，TCP 成功后才进入握手 |
| Challenge-Response 认证，Nonce 防重放 | `NonceA` / `NonceB` 均进入转录串；Bob 每次连接生成新 `NonceB` |
| Encrypt-then-MAC | 数据阶段先 `aesCtrEncrypt` 再对「头部+密文」算 CMAC |
| 统一 Packet 格式 | 与课程建议格式一致，**另加 1 字节 `Direction`** 防反射 |
| Sequence + SessionId 防重放 | `ReplayGuard` 两阶段 + SessionId 绑定校验 |
| Eve 攻击演示（窃听/篡改/伪造/重放） | 四条路径全部有实测证据 |
| 访问控制 | 身份→角色→权限，服务端权威判定 + 审计日志 |

### 1.3 未实现 / 明确限制（项目主动写明，是加分项）

| 项 | 现状 | 原因 |
| --- | --- | --- |
| 前向保密 | ❌ 不支持 | 要求 1 规定会话密钥是**固定值**，结构上做不到。改点在 `makeCourseSessionKey()` |
| 抗 DoS | ❌ 未设计 | 握手入口敞开（未认证的 HELLO 也会被处理）；但**数据通道防住了**（两阶段提交） |
| 多客户端并发 / 密钥轮换 | ❌ | 单会话、单线程模型 |
| 每身份独立凭证 | ❌ | 所有身份共用一把 `K_master`（实验环境简化） |
| 真机双机（两台物理机） | 🟡 命令就绪 | netns 模拟已完成；Windows↔Ubuntu 属"宿主↔虚拟机" |

---

## 2. 项目架构

### 2.1 分层与依赖方向

```text
        ┌─────────────────────────────────────────────────────────────┐
        │  apps/                  alice · bob · ui(Qt5)               │
        │  应用入口：命令行演示程序 + 图形界面                          │
        └────────────────────────────┬────────────────────────────────┘
                                     │
        ┌────────────────────────────▼────────────────────────────────┐
        │  application/           crc32 · transfer_meta · file_transfer│
        │  应用层：文件/图像的分块、重组、整文件 CRC32 校验              │
        └────────────────────────────┬────────────────────────────────┘
                                     │
        ┌────────────────────────────▼────────────────────────────────┐
        │  security/     session · keystore · replay_guard · access    │
        │  安全层：握手状态机 · 密钥分发 · 加密数据通道 · 访问控制        │
        │  ★ SecureSession 是对外唯一门面                              │
        └───────┬──────────────────────────────────────┬──────────────┘
                │                                      │
        ┌───────▼──────────────┐              ┌────────▼──────────────┐
        │  protocol/           │              │  network/             │
        │  packet · transcript │              │  frame · network      │
        │  数据包编解码 +       │              │  长度前缀分帧、        │
        │  握手转录串（无状态）  │              │  粘包拆包（第一阶段冻结）│
        └───────┬──────────────┘              └───────────────────────┘
                │
        ┌───────▼──────────────────────────────────────────────────────┐
        │  crypto/   aes · cmac（第一部分原样导入）                     │
        │            mac_engine · cmac_engine · crypto_provider（接缝） │
        └──────────────────────────────────────────────────────────────┘

        common/  —— 横切模块：types · byte_buffer · hex · random ·
                    constant_time · log · console · path_utils · text_encoding
```

**依赖方向严格单向**：`apps → application → security → protocol → crypto / network`。
- 网络层**不知道**协议层的存在；
- 协议层**不知道**业务类型（短消息/文件/图像）的存在；
- 算法层**不知道**协议层的存在。

### 2.2 模块职责表

| 模块 | 位置 | 职责 | 规模 |
| --- | --- | --- | --- |
| `common/*` | `include/common/` | 类型、TLV 编解码、十六进制、随机源、常数时间比较、日志、控制台、路径/编码适配 | 1092 |
| `AES` / `CMAC` | `include/crypto/aes.h`、`cmac.h` + `src/crypto/` | **第一部分成果**：自实现 AES-128 单分组 + CTR、CMAC（RFC 4493） | 381 |
| `MacEngine` / `CmacEngine` | `include/crypto/` | MAC 算法接缝；`cmac_engine.h` 是**唯一的粘合代码**（45 行） | 77 |
| `CryptoProvider` / `AesCryptoProvider` | `include/crypto/`、`src/crypto/` | 算法与协议之间的唯一接缝；默认真实 AES-CTR + 真实 CMAC | 237 |
| `PlaceholderMacEngine` / `MockCryptoProvider` | `src/crypto/` | ⚠ 开发期占位实现（**不具备密码学强度**），仅用于演示解耦与联调 | 303 |
| `Frame` / `Network` | `include/network/`、`src/network/` | **第一阶段成果，未改动**：长度前缀分帧、readExact/writeAll 循环、错误三档语义 | 1093 |
| `Packet` | `protocol/packet.*` | 统一数据包格式（41B 头 + Body + 16B MAC）、编解码、边界校验 | 205 |
| `transcript` | `protocol/transcript.*` | 握手 MAC 输入：TLV + 域分离前缀 + 方向标签 | 203 |
| `ReplayGuard` | `security/replay_guard.*` | 防重放：`wouldAccept()`（只判断）/ `commit()`（通过后推进）两阶段 | 122 |
| `KeyStore` | `security/keystore.*` | `K_master` 与身份的带外配置读取、**文件权限检查**、密钥指纹 | 204 |
| `SecureSession` | `security/session.*` | **对外唯一门面**：握手状态机 + 密钥分发 + 加密数据通道 | 931 |
| `access_control` | `security/access_control.*` | 身份→角色→权限，服务端权威判定 + 审计日志 | 428 |
| `crc32` / `transfer_meta` / `file_transfer` | `application/` | 自实现 CRC32、元数据编解码 + 文件名安全校验、`FileSender`/`TransferReceiver` | 832 |
| `alice` / `bob` | `apps/` | 命令行演示：握手 + 4 条消息 + 文件/图像 + 访问控制命令 | 891 |
| `ui`（Qt5） | `apps/ui/` | 图形界面：`MainWindow`（界面）+ `SessionWorker`（工作线程）；**不含任何密码学逻辑** | 1440 |

### 2.3 六条关键设计决策（报告可直接引用）

1. **安全逻辑全塞进 `Frame::payload`** → 网络层一行未改，第一阶段 27 个用例继续当回归基线。
2. **Encrypt-then-MAC**，且 `PayloadLen` / `Sequence` / `Direction` / `SessionId` **全部参与 MAC**
   → 截断、拼接、反射、跨会话重放都会被检测出来。
3. **握手 MAC 输入是显式转录串**（TLV 编码 + 域分离标签 + 方向标签）
   → 避免字段拼接歧义、用途混用与反射攻击。
4. **`K_session` 真的被传输**（用 `K_master` 做 CTR 包裹），而不是本地推导
   → 因为课程要求的是"安全地**分发**"，且密钥是规定值。
5. **Nonce 三段式**：`随机前缀(8) ‖ 0x00000000(4) ‖ 消息计数(4)`
   → `AES::ctrXor` 会把**整个 128 位**计数器大端自增，一条长消息会占用连续多个计数值；
   若用 `prefix‖seq` 会造成**密钥流复用**。计数区隔离在低 32 位可根治。
6. **防重放先判断、后提交**：`wouldAccept()` 不推进水位，MAC 通过后才 `commit()`
   → 攻击者无法用伪造的大序号包把合法包"挤掉"（否则是一个拒绝服务漏洞）。

---

## 3. 每一层负责什么

### 3.1 算法层 `crypto/`（第一部分，原样导入）

**核心事实：这一层的文件**（`aes.cpp` / `cmac.cpp`）**为了配合协议没有改过任何一行。**

- `AES::encryptBlock` —— 单分组加密，SPN 结构（10 轮），128 位密钥扩展成 11 组轮密钥。
- `AES::ctrXor(key, nonce, data, len)` —— CTR 模式，**原地异或**，只加密不逆运算。
- `CMAC::generate` / `CMAC::verify` —— CBC-MAC 的加固版：K1/K2 子密钥掩码 + `0x80` 填充，
  解决"长度扩展"与"填充歧义"两个漏洞。
- **接缝**：`CmacEngine`（45 行）把 `CMAC` 适配成 `MacEngine`；
  `AesCryptoProvider` 把它接进 `CryptoProvider`。协议层只认接口。

> 验证：FIPS-197 单分组、NIST SP 800-38A CTR、RFC 4493 的 4 条 CMAC 向量；
> 另与 OpenSSL **逐字节交叉验证一致**（`docs/performance.md` §4）。

### 3.2 网络层 `network/`（第一阶段成果，冻结）

- `Frame` —— `[length(4)][payload(N)]`，`kMaxPayloadSize = 1 MiB`。
- `Network` —— TCP 封装。真正的机关是 `readExact()` / `writeAll()` 的**循环**：
  TCP 是字节流，一次 `recv` 可能只拿到半个包，一次 `send` 可能只发出去一部分，
  所以必须循环直到收满/发完。
- `receiveFrame()` **三步**：先读 4 字节长度 → **先校验长度上限再分配内存** → 循环读满 payload。
- 错误分三档语义：可重试（`EINTR` / `EAGAIN`）/ 对端消失 / 真错误。
- **Windows 适配**：`#ifdef _WIN32` 走 Winsock2（`WSAStartup` / `closesocket` /
  `WSAGetLastError` / `SocketHandle = intptr_t` / `MSG_NOSIGNAL` 条件编译）。
- `waitReadable()` / `waitAcceptable()` 是后加的：给界面用 `select()` 等可读/可接入，
  解决"接收靠超时轮询"与"`accept()` 阻塞导致点断开没反应"两个问题。

> ⚠ `Frame::deserialize()` 在**生产代码零调用**，只用于单元测试 ——
> 它的角色是「格式的可执行规格说明」（验证 serialize/deserialize 对称、证明格式可流式切分），
> 不是生产路径。生产用的是 `receiveFrame()` 手工重造 Frame。

### 3.3 协议层 `protocol/`（无状态）

- `message_type.h` —— 0x01~0x0E 的消息类型；`isDataBearing()` 决定哪些类型走加密通道。
- `packet.*` —— 41 字节头（Magic/Version/Type/Direction/SessionId/Sequence/Nonce/PayloadLen）
  + Body + 16 字节 MacTag = 总开销 **57 字节**。
  `decode()` 做 5 项检查：长度 ≥ 57 / Magic `0x5354` / Version `0x01` /
  `PayloadLen ≤ 1048519` / `PayloadLen 与实际长度一致`。
- `transcript.*` —— 握手 MAC 的输入构造：`L(x) = uint16_be(len) ‖ x`，
  三段安全性质：**域分离**（`ST-AUTH-v1` / `ST-KREQ-v1` / …）、
  **无歧义**（TLV 长度前缀）、**防反射**（`L("C2S")` / `L("S2C")`）。

### 3.4 安全层 `security/`（有状态，核心）

- **`SecureSession` —— 对外唯一门面**。上半层只认识这个类，不需要知道 Frame / Packet / 握手细节。
- **收发的两个"关卡表"都在这里**（见 §5.2 / §5.3）。
- `ReplayGuard` —— 两阶段防重放。
- `KeyStore` —— 读 `configs/keys.conf`，做**文件权限检查**（group/other 可读会警告），算密钥指纹（不打印密钥）。
- `AccessController` —— 身份→角色→权限。**判定在服务端**；拒绝**操作**但不中断**会话**。

> 📌 **协议层的一个结构现象（答辩可讲，非 bug）**：
> 握手 6 处 MAC 验证**全部手写** `crypto_.cmac()` + `constantTimeEquals()`；
> 而数据阶段走封装的 `crypto_.verifyCmac()` → `AesCryptoProvider::verifyCmac`
> → `MacEngine::verify` → `CmacEngine::verify`。**两条路都在用**。

### 3.5 应用层 `application/`

- `crc32.h` —— **自实现** CRC32（IEEE 802.3），流式接口。
- `transfer_meta.*` —— 元数据编解码 + `isSafeFileName()`：禁止 `/` `\` `..` 与控制字符，
  防**目录穿越**。
- `file_transfer.*` —— `FileSender` / `TransferReceiver`：
  分块（64 KiB）或单包、重组、整文件校验、进度回调。
- **这一层不加任何密码学机制** —— 每一块都走 `SecureSession::sendMessage`，
  自动获得加密 + CMAC + 防重放。它只加"分块 / 重组 / 校验"。

### 3.6 应用入口 `apps/`

- `alice/main.cpp`（442 行）—— 客户端：握手 + 4 条测试消息 + `--file` / `--image` / `--whoami` / `--view-log`。
- `bob/main.cpp`（449 行）—— 服务端：握手 + 校验 + 落盘 + 访问控制判定 + 统计输出。
- `apps/ui/`（1440 行）—— Qt 图形界面，见 §6。

### 3.7 横切 `common/`

唯一"谁都能用但谁也不认识"的模块。注意其中几个是**为跨平台后加的**：
`console.cpp`（Windows `SetConsoleOutputCP(CP_UTF8)`）、
`path_utils.h`（中文路径要用宽字符 API 打开）、
`text_encoding.cpp`（`GetCommandLineW` 转 UTF-8）。

---

## 4. 从一次连接建立完整走一遍

### 4.0 前置：TCP 连接

```text
Alice                                    Bob
  │  connect(host, port)                   │  listen(0.0.0.0, port)
  │ ──────────── SYN ─────────────────────▶│
  │ ◀────────── SYN-ACK ───────────────────│
  │ ──────────── ACK ─────────────────────▶│
  │                                        │  accept()
  └────────────── 字节流可用 ──────────────┘
```

此时**什么都没加密**，TCP 只保证"字节可靠送达"，不保证任何安全属性。

### 4.1 握手七步（代码：`src/security/session.cpp:189-435`）

```text
Alice（客户端）                                          Bob（服务端）
────────────────────────────────────────────────────────────────────────────
① 生成 NonceA(16随机) + SessionId(8随机)
   HELLO  Body=TLV("alice")  Nonce=NonceA  Mac=空 ──────▶ 记录 SessionId / Alice_ID / NonceA
                                                          校验 aliceId == 期望对端身份

② 生成 NonceB(16随机)
   ◀──── HELLO_ACK  Body=TLV("bob")  Nonce=NonceB
          Mac = CMAC(K_master, T ‖ L("S2C"))
   校验 peerId；验证 MAC ⇒ Bob 身份认证成功
   （T 含 NonceA ⇒ 消息是新鲜的）

③ Mac = CMAC(K_master, T ‖ L("C2S")) ──────────────────▶ 验证通过 ⇒ Alice 身份认证成功
   AUTH                                                                  ★ 双向认证完成

④ Mac = CMAC(K_master, KREQ 串) ───────────────────────▶ 验证通过
   KEY_REQUEST

⑤ ◀──── KEY_EXCHANGE  Body = wrapped(K_session) 16 字节
          Mac = CMAC(K_master, KEYEX 串 ‖ wrapNonce ‖ wrapped)
   验证 + 解包 ⇒ 得到 K_session

⑥ Mac = CMAC(K_session, KC 串) ────────────────────────▶ 验证通过 ⇒ 双方 K_session 一致
   KEY_CONFIRM

⑦ ◀──── KEY_CONFIRM_ACK  Mac = CMAC(K_session, KCA 串)
   验证通过 ⇒ 双方进入 ESTABLISHED
────────────────────────────────────────────────────────────────────────────
```

其中公共转录串：

```text
T = L("ST-AUTH-v1") ‖ L(SessionId) ‖ L(Alice_ID) ‖ L(Bob_ID) ‖ L(NonceA) ‖ L(NonceB)
L(x) = uint16_be(len(x)) ‖ x
```

**密钥包裹（第 ⑤ 步的核心）**：

```text
wrapNonce = NonceA XOR NonceB                 （两个随机数之异或，公开可见）
keystream = AES-CTR(K_master, wrapNonce, 0^16) （取 16 字节密钥流）
wrapped   = K_session XOR keystream           （网络上传输的就是这 16 字节）
```

因为两个 Nonce 都是本次新生成的随机数，`wrapNonce` 每个会话都不同
⇒ `K_master` 下的密钥流不会复用；Eve 抓到 `wrapped` 与 `wrapNonce` 也无法恢复 `K_session`。

### 4.2 会话建立后的密钥派生（`deriveSessionKeys()`）

```text
encKey_    = CMAC(K_session, L("ST-DATA-ENC"))   ← 用途分离：只用于加密
macKey_    = CMAC(K_session, L("ST-DATA-MAC"))   ← 用途分离：只用于完整性
prefixC2S_ = random(8)                            ← 方向独立前缀
prefixS2C_ = random(8)
sendSequence_ = 0
replayGuard_.reset()
state_ = kEstablished
```

### 4.3 状态机

```text
DISCONNECTED ──connect()/accept()──▶ TCP_CONNECTED
                                        │ HELLO 发出/收到
                                        ▼
                                  AUTHENTICATING ──认证失败──▶ FAILED
                                        │ 双向认证通过
                                        ▼
                                  KEY_EXCHANGE ──解包/确认失败──▶ FAILED
                                        │ KEY_CONFIRM(_ACK) 通过
                                        ▼
                                  ESTABLISHED ──CLOSE / 出错──▶ CLOSED
```

**只有 `ESTABLISHED` 才允许收发业务数据**，其它状态调用会立即失败并计入 `stats().rejectedState`。

### 4.4 失败分支

| 情况 | 行为 | 可见输出 |
| --- | --- | --- |
| 认证失败（`K_master` 不一致） | 关闭连接 | `Authentication Failed：对端未能通过 K_master 认证` |
| MAC 校验失败（被篡改） | 拒绝该包，不交付上层 | `CMAC verification failed - Message rejected` |
| 序号重放 | 拒绝该包 | `Replay Attack Detected - Packet rejected` |
| 格式/版本/SessionId/方向非法 | 静默丢弃 | `WARN` 日志 + 统计计数 |
| 握手超时 | 关闭连接 | `Handshake timeout` |

---

## 5. 数据传输线

### 5.1 数据包格式（总开销 57 字节）

| 偏移 | 长度 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0 | 2 | `Magic` | `0x53 0x54`（"ST"），快速过滤非本协议字节流 |
| 2 | 1 | `Version` | `0x01` |
| 3 | 1 | `Type` | 消息类型 |
| 4 | 1 | `Direction` | `0x01`=Alice→Bob，`0x02`=Bob→Alice |
| 5 | 8 | `SessionId` | 会话标识 |
| 13 | 8 | `Sequence` | 该方向包序号；握手包为 0，数据包从 1 严格递增 |
| 21 | 16 | `Nonce` | 数据包 = CTR 初始计数器块；握手包 = 本端 Nonce |
| 37 | 4 | `PayloadLen` | Body 字节数 |
| 41 | N | `Body` | 握手包 = 明文；数据包 = **密文** |
| 41+N | 16 | `MacTag` | 认证标签 |

**MAC 覆盖范围**：数据包 = `Packet[2 .. 41+N)`（Version 起、Body 结束，**不含 Magic 和 MacTag 自身**）；
握手包 = 显式转录串。

> 包头 41 字节**不是 16 的倍数**是有意的：只有 Body 需要按 AES 分组处理，
> 头部只是被 MAC 覆盖的字节串，不需要对齐。

### 5.2 发送路径（`SecureSession::sendMessage`，5 步）

```text
① 状态检查：必须 kEstablished；类型必须 isDataBearing；长度 ≤ 1048519；序号未耗尽
② seq  = ++sendSequence_
   nonce = prefix(8) ‖ 0^4 ‖ seq(4)          ← 三段式 Nonce
③ body = AES-CTR(encKey_, nonce, plaintext)  ← 先加密
④ mac  = CMAC(macKey_, packet.encode())      ← 再对「Version..Body」算 MAC（Encrypt-then-MAC）
⑤ 发送 Frame{ payload = [头部 ‖ body ‖ mac] }
```

发送后还会把本次包的信息（type / sequence / nonce / 密文 / MAC）存进 `lastSentTrace_`，
供报告与界面显示；原始字节存进 `lastSentWire_`（给攻击演示用）。

### 5.3 接收路径（`receiveMessage`，六道关卡）

| # | 关卡 | 位置 | 失败动作 |
| --- | --- | --- | --- |
| 1 | 会话状态必须 `kEstablished` | `session.cpp:598` | `rejectedState++` |
| 2 | Frame 长度上限（**先校验再分配内存**） | `network.cpp receiveFrame` | 拒绝 |
| 3 | 格式：长度≥57 / Magic / Version / `PayloadLen≤1048519` / 长度自洽 | `Packet::decode` | `rejectedFormat++` |
| 4 | `SessionId` 必须等于本会话 | `session.cpp:159` | `rejectedFormat++` |
| 5 | `Direction` 必须等于入方向（**防反射**） | `session.cpp:163` | `rejectedFormat++` |
| 6 | 类型必须 `isDataBearing` | `session.cpp:608` | `rejectedState++` |
| 7 | **防重放**：`wouldAccept(seq)`（只判断，不推进水位） | `session.cpp:617` | `rejectedReplay++` |
| 8 | **完整性**：`verifyCmac(macKey_, encode(), mac)`（常数时间比较） | `session.cpp:623` | `rejectedMac++` |
| 9 | 通过后才 `commit(seq)` → 推进水位 → 解密 → 交付上层 | `session.cpp:629` | — |

**为什么 7 在 8 之前**：先做便宜的检查（比大小），再做贵的检查（CMAC 要跑一遍 AES）。
**为什么是"先判断后提交"**：若检查序号时直接推进水位，攻击者伪造一个序号极大的包
（MAC 必然失败）就能把水位推高，导致之后所有合法包被误判为重放 —— 这是拒绝服务漏洞。

### 5.4 文件 / 图像传输线

```text
普通文件 / 大图像（分块）：
    FILE_START  正文 = 元数据{kind, mode=分块, 文件名, 总字节数, CRC32}
    FILE_CHUNK  正文 = 这一块的原始字节（64 KiB；顺序由 Sequence 保证）
    FILE_END    正文 = {总字节数, CRC32}

小图像（单包，≤ 约 1 MiB）：
    IMAGE       正文 = 元数据{kind=图像, mode=单包, 文件名, 总字节数, CRC32, 数据长度} + 数据
```

**五重校验**：① 格式校验 ② 每块 CMAC（防篡改）③ Sequence（防漏块/乱序）
④ 总字节数 ⑤ 整文件 CRC32（重组后重新算）。

> CRC32 是**非密码学**差错检测，用于确认"重组结果对不对"；
> 防篡改靠每块的 CMAC。**两者不可互相替代**，报告里要写清这个分工。

### 5.5 访问控制的插入点

```text
DATA / FILE_* / IMAGE  →  映射为受保护操作  →  按对端身份的角色权限判定  →  允许 / 拒绝
     DATA      → send_message
     FILE_*    → send_file
     IMAGE     → send_image
     （CLOSE / ERROR 不做访问控制）
```

关键点：
1. **身份取自握手阶段认证过的对端标识**，不是消息里自称的名字；
2. 被拒绝时只拒绝该操作并回 `ACCESS DENIED: ...`，**会话保持可用**；
3. 若 `FILE_START` 被拒绝，后续 `FILE_CHUNK` 用 `droppingTransfer` 状态**静默丢弃、不落盘**
   （否则等于"拒绝了却还是写了文件"）。

---

## 6. Qt 图形界面

### 6.1 技术选型

| 项 | 内容 |
| --- | --- |
| 技术栈 | Qt 5 Widgets（C++），Linux 侧 Qt 5.12 / Windows 侧 Qt 5.15.19 |
| 与内核关系 | **同一进程**，直接调用 `SecureSession` / `FileSender` / `AccessController` |
| 代码量 | 3 个源文件约 1440 行 |
| 界面语言 | 中文（通用术语保留英文，如 SessionId / CRC32 / IMAGE） |

### 6.2 需求分析（界面要解决什么）

课程要求"使安全操作尽量对用户透明"，所以界面解决三件事：

1. **用户不需要敲命令** —— 连接对象、端口、身份、策略都能在界面上选；
2. **安全过程可见但不需要理解** —— 握手每一步、SessionId、算法、角色权限、收发统计自动显示，
   用户只看到"已建立安全会话 / 已安全发送"；
3. **能演示与验证** —— 文件/图像传输有进度与校验结果，攻击演示有一键按钮，越权时给出明确原因。

### 6.3 线程模型（关键设计）

```text
GUI 线程                                    工作线程（独占 SecureSession）
────────                                   ──────────────────────────────
画界面                                      循环：
  │  点击"发送"                                 ① 取命令队列（加锁）
  │  ── request*() 塞进加锁队列 ──────────────▶  ② tryReceiveMessage(type, body, 100)
  │                                              ③ 结果用 Qt 信号发回
  ◀──────── 信号（自动跨线程排队）──────────────┘
```

- `SecureSession::receiveMessage()` 是**阻塞**的，直接放 GUI 线程会卡死界面；
- 所以工作线程独占 `SecureSession`（该对象**不是线程安全的**）；
- `tryReceiveMessage()` 内部用 `select()` 等"可读"，**数据一到立刻返回** ——
  消息显示延迟不受那个 100 ms 影响；100 ms 只是"没数据时最多隔多久再回头看一眼命令队列"。

> **这一块踩过坑（值得写进复盘）**：早期版本用"250 ms 超时接收 + 把超时当没有数据"，
> 后果是①消息最多晚 250 ms 显示 ②空闲时每 250 ms 打一行 ERROR 日志（几秒几百行）。
> 修好后实测：客户端日志从 **352 行降到 11 行、超时行 0 条**。

### 6.4 界面分区（8 块）

| 区域 | 控件 | 作用 |
| --- | --- | --- |
| 1. 连接与身份 | 角色 / 对端地址 / 端口 / 本端身份 / 对端身份 / 密钥配置 / 访问策略 / 接收目录 / 审计日志 / [启动] [断开] | 一个界面既能当 Alice 也能当 Bob |
| 2. 安全会话状态 | 状态灯 + SessionId + NonceA/B + 我的角色与权限 | 会话是否建立一目了然 |
| 3. 统计与访问控制 | 收发统计 + [查询我的角色] [查看审计日志] | 对应 `CMD WHOAMI` / `CMD VIEW_LOG` |
| 4. 短消息 | 历史记录 + 输入框 + [发送] | 明文输入，加密在后台完成 |
| 5. 文件 / 图像传输 | [选择文件…] [选择图像…] + 进度条 + 结果标签 | 显示 CRC32 校验结果 |
| 6. Eve 攻击演示 | [篡改上一个数据包并重发] [原样重放上一个数据包] | 一键验证完整性与防重放 |
| 7. 运行日志 | 滚动日志 | 握手每一步、访问控制判定、传输细节 |

### 6.5 界面与安全内核解耦（要求 4 的结构性保证）

界面代码里**搜 `crypto|AES|CMAC|Packet|Nonce` 零匹配** —— 这是编译期就能验证的结构性保证，
不是靠"我们注意没写"。

---

## 7. UI 如何部署

四条路径，按"使用者的身份"选。

### 路径 A：Linux 开发运行（原始路线）

```bash
sudo apt install -y qtbase5-dev            # 一次性，约 100 MB
cd /home/securityTransfer && mkdir -p build && cd build
cmake .. && cmake --build . -j4
ls -l st_ui
DISPLAY=:0 ./st_ui                          # 需要桌面会话
```

Qt 不存在时 CMake **自动跳过该目标**，不影响 `alice` / `bob` 与全部测试。

### 路径 B：Windows 开发运行（当前主用）

```bash
# 在 MSYS2 的 MinGW64 shell 中执行
cd /d/AppGallery/codex/Urruna_codex_OS/projects/securityTransfer
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-win -j8
```

两种启动方式：

1. **双击项目根的 `run_ui_build.bat`** —— 它临时把 MSYS2 的 `mingw64\bin` 加进本进程 PATH，
   不修改系统环境变量，可带参数（`run_ui_build.bat --server --port 9000`）；
2. **MSYS2 shell 里直接 `./build-win/st_ui.exe`** —— 该 shell 的 PATH 天然含 `/mingw64/bin`。

> ⚠ 直接双击 `build-win\st_ui.exe` 会报 `0xC0000135`（找不到 Qt5Core.dll）；
> 且**必须从项目根目录启动**（界面按相对 cwd 找 `configs/keys.conf`）。
> ⚠ `run_ui_build.bat:15` 目前**写死了本机 MSYS2 路径**，别人机器上会失效。

### 路径 C：Windows 免环境分发（给别人用）

```bash
# 在 MSYS2 MinGW64 shell 中
bash scripts/package_windows.sh
```

输出 `dist/securityTransfer/`（**约 75 MB**）：

- `alice.exe` / `bob.exe` / `st_ui.exe`；
- Qt5 DLL（`windeployqt-qt5` 部署）+ `platforms/qwindows.dll`；
- MinGW 运行时 DLL（脚本按"依赖传递闭包"自动补齐 `icu*` / `zlib1` / `harfbuzz` / `pcre2` 等）；
- `configs/`（**只含 `keys.conf.example`，不含真实密钥**）+ `experiment_data/`；
- 双击即用的 `run_bob.bat` / `run_alice.bat` / `run_ui.bat`。

对方只需：解压 → 把 `keys.conf.example` 复制成 `keys.conf` 并填 `K_master` → 双击 `run_ui.bat`。
**无需 Qt / MSYS2 / 编译器。**

> `dist/` 已被 `.gitignore` 排除，clone 出来没有可执行文件，需要时重新跑脚本。

### 路径 D：GitHub Release + CI 自动出包

- 工作流 `.github/workflows/windows-ui.yml`：装 MSYS2 + Qt5 → 跑 `package_windows.sh`
  → 检查依赖完整性 → 打 zip → **Release 时自动挂到该 Release 上**（附 `sha256.txt`）。
- 平时 push 到 `main` 也会自动构建并上传 artifact（保留 90 天）。
- 一键获取脚本：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\get_ui.ps1 -Token ghp_xxx
# 结果：.\dist\securityTransfer\（含 run_ui.bat）
```

> ⚠ 仓库为**私有**：对方需要是 collaborator 并登录 GitHub 才能下载。

### 四条路径对比

| 路径 | 使用者 | 需要什么 | 产物 |
| --- | --- | --- | --- |
| A | 自己（Linux 侧） | `qtbase5-dev` + 桌面会话 | `build/st_ui` |
| B | 自己（Windows 侧，当前主用） | MSYS2 MinGW-w64 + Qt5 | `build-win/st_ui.exe` |
| C | 队友 / 老师 | **什么都不用装** | `dist/securityTransfer/`（75 MB） |
| D | 任何人（需仓库权限） | 只要 GitHub 账号 | Release 的 zip（约 32 MB） |

### 界面自动化（不需要人工点击）

```bash
./build-win/st_ui.exe --server --auto --port 9820 --out-dir experiment_data/received_ui &
./build-win/st_ui.exe --client --auto --host 127.0.0.1 --port 9820 \
    --send-text "Hello from Qt UI on Windows" \
    --send-file experiment_data/test_file_64KB.bin --cmd WHOAMI
```

另有 `--geometry 940x600`（复现小窗口布局问题）与 `--print-geometry`（打印各控件实际尺寸）两个诊断开关。

---

## 8. 未来改进方向

按"性价比 × 与课程/保研的相关性"排序，不是简单罗列。

### 8.1 安全层面（学术价值最高）

| 方向 | 说明 | 工作量 |
| --- | --- | --- |
| **前向保密（PFS）** | 把 `K_session` 的来源从「被 `K_master` 包裹分发」改为「由双方临时私钥 ECDHE 推导」。⚠️ **真正的工作量不在改握手，而在自写一个 ECDH 模块**（要求 4 不许用库）—— 改动面很窄，但实现量不小 | 高 |
| **握手抗 DoS** | 目前未认证的 HELLO 也会被处理。可加 cookie（SYN-cookie 思想）或工作量证明 | 中 |
| **每身份独立凭证** | 当前所有身份共用一把 `K_master`，"身份"强度 = "知道 K_master"。可给每个身份独立密钥或引入证书 | 中 |
| **审计日志防篡改** | 现在是本地追加文本，可改为只追加 + 哈希链 / 签名 | 小 |
| **`kError` 明文可伪造** | 仅影响可用性（可被用来发假错误提示）；网络层已有 1 MiB 上限兜底 | 小 |

### 8.2 性能层面（有实测数据支撑）

| 方向 | 预期收益 | 出处 |
| --- | --- | --- |
| 用 AES-NI 内建函数替换查表实现 | 提高一个数量级（但偏离"纯软件自实现"的教学目标，适合做**扩展实验**） | `performance.md` §6.1 |
| CTR 多分组并行 + 循环展开 | 2~4 倍 | §6.2 |
| T 表合并 SubBytes+ShiftRows+MixColumns | 减少访存 | §6.3 |
| CMAC 复用上下文 | 避免每消息重复密钥扩展与 K1/K2 推导（当前已测出密钥扩展仅占 1 KB 的 0.4%，收益有限） | §6.4 |
| 块大小 64 KiB → 256/512 KiB | 当前应用层吞吐 30~42 MB/s，纯加密吞吐约 110 MB/s，差距来自固定开销与调用次数 | `file_transfer.md` §6 |

### 8.3 工程与健壮性

1. **超时/断线重连**：当前传输中断需要整个文件重发（无断点续传）；
2. **超大文件流式读取**：`FileSender` 现在会把整个文件读进内存再分块；
3. **多客户端并发**：现在服务端一次只接受一个对端；
4. **`TransferReceiver::reset()` 是死函数**（无调用点）；
5. **三端重复代码**：根因是 `common/hex.h` 缺一个 `toHex(u32)` 重载 —— 补上可消除多处重复；
6. **`file_transfer.cpp` 的 `metaSize` 硬编码**：元数据长度应随字段变化，硬编码有维护风险。

### 8.4 交付与展示

1. **实验报告 `.docx`**（尚未产出）；
2. **提交包整理**：需剔除 `.sln` / `.vcxproj` / `.vs` / `Debug` / `x64` / `build-*`（这些是第一部分遗留），
   以及 30 道 LeetCode 等无关文件；
3. **真机双机截图**：两台物理机的测试本身尚未执行（netns 与"宿主↔虚拟机"都不算）；
4. **`run_ui_build.bat` 自动探测 MSYS2 路径**（约 15 行），让别人 clone 后也能直接双击；
5. **附录 C 的文档过时点**逐条修掉。

### 8.5 如果只做三件事

1. **前向保密** —— 唯一能称为"协议设计层面"的实质增强，且改动点被隔离在单个函数里；
2. **真机双机截图** —— 交付层面的硬缺口，且成本只是"找第二台电脑 + 20 分钟"；
3. **把 `run_ui_build.bat` 的路径写活 + 修完附录 C 的文档** —— 成本极低，但直接决定别人能不能顺利跑起来。

---

## 附录 A：实测数据汇总

| 指标 | 数值 | 出处 |
| --- | --- | --- |
| `ctest` | **16/16 通过**（80+ 用例），1.02 秒 | `test_report.md` |
| 编译 | `-Wall -Wextra` 下 0 错误 0 警告（Linux + Windows 两端） | 同上 |
| 4 条测试消息 | 10 B / 39 B / 75 B / 85 B，全部"解密一致，MAC 通过" | 同上 |
| 篡改攻击 | `rejectedMac=1, rejectedReplay=0` → 精确落在 MAC 关卡 | `test_tamper` |
| 重放攻击 | `rejectedReplay=1, rejectedMac=0` → 精确落在防重放关卡 | `test_replay` |
| 伪造攻击 | 错误 `K_master` 过不了认证（双向都拒绝） | `test_forge` |
| 窃听（Linux tcpdump） | `capture_size=3501`，`plaintext_hits=0` | `test_report.md` |
| 窃听（Windows tshark 跨机） | 75 帧 / 74308 字节；明文、文件内容、`K_master`、`K_session` **全部 0 命中** | `eavesdrop.md` |
| netns 双机 | 32 个以太网帧，TCP SYN-SYNACK 完整，明文泄露 0 次 | `lan_test.md` |
| 跨系统双机 | Windows↔Ubuntu 双向；吞吐 54.51 / 28.28 MB/s；sha256 逐字节一致 | `lan_test.md` §8 |
| 文件传输 | 64KB / 1MB / 147KB图像 / 2.2MB图像，4/4 逐字节一致 | `file_transfer.md` |
| 应用层吞吐 | 30.4 / 36.6 / 31.5 / 42.3 MB/s | 同上 |
| 性能对比（Linux） | 默认库快 **4.7~82 倍**；禁用 AES-NI 后 **2.7~3.6 倍** | `performance.md` |
| 性能对比（Windows） | 默认 **12~23 倍**（AES-CTR）；禁用后 **2.5~4.4 倍** | §8 |
| 正确性交叉验证 | 与 OpenSSL **逐字节一致**（AES-CTR 与 CMAC 两项） | §4 / §8.3 |
| 界面日志噪声 | 客户端 **352 行 → 11 行**，超时行 0 | `ui.md` §10 |

## 附录 B：代码规模

| 层 | 目录 | 行数 |
| --- | --- | --- |
| 横切 | `common/` | 1092 |
| 算法 | `crypto/` | 872 |
| 网络 | `network/` | 1093 |
| 协议 | `protocol/` | 493 |
| 安全 | `security/` | 1685 |
| 应用 | `application/` | 832 |
| **源码合计** | `src/` + `include/` | **6067** |
| 入口 | `apps/`（alice 442 + bob 449 + ui 1440） | 2331 |
| 测试 | `tests/` | 3711 |
| 工具 | `tools/` | 459 |
| **总计** | | **约 12568** |

## 附录 C：本次核实到的文档过时点（待修）

以下是**逐个打开源码核实**后确认仍过时的地方（不是猜测）。

| # | 位置 | 问题 | 建议改法 |
| --- | --- | --- | --- |
| 1 | `docs/architecture.md:26` | 架构图写「AES 已接入，**CMAC 待交付**」 | CMAC 早已集成且是默认实现 |
| 2 | `include/crypto/mac_engine.h:8-9` | "当前状态：**CMAC 仍在第一部分开发中**" | 改为"CMAC 已交付，见 `cmac_engine.h`" |
| 3 | `include/crypto/crypto_provider.h:11` | 列了「**未来的** Part1CryptoProvider」 | 它就是现在的 `CmacEngine`，已接入 |
| 4 | `include/network/frame.h:6-8` | "后续会**在其上扩展** Message Type / Session ID / Sequence …" | 实际路线是 payload 里套 Packet，**Frame 一字未改**；与同层 `network.h:13-14` 自相矛盾 |
| 5 | `include/security/session.h:148` | `close()` 注释写「**发送 kClose（尽力而为）**并关闭连接」 | 实现（`session.cpp:668`）**只关连接、一个字节都没发**；真正发 kClose 的是应用层 |
| 6 | `include/security/session.h:159` | `macIsCryptographicallySecure()` 注释写「CMAC **未交付**时为 false」 | CMAC 已交付 |
| 7 | `docs/development.md:155` | 出现旧目录名 `cd /home/securityTransfer/**实验数据**` | 已英文化为 `experiment_data` |
| 8 | `docs/development.md:10` | "第三方依赖：**无**（不需要 OpenSSL / Qt / 网络库）" | Windows 下链接 `ws2_32` / `bcrypt`，Qt 为可选目标 |
| 9 | `docs/development.md:43-54` | 产物清单缺少 `st_ui` / `crypto_benchmark` / `test_file_transfer` / `test_access_control` 等新目标 | 补全 |
| 10 | `run_ui_build.bat:15` | 写死 `D:\AppGallery\dev-tools\msys64\mingw64\bin` | 改为自动探测常见安装位置 |

> ✅ **已修**（本次核对确认）：`README.md:5` / `README.md:9`（第三部分状态、测试数）；
> `src/network/network.cpp:100` 的 `describeError()` 已改用 `FormatMessageW` + UTF-8 转换（提交 `dd54726`）。

---

**相关文档索引**

| 想了解什么 | 看哪个 |
| --- | --- |
| 课程要求逐条对照 | `docs/requirements.md` |
| 协议格式与握手细节 | `docs/protocol.md` |
| 分层、模块、依赖方向 | `docs/architecture.md` |
| 对外接口清单与稳定级别 | `docs/interfaces.md` |
| 编译、运行、扩展指南 | `docs/development.md` |
| 测试与攻击实测数据 | `docs/test_report.md` |
| 性能对比 | `docs/performance.md` |
| 双机 / 局域网测试 | `docs/lan_test.md` |
| 文件与图像传输 | `docs/file_transfer.md` |
| 访问控制 | `docs/access_control.md` |
| 图形界面 | `docs/ui.md` + `docs/screenshots/` |
| 窃听证据 | `docs/eavesdrop.md` |
| 每一轮做了什么（决策记录） | `Part2_transfer.md` |
