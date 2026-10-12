# 第二部分实施方案：安全通信协议与网络

> 面向课程项目《安全的信息传输套件》（课程需求：`docs/project_q1.md`）的 **第二部分**：
> TCP、数据包格式、身份认证、Session Key 分发、会话管理、防重放。
>
> 本文档是**方案**（设计 + 步骤 + 验收标准），不是最终交付报告。
> 文中区分三类陈述：**【已验证】**（本次实际执行得到的事实）、**【已有材料】**（读取现有文件得到）、**【建议/待决策】**（设计选择，需你确认）。

---

> **本文档 = 方案（§0–§15）+ 研发历程索引**。
>
> * 分轮的完整记录已归档到 [`docs/history_rounds.md`](docs/history_rounds.md)
>   （原 §16–§31 原样搬迁，只修正了轮次编号：§29/§30/§31 分别是第 14/15/16 轮）；
> * **课程要求完成情况**（唯一权威）→ [`docs/requirements.md`](docs/requirements.md)；
> * 协议细节 → [`docs/protocol.md`](docs/protocol.md)；界面 → [`docs/ui.md`](docs/ui.md)；
>   中间人攻击 → [`docs/eve_mitm.md`](docs/eve_mitm.md)。
>
> **当前状态（2026-10-12）**：课程要求 1–9 全部实现并实测，要求 10 部分达成；
> `ctest` **18/18**（Windows MinGW-w64 + Ubuntu 20.04 双平台，0 编译告警）。

---

## 研发历程索引

每一步"为什么改、改了什么、结论是什么"的完整记录见
[`docs/history_rounds.md`](docs/history_rounds.md)；下表只给一句话摘要与定位。

| 轮次 | 日期 | 一句话 | 详细 |
| --- | --- | --- | --- |
| 1 | 09-26 | 按本方案落地第二部分：协议栈 + 七步握手 + AES 接入，测试全绿 | §16 |
| 2 | 09-26 | 资源整合：第一部分 CMAC 交付并接入（占位 MAC → 真实 CMAC） | §17 |
| 3 | 09-26 | 与库实现的性能对比（OpenSSL）+ 局域网双机测试（netns 两独立 IP 栈） | §18 |
| 4 | 09-28 | 文件与图像安全传输（64 KiB 分块 / 小图单包 + CRC32 校验） | §19 |
| 5 | 09-28 | 访问控制：身份 → 角色 → 权限 + 审计日志（越权只拒操作、不断会话） | §20 |
| 6 | 09-28 | Qt 图形界面第一版（连接/消息/文件/攻击演示/日志） | §21 |
| 7 | 10-01 | 中文路径改英文 + GitHub 首次备份 + 启动 Windows 迁移 | §22 |
| 8 | 10-01 | Windows 迁移 M2–M6（Winsock2 / BCrypt / UTF-8 控制台）+ 两端回归 | §23 |
| 9 | 10-01 | `SecureSession` 增加非阻塞尝试接收，界面不再靠超时轮询 | §24 |
| 10 | 10-01 | Windows 打包分发（windeployqt）+ Wireshark 窃听证据 | §25 |
| 11 | 10-06 | 修界面五个使用问题（布局压缩 / 中文路径 / 断开卡死 / 乱码 / 双机说明） | §26 |
| 12 | 10-06 | CI 自动测试 + 服务端常驻化与抗拒绝服务（握手总时限） | §27 |
| 13 | 10-07 | 性能对比扩展到 Mbed TLS 与 Botan（含纯软件对照与汇总表） | §28 |
| 14 | 10-09 | 界面改版：三栏外壳 + 握手 7 步 + Eve 面板（`RejectGate` / 攻击回执） | §29 |
| 15 | 10-10 | 真实链路中间人（独立进程 `eve`）+ 面板升级（流水线/检查器/历史/剧本） | §30 |
| 16 | 10-12 | 按使用反馈修 UI（文字压缩 / 攻击目标 / 攻击者视角）+ 序号按类型计数 | §31 |

> 读法建议：只想知道**当前设计**，看下面的 §1–§15 就够；
> 想知道**为什么会是现在这样**，按上表跳到 `docs/history_rounds.md` 对应小节。

---

## 0. 摘要（先看这一节）

> ⚠ **§0–§15 是实施前的方案原稿**（保留它是为了看清"当初怎么想的"）。
> 文中"CMAC 尚未编写""要做…"这类表述都是**当时**的状态；
> 现在完成到哪一步，看文档顶部的**当前状态**与
> [`docs/requirements.md`](docs/requirements.md)。

结论：**第二部分的骨架已经存在且能跑**，不需要从零开始。

| 能力 | 现在有什么 | 第二部分要做到 | 归属 |
| --- | --- | --- | --- |
| TCP 连接、分帧、粘包拆包 | 【已验证】`/home/SecureTransfer` 第一阶段代码，编译通过、`ctest` 3/3 套件通过 | 直接复用，**不改 STABLE API** | 第二部分（已完成） |
| 统一数据包格式 | 仅有 `Frame = length + payload`，无协议头 | 新增 41 字节 Packet 头（Magic/Version/Type/Direction/SessionId(8)/Sequence/Nonce/Length）+ 16 字节 CMAC | 第二部分 |
| 身份认证 | 无，任何人都能连上 Bob | `K_master` 预共享 + Challenge-Response（Nonce_A/Nonce_B + CMAC）双向认证 | 第二部分 |
| Session Key 分发 | 无 | `K_session = 000102...0F` 用 `K_master` 包裹后传输 + `KEY_CONFIRM` 双方确认 | 第二部分 |
| 会话管理 | 无 | 会话状态机 + SessionId + 握手超时 + 统计计数 | 第二部分 |
| 防重放 | 无 | Sequence 严格递增检查 + 每方向独立计数 + Nonce 结构保证不重复 | 第二部分 |
| AES / CMAC 算法 | 【已有材料】AES 在 Windows：`D:\圈圈\课程\算法设计与实验\AES\大作业`，C 语言实现，已有 FIPS-197 向量自测；**CMAC 尚未编写** | 只对接，不实现（属于第一部分） | 第一部分 |

第二部分的**工作量重心**在三处：

1. 定义并冻结**包格式与接口**（一旦第三部分开始写 UI，接口就不能再改）；
2. 实现**握手状态机**（HELLO → 认证 → 密钥分发 → 确认），这是最容易出错、也最容易被提问的部分；
3. 把**加密 + 完整性 + 防重放**正确地组合起来（Encrypt-then-MAC、Nonce 不重复、Sequence 拒绝重放），并用篡改/伪造/重放测试证明它真的有效。

---

## 1. 素材与现状盘点

### 1.1 已有材料

| 材料 | 位置 | 本次读取到的内容 |
| --- | --- | --- |
| 课程要求 | `docs/project_q1.md` | 10 项要求 + 步骤 1–10；第二部分 = TCP / 数据包格式 / 身份认证 / Session Key 分发 / 会话管理 / 防重放 |
| 组内接口约定 | `docs/team_interfaces_original.md` | `AES::encryptBlock`、`AES::encryptCTR`、`CMAC::generate/verify`、`Network::connect/listen/accept/sendFrame/receiveFrame/close`、`struct Frame` |
| AES 成果 | `D:\圈圈\课程\算法设计与实验\AES\大作业\` | `aes.h` / `aes.c` / `test.c`；导出 `aes_key_expand`、`aes_encrypt_block`、`aes_ctr_xor`；`test.c` 含 5 条自测（FIPS-197 单块向量 + 4 条 CTR 往返） |
| 第一阶段链路 | Ubuntu6.21 虚拟机 `/home/SecureTransfer`（源码 + `build/`）；备份 `/home/urruna/SecureTransfer.zip` | Frame / Network / Alice / Bob + 3 个测试程序 + 6 份 docs |

> 说明：上表记录的是**第一轮开始时的位置**。项目整理完成后，课程需求与组内约定
> 已移入本目录的 `docs/`（`docs/project_q1.md`、`docs/team_interfaces_original.md`），
> 第一阶段的代码与文档分别保留在本工程的 `include/network`、`src/network`、
> `tests/` 与 `docs/history_stage1.md`（原 `docs/stage1/` 已归档合并）中；
> 第一阶段代码在虚拟机里仍有一份原样副本
> `/home/SecureTransfer`（未改动，仅作备份）。

**`aes.h` 导出的接口（第二部分需要按这个对接）：**

```c
void aes_key_expand(const uint8_t key[16], uint8_t rk[176]);
void aes_encrypt_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]);
void aes_ctr_xor(const uint8_t rk[176], const uint8_t nonce[16], uint8_t* data, size_t len);
```

注意三点（对第二部分很关键）：

1. `aes_ctr_xor` 是**原地 XOR**，加密和解密是同一个函数（CTR 的特性）；
2. 它把 `nonce` 当作**初始计数器块**，内部按**大端整体自增 128 位**（`inc128_be`）——这直接决定了 Nonce 的结构设计（见 §7.1）；
3. 它是 C 语言接口（`aes.c` 按 C 编译），且 `aes.h` 与源文件里的中文注释是 **GBK 编码**，在 Ubuntu 下用 UTF-8 打开是乱码，C++ 里直接 `#include` 还会遇到 name mangling 问题（见 §10）。

### 1.2 第一阶段成果的实际状态【已验证】

本次在 Ubuntu6.21 虚拟机里重新执行：

```text
$ cd /home/SecureTransfer/build && cmake --build . && ctest --output-on-failure

[ 23%] Built target st_network
[ 38%] Built target bob
[ 53%] Built target alice
[ 69%] Built target test_tcp_roundtrip
[ 84%] Built target test_network
[100%] Built target test_frame

1/3 Test #1: test_frame .......................   Passed    0.01 sec
2/3 Test #2: test_network .....................   Passed    0.31 sec
3/3 Test #3: test_tcp_roundtrip ...............   Passed    0.03 sec
100% tests passed, 0 tests failed out of 3
```

即：**编译能过、27 个用例（12+10+5）当前全部通过**，这构成后续开发的**回归基线**。改任何东西之后，这 27 个用例必须继续全绿。

### 1.3 虚拟机环境【已验证】

| 项目 | 实测值 |
| --- | --- |
| 虚拟机 | VMware Workstation 17 里的 `Ubuntu6.21`（`D:\ctf\ubuntu\newtry6.21\Ubuntu6.21.vmx`），当前处于开机状态 |
| 系统 | Ubuntu 20.04.6 LTS (focal)，内核 `5.15.0-140-generic`，x86_64，2 vCPU / 4 GB |
| 网络 | NAT，guest IP `192.168.111.139`（宿主 `192.168.111.1`，NAT 网关 `192.168.111.2`） |
| 编译器 | g++ 9.4.0（C++17 可用） |
| 构建 | CMake 3.16.3 + GNU Make 4.2.1；git 2.25.1；python3 3.8.10 |
| 密码学库 | OpenSSL 1.1.1f，`/usr/include/openssl/evp.h` 存在（**libssl-dev 已装**） |
| 抓包工具 | `tcpdump`、`wireshark`、`nc`、`socat`、`xxd` 均已安装 |
| 项目路径 | `/home/SecureTransfer`（课程要求路径） |

两个直接结论：

* **没有依赖问题**：`libssl-dev` 已装，第一部分要做「与库的性能对比」、我们要做「协议层独立交叉验证」都不需要再装包；
* **虚拟机里没有 AES 代码**：`find /home -iname '*aes*'` 无结果。AES 成果目前在 Windows 主机上，需要导入（见 §10）。

### 1.4 能力缺口清单

| 缺口 | 影响的要求 | 本方案对应章节 |
| --- | --- | --- |
| 无协议头（无法表达 Type/SessionId/Sequence/Nonce） | 要求 7、要求 9 | §5 |
| 无认证，任何人都能连 Bob | 要求 7、Eve 伪造演示 | §6.3 |
| 无会话密钥分发 | **要求 1（10 分）** | §6.4 |
| 无加密数据通道 | **要求 2（10 分）** | §7 |
| 无完整性保护与篡改拒绝 | **要求 3（10 分）** | §7.3 |
| 无重放检测 | 要求 7、Eve 重放演示 | §7.2 |
| CMAC 算法本身缺失 | 要求 3（第一部分） | §10.3 |

---

## 2. 第二部分的目标与边界

### 2.1 要做（本方案的范围）

```text
第二部分交付物
├── D1  统一数据包格式（Packet）与编解码 + 单元测试
├── D2  握手协议状态机：HELLO → HELLO_ACK → AUTH → KEY_REQUEST
│                       → KEY_EXCHANGE → KEY_CONFIRM → KEY_CONFIRM_ACK → ESTABLISHED
├── D3  基于 K_master 的双向身份认证（Challenge-Response + CMAC）
├── D4  Session Key 安全分发与双方确认（K_session = 000102...0F）
├── D5  会话管理：SessionId、状态机、超时、统计计数
├── D6  数据阶段的机密性/完整性/防重放（Encrypt-then-MAC + Sequence）
├── D7  安全测试：篡改 / 伪造身份 / 重放 / 窃听（可复现的测试程序）
└── D8  对外接口 SecureSession（供第三部分 UI / 文件 / 图像直接调用）
```

### 2.2 不做（属于其他部分）

| 不做的事 | 归属 | 我们只负责什么 |
| --- | --- | --- |
| AES-128 单块 / CTR / CMAC 算法实现与标准向量 | 第一部分 | 定义并调用 `CryptoProvider` 接口 |
| 100 MB 级性能对比 benchmark | 第一部分 | 不涉及（可在协议层复用其 API） |
| Qt GUI、文件/图像传输、访问控制 | 第三部分 | 提供 `sendMessage(type, bytes)` 通用接口并预留 Type 值 |
| Eve 演示的展示脚本 | 第三部分 | 提供可复现的攻击注入测试与日志输出 |

> 【建议】访问控制（Role/Permission）虽然课程放在「安全协议」一节，但按 `project_q1.md` 第 7 节的分工属于第三部分。第二部分只在握手完成后把**认证出的身份**（`Alice_ID` / `Bob_ID`）交给上层，权限判断交给第三部分，避免重复实现。

### 2.3 与其他部分的接口契约（必须尽早确认）

```text
第一部分                        第二部分                        第三部分
─────────                       ─────────                       ─────────
AES / CMAC 实现        ──▶      Packet 编解码 / 握手状态机  ──▶   UI、文件、图像
CryptoProvider 接口             SecureSession 门面              访问控制、Eve 演示
                                Network（第一阶段成果）
```

* 我们**向上**承诺：`SecureSession`（§4.3）不变；
* 我们**向下**要求：`CryptoProvider`（§4.2）不变；
* 我们**不改**：`Network` / `Frame` 的 STABLE API（这是第一阶段已经验证过的资产）。

---

## 3. 总体设计

### 3.1 分层

```text
        ┌──────────────────────────────────────────────┐
        │  第三部分：UI / 短消息 / 文件 / 图像 / 访问控制  │
        └───────────────────┬──────────────────────────┘
                            │  sendMessage(type, bytes)
                            ▼
        ┌──────────────────────────────────────────────┐
        │  第二部分：SecureSession                      │
        │  ┌────────────────────────────────────────┐  │
        │  │ 握手状态机 Handshake（认证 + 密钥分发）  │  │
        │  ├────────────────────────────────────────┤  │
        │  │ 记录层 Record：加密 / CMAC / 防重放      │  │
        │  ├────────────────────────────────────────┤  │
        │  │ Packet 编解码（字节 ↔ 结构体）           │  │
        │  └────────────────────────────────────────┘  │
        └───────────────────┬──────────────────────────┘
                            │  调用 CryptoProvider（接口，不关心谁实现）
                            │  调用 Network::sendFrame / receiveFrame
                            ▼
        ┌───────────────────────────┐   ┌────────────────────────────┐
        │ 第一阶段：Network + Frame │   │ 第一部分：AES / CMAC 实现    │
        │ （不改动，直接复用）        │   │ （通过 CryptoProvider 接入） │
        └───────────────────────────┘   └────────────────────────────┘
```

### 3.2 六条设计原则

1. **安全逻辑全部放在 `Frame::payload` 内部。**
   第一阶段文档已经预留了这个扩展点：「Frame 的 payload 里放明文还是密文，对 `Network` 来说是一样的」。这样包格式怎么演进，都不需要动网络层，第一阶段的 27 个用例继续有效。

2. **Encrypt-then-MAC。**
   先 AES-CTR 加密得到 Body，再对「头部 + Body」算 CMAC。顺序不能反：先 MAC 后加密（MAC-then-Encrypt）会引入额外的安全性论证负担，Encrypt-then-MAC 可以直接拒绝任何被改动的包，且不需要先解密。

3. **长度字段必须进 MAC。**
   `Frame` 自己带的 4 字节长度是**网络层的**，不在 CMAC 覆盖范围内；所以 Packet 头里保留自己的 `PayloadLen` 并把它算进 CMAC，否则攻击者可以截断/拼接 Body 而不被发现。

4. **方向和身份必须进 MAC。**
   头部带 `Direction` 字节（0x01 = Alice→Bob，0x02 = Bob→Alice），且握手 MAC 输入带方向标签。否则存在**反射攻击**：把 Bob 发给 Alice 的消息原样发回给 Bob，MAC 依然成立。

5. **Nonce 不重复要在结构上保证，不靠「随机应该不会撞」。**
   见 §7.1——这是 CTR 模式的生死线（Nonce 复用 ⇒ 密钥流复用 ⇒ 明文可被异或恢复）。

6. **握手阶段不依赖加密，只依赖 MAC。**
   HELLO / AUTH 等消息的 Body 是明文（但被 CMAC 保护，防止篡改与伪造）；只有 Session Key 的包裹体是加密的。理由：加密需要 `K_session`，而 `K_session` 正是握手要分发的东西，不能循环依赖。

---

## 4. 冻结接口

### 4.1 `include/common/types.h`（第一部分、第二部分共用）

```cpp
#pragma once
#include <array>
#include <cstdint>
#include <vector>

using Byte  = uint8_t;                      // 统一用无符号：中文/高位字节不会出错
using Bytes = std::vector<Byte>;

using Key128    = std::array<Byte, 16>;     // AES-128 密钥
using Block128  = std::array<Byte, 16>;     // AES 分组
using Nonce     = std::array<Byte, 16>;     // CTR 初始计数器块
using MacTag    = std::array<Byte, 16>;     // CMAC 输出
using SessionId = std::array<Byte, 16>;     // 会话标识【待决策 D1，见 §13】

enum class Direction : Byte { kClientToServer = 0x01, kServerToClient = 0x02 };
```

> 【已有材料】`projects/team_interfaces_original.md` 与第一阶段 `docs/architecture.md` 把 `Bytes / Key128 / Nonce / MacTag` 定为 16 字节。
> **【已决策 D1】** `SessionId` 最初在本方案里按组内约定写成 16 字节，但 `project_q1.md` §5 的建议格式是 **8 字节**。
> 实施时按你的要求**采用课程规定的 8 字节**，因此包头由草案的 49 字节变为 41 字节（见 §16.3）。

### 4.2 `include/crypto/crypto_provider.h`（第一部分实现，第二部分调用）

这是**唯一的算法接缝**。第二部分只认这个接口，不关心背后是「自己写的 AES」还是别的实现。

```cpp
class CryptoProvider {
public:
    virtual ~CryptoProvider() = default;

    // CTR 加密与解密是同一个运算（对称性），保留两个名字只为可读性
    virtual Bytes aesCtrEncrypt(const Key128& key, const Nonce& nonce,
                                const Bytes& plaintext)  = 0;
    virtual Bytes aesCtrDecrypt(const Key128& key, const Nonce& nonce,
                                const Bytes& ciphertext) = 0;

    // CMAC over arbitrary length
    virtual MacTag cmac      (const Key128& key, const Bytes& data) = 0;
    virtual bool   verifyCmac(const Key128& key, const Bytes& data,
                              const MacTag& tag) = 0;   // 内部做常数时间比较
};
```

约束（写进接口注释，避免后面扯皮）：

* `verifyCmac` 必须用**常数时间比较**（不要用 `memcmp` 提前返回）；
* `aesCtrEncrypt/Decrypt` 必须支持**任意长度**（0 字节、1 字节、不是 16 的倍数、1 MB）；
* 不允许在内部打印密钥（只能 `DEBUG` 级别且默认关闭）。

同时提供一个**开发期 Mock**（第一阶段 `docs/development.md` 已建议）：

```cpp
// include/crypto/mock_crypto_provider.h
// WARNING: development-only mock implementation - 不可用于任何真实场景
class MockCryptoProvider : public CryptoProvider { /* 可逆的伪运算占位 */ };
```

价值：**第一部分的真 AES/CMAC 到位之前，第二部分就能把协议跑通并做完单元测试**，两块工作可以并行。

### 4.3 `include/security/session.h`（第二部分对外，第三部分调用）

```cpp
enum class SessionState {
    kDisconnected, kTcpConnected, kAuthenticating,
    kKeyExchange, kEstablished, kClosing, kFailed
};

struct SessionConfig {
    std::string localId;        // "alice" / "bob"
    std::string peerId;         // 期望的对端身份，用于认证校验
    std::string host;           // 客户端用，例如 "127.0.0.1"
    uint16_t    port = 9000;
    std::string masterKeyFile;  // K_master 的读取路径（见 §8）
    int         handshakeTimeoutMs = 5000;
    int         ioTimeoutMs        = 10000;
};

struct ProtocolStats {           // 给第三部分的「传输状态」界面用
    uint64_t sentPackets = 0, receivedPackets = 0;
    uint64_t rejectedReplay = 0, rejectedMac = 0, rejectedFormat = 0;
};

class SecureSession {
public:
    SecureSession(CryptoProvider& crypto, const SessionConfig& config);
    ~SecureSession();

    // 客户端：TCP connect + 完整握手；返回 true 时 state() == kEstablished
    bool connectToServer();

    // 服务端：listen + accept + 完整握手
    bool acceptOneClient();

    // 业务数据（短消息 / 文件分块 / 图像都用这一对接口）
    bool sendMessage(MessageType type, const Bytes& plaintext);
    bool receiveMessage(MessageType& type, Bytes& plaintext);

    void close();

    SessionState state() const;
    const SessionId& sessionId() const;
    const ProtocolStats& stats() const;
    const std::string& lastError() const;
};
```

这个门面一冻结，第三部分就可以并行开工（先用 Mock 跑 UI 流程，最后换真实现，只改一处工厂函数）。

---

## 5. 统一数据包格式（Packet）

> ⚠ **本节是原始设计草案**：其中包头按 16 字节 SessionId 计算（49 字节）。
> 实施时 SessionId 改为 8 字节，**实际包头为 41 字节、总开销 57 字节**，
> 其余字段与布局完全一致。以 §16.3 与 `projects/securityTransfer/docs/protocol.md` 为准。

### 5.1 放置方式：Packet 放在 `Frame::payload` 里

```text
TCP 字节流
└── Frame（第一阶段成果）:  [ length(4) ][ payload(N) ]
                                └── payload 里装的就是我们定义的 Packet：
                                    [ Packet 头(49) ][ Body(N') ][ CMAC(16) ]
```

理由：`Network::sendFrame()` / `receiveFrame()` 已经处理好了粘包/拆包、partial send/recv、长度上限、错误处理，且 27 个用例在测它。把协议头放进 payload，等于**白拿一层已被测试过的可靠传输**，同时完全不碰网络层代码。

### 5.2 字段定义

```text
偏移  长度  字段
 0     2    Magic        = 0x53 0x54 ("ST")
 2     1    Version      = 0x01
 3     1    Type         = MessageType
 4     1    Direction    = 0x01 (C→S) / 0x02 (S→C)
 5    16    SessionId
21     8    Sequence     uint64 大端
29    16    Nonce
45     4    PayloadLen   uint32 大端 = Body 字节数
49     N    Body         握手包=明文；数据包=密文
49+N  16    MacTag       CMAC
```

| 偏移 | 长度 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0 | 2 | `Magic` | 固定 `"ST"`。不匹配直接丢弃，用来快速过滤「不是本协议的字节流」 |
| 2 | 1 | `Version` | `0x01`；版本不匹配 → 拒绝（为以后升级留出口） |
| 3 | 1 | `Type` | 消息类型，见 §6.1 |
| 4 | 1 | `Direction` | `0x01` Alice→Bob，`0x02` Bob→Alice；进 MAC，防反射攻击 |
| 5 | 16 | `SessionId` | 本次会话标识；握手第一条由 Alice 随机生成，其后必须一致 |
| 21 | 8 | `Sequence` | 该方向的包序号，从 1 开始严格递增；握手包为 0 |
| 29 | 16 | `Nonce` | CTR 初始计数器块；数据包必须唯一（§7.1） |
| 45 | 4 | `PayloadLen` | Body 的字节数（不含头、不含 MAC）；**进 MAC**，防截断 |
| 49 | N | `Body` | 明文（握手包）或密文（数据包） |
| 49+N | 16 | `MacTag` | CMAC 输出 |

**包头固定 49 字节，一个包总长 = N + 65 字节。**

负载长度上限沿用 `Frame::kMaxPayloadSize = 1 MiB`，所以单个 Packet 的 Body 最大
`1048576 - 65 = 1048511` 字节。第三部分做文件传输时按 64 KiB 分块（留足余量，也便于显示进度）。

> 包头不是 16 的倍数，这是有意的：只有 `Body` 需要被 AES 按分组处理，头部只是被 CMAC 覆盖的字节串，不需要对齐。

### 5.3 MAC 覆盖范围

```text
数据包：  MAC 输入 = Packet[2 .. 49+N)      // Version 起、到 Body 结束
                                （不含 Magic 2 字节，不含 MacTag 自身 16 字节）

握手包：  MAC 输入 = 显式的握手转录串（§6.3），因为握手消息的语义字段
                     （双方 ID、两个 Nonce）比头部字段更多
```

### 5.4 与课程建议格式的差异（要在报告里说明）

| 课程 `project_q1.md` §5 建议 | 本方案 | 原因 |
| --- | --- | --- |
| Magic 2 / Version 1 / Type 1 / SessionID 8 / Sequence 8 / Nonce 16 / PayloadLen 4 | 相同，但 SessionID 用 16 字节（待决策 D1） | 对齐组内 `team_interfaces_original.md` 的统一类型 |
| 无 Direction 字段 | 增加 1 字节 `Direction` | 防反射攻击（把对端发来的合法包原样发回） |
| 无 Flags/Reserved | 也未使用 | 保持最小；将来需要时用 `Version` 升级 |

这些差异都属于**可以写进报告的设计论证**，不是偏离要求——课程给的格式是「建议」。

---

## 6. 握手协议（认证 + 密钥分发 + 会话建立）

### 6.1 消息类型

```cpp
enum class MessageType : uint8_t {
    kHello          = 0x01,  // C→S  Alice_ID
    kHelloAck       = 0x02,  // S→C  Bob_ID + MAC(K_master, 转录, "S2C")
    kAuth           = 0x03,  // C→S  MAC(K_master, 转录, "C2S")
    kKeyRequest     = 0x04,  // C→S  空 Body，MAC(K_master) 保护
    kKeyExchange    = 0x05,  // S→C  wrapped(K_session) + MAC(K_master)
    kKeyConfirm     = 0x06,  // C→S  MAC(K_session, "ST-KC-v1"||...)
    kKeyConfirmAck  = 0x07,  // S→C  MAC(K_session, "ST-KCA-v1"||...)
    kData           = 0x08,  // 双向  密文 + MAC(K_mac)
    kFileStart      = 0x09,  // 双向  （第三部分用，处理方式与 kData 完全相同）
    kFileChunk      = 0x0A,
    kFileEnd        = 0x0B,
    kImage          = 0x0C,
    kError          = 0x0D,  // 双向  1 字节错误码 + 可选说明（明文，仅用于演示提示）
    kClose          = 0x0E   // 双向  正常结束
};
```

**处理规则**：所有「带业务数据」的类型（`kData` / `kFileStart` / `kFileChunk` / `kFileEnd` / `kImage`）走**完全相同的加密 + MAC + 防重放流程**，只是 `Type` 不同。这样第三部分的文件、图像、短消息不需要各自写一套安全逻辑。

### 6.2 握手时序

```text
  Alice (客户端, 有 K_master)                                  Bob (服务端, 有 K_master)
  ───────────────────────────                                  ───────────────────────────
  TCP connect ─────────────────────────────────────────────▶  TCP accept

  ① 生成 Nonce_A(16 随机) + SessionId(16 随机)
     HELLO        Type=0x01 Dir=C→S Seq=0 Nonce=Nonce_A
     Body = L("alice")                                   ──▶  检查 Magic/Version/Type
                                                               记录 Alice_ID / Nonce_A / SessionId
  ② 生成 Nonce_B(16 随机)
     ◀──  HELLO_ACK  Type=0x02 Dir=S→C Seq=0 Nonce=Nonce_B
          Body = L("bob") + CMAC(K_master, T || L("S2C"))

  Alice 用 K_master 验证 tag_B ──▶ 认证 Bob 成功
  （同时确认 Nonce_A 被包含在 T 里 ⇒ 这是本次连接、不是旧消息）

  ③  AUTH         Type=0x03 Dir=C→S Seq=0
     Body = CMAC(K_master, T || L("C2S"))                ──▶  Bob 验证 tag_A
                                                               ⇒ 认证 Alice 成功（双向认证）
  ④  KEY_REQUEST  Type=0x04
     Body = CMAC(K_master, "ST-KREQ-v1"||...)            ──▶  Bob 生成 K_session

  ⑤  ◀── KEY_EXCHANGE Type=0x05 Seq=0
          Body = wrapped(16) + CMAC(K_master, "ST-KEYEX-v1"||...)

  Alice 验证并解包，得到 K_session

  ⑥  KEY_CONFIRM  Type=0x06
     Body = CMAC(K_session, "ST-KC-v1"||L(SessionId)||L(NonceA)||L(NonceB))
                                                         ──▶  Bob 验证成功
                                                              ⇒ 双方持有同一个 K_session
  ⑦  ◀── KEY_CONFIRM_ACK Type=0x07
          Body = CMAC(K_session, "ST-KCA-v1"||...)

  Alice 验证 ──▶ 双方进入 ESTABLISHED，初始化
                 seq_c2s = 0, seq_s2c = 0, 每方向一个随机 NoncePrefix(8)
```

对应课程 `project_q1.md` §3.1 的 `KEY_REQUEST → encrypted(K_session) → KEY_CONFIRM` 三个动作，我们额外加了 ①②③（身份认证）和 ⑦（服务端反向确认）。理由：只有 Alice 单向确认时，Bob 无法证明自己掌握的密钥与 Alice 一致；双向确认更完整，也更好演示。

### 6.3 认证转录串（Transcript）的精确定义

握手 MAC 的输入必须**无歧义**，否则会出现「不同字段拼起来字节相同」的边界攻击。因此所有字段用 **2 字节长度前缀 + 内容**（TLV）编码：

```text
L(x)  = uint16_be(x.size()) || x

T     = L("ST-AUTH-v1") || L(SessionId) || L(AliceID) || L(BobID) || L(NonceA) || L(NonceB)

tag_B = CMAC(K_master, T || L("S2C"))      // Bob 证明自己是 Bob（HELLO_ACK 携带）
tag_A = CMAC(K_master, T || L("C2S"))      // Alice 证明自己是 Alice（AUTH 携带）
```

* 固定前缀 `"ST-AUTH-v1"` 做**域分离**（domain separation），避免同一把 `K_master` 在不同用途下的 MAC 被混用；
* `"S2C"` / `"C2S"` 方向标签 ⇒ 防止把 Bob 的 tag 拿去冒充 Alice（反射）；
* 两个 Nonce 都在里面 ⇒ **新鲜的挑战-响应**：Bob 每次连接都生成新的 `Nonce_B`，Alice 必须对它做 MAC，旧的 AUTH 消息无法通过验证（防重放）。

### 6.4 Session Key 的安全分发（要求 1，10 分）

课程指定：

```text
K_session = 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
```

这是**固定值**，所以不能「用 KDF 推导出来假装分发了」，必须**真的把 16 字节传过去**，并且传输过程不能让 Eve 拿到。

**方案：用 K_master 做一次性键盘（CTR 包裹）**

```text
wrapNonce = NonceA XOR NonceB                        // 16 字节，公开值，不必保密
keystream = AES-CTR(K_master, wrapNonce, 0^16)       // 取 16 字节密钥流
wrapped   = K_session XOR keystream                  // 网络上传输的就是这 16 字节
```

理由：

* `wrapNonce` 由两个**本次会话新生成**的随机数异或得到 ⇒ 每个会话都不同 ⇒ `K_master` 下的 AES-CTR 密钥流不会复用；
* Eve 不知道 `K_master`，因此即使抓到 `wrapped` 与 `wrapNonce`，也无法恢复 `K_session`；
* 完全复用第一部分已有的 AES-CTR，不需要新算法。

【建议】把这一处封装成单一函数，方便将来替换成「真随机会话密钥」：

```cpp
// 课程实验：会话密钥是规定值，必须「分发」而不是「推导」
inline Key128 makeCourseSessionKey() { return kCourseFixedSessionKey; }
// 真实系统：随机生成 —— 只需替换这一行的实现，协议与测试都不用动
```

**KEY_CONFIRM 的意义**（课程 `project_q1.md` §3.2 明确要求）：

```text
KEY_CONFIRM = CMAC(K_session, L("ST-KC-v1") || L(SessionId) || L(NonceA) || L(NonceB))
```

Alice 能算出正确的 `KEY_CONFIRM`，说明**她确实拿到了 `K_session`**；Bob 能验证通过，说明**Bob 手里的 `K_session` 与 Alice 的一致**，且双方处于同一会话（Nonce 与 SessionId 都绑定了）。第 ⑦ 步的 `KEY_CONFIRM_ACK` 把这个结论对称地给回 Alice。

### 6.5 会话状态机

```text
                    connect()/accept()
   DISCONNECTED ──────────────────────▶ TCP_CONNECTED
                                            │
                       发送/收到 HELLO      │
                                            ▼
                                      AUTHENTICATING ──tag 验证失败──▶ FAILED
                                            │
                          双方认证通过       │
                                            ▼
                                      KEY_EXCHANGE ────解包/确认失败──▶ FAILED
                                            │
                      KEY_CONFIRM(_ACK) 通过 │
                                            ▼
                                      ESTABLISHED ──ERROR/CLOSE/超时──▶ CLOSING ─▶ CLOSED
```

规则：

* 状态机是**单线程同步**的（第一阶段 `Network` 本身就非线程安全，`docs/architecture.md` §5 已说明），不做异步/多线程，降低出错面；
* **只有在 `ESTABLISHED` 状态才允许** `sendMessage` / `receiveMessage`；其它状态调用直接返回 false 并记录 `lastError`；
* 任何状态收到不符合当前阶段的 Type（例如在 `AUTHENTICATING` 收到 `kData`）⇒ 视为协议违规，拒绝并关闭会话；
* 整个握手有超时（`handshakeTimeoutMs`，默认 5 秒），超时后关闭连接，避免程序卡死；
* 每个会话只允许一条 TCP 连接、一个 SessionId（演示够用；多客户端由第三部分决定是否需要，网络层已经支持为每个连接建独立 `Network` 对象）。

---

## 7. 数据阶段：机密性、完整性、防重放

### 7.1 Nonce 构造（CTR 模式的生死线）

**问题**：`aes_ctr_xor` 把 `nonce` 当成初始计数器，内部把整个 128 位**大端自增**（`inc128_be`），因此一条长消息会**占用连续多个计数器值**。

如果简单地令 `Nonce = prefix || msgSeq`（msgSeq 逐消息 +1），那么第 1 条消息（若有 1 MB）会用到计数器
`prefix||1` … `prefix||65537`，其中就包含第 65537 条消息要用的起始值 ⇒ **密钥流复用**。

**方案：把计数区隔离在低 32 位**

```text
Nonce(16) = Prefix(8, 会话建立时随机生成一次) || 0x00000000(4) || MsgCounter(4, 大端)
                                                                └── 该方向的消息序号
```

* 每个方向（C→S / S→C）有**独立**的 Prefix 和 MsgCounter；
* 第 m 条消息占用的计数器区间是 `[Prefix||0||m , Prefix||0||m + blocks)`，其中 `blocks = ceil(len/16) ≤ 65536`（1 MB 上限）；
* 因为 `blocks < 2^32`，不同 m 的区间**一定不相交**；又因为 `Prefix` 每会话随机、方向独立 ⇒ **不同消息、不同会话、不同方向的密钥流都不重复**；
* 剩余约束：单条消息 ≤ 2^32 个分组，单个会话消息数 < 2^32（对课程演示是天文数字）。

这个设计能直接和第一部分的 `aes_ctr_xor` 对接（把算好的 16 字节 `Nonce` 原样传进去即可），不需要改动 AES 代码。

### 7.2 Sequence 与防重放

```text
发送：seq = ++seqSend[direction]            // 从 1 开始
接收：if (seq <= lastSeq[收到的方向])        ⇒ 判定为重放，拒绝，rejectedReplay++
      else lastSeq = seq，继续校验 MAC
```

* 一个方向一个计数器（Alice 的发送序列与 Bob 的接收序列对应同一组数字）；
* 因为 TCP 保证有序，这里用**严格递增**即可覆盖重放与乱序；若将来要容忍乱序，可换成一个 64 位滑动窗口 bitmap（接口不变，属于可选扩展）；
* 判定顺序很关键：**先查重放（便宜），再验 MAC（贵）**；两种情况都必须拒绝并且**不把数据交给上层**；
* `SessionId` 也参与校验：不属于当前会话的包直接丢弃，避免「上一个会话的旧包」被当成合法数据。

### 7.3 接收处理流程（伪代码）

```cpp
bool SecureSession::receiveMessage(MessageType& type, Bytes& plaintext) {
    Frame frame;
    if (!network_.receiveFrame(frame)) return fail(network_.lastError());

    Packet pkt;
    if (!Packet::deserialize(frame.payload, pkt)) {          // ① 格式检查
        stats_.rejectedFormat++;  return false;              //    Magic/Version/长度/字段缺失
    }
    if (pkt.sessionId != sessionId_) {                       // ② 会话绑定
        stats_.rejectedFormat++;  return false;
    }
    if (pkt.direction != expectedIncoming_) {                // ③ 方向检查（防反射）
        stats_.rejectedFormat++;  return false;
    }
    if (!replayGuard_.accept(pkt.sequence)) {                // ④ 防重放（先查便宜的）
        stats_.rejectedReplay++;  log("Replay Attack Detected");
        return false;
    }
    const Bytes macInput = pkt.headerBytes() + pkt.body;     // ⑤ 完整性（Encrypt-then-MAC）
    if (!crypto_.verifyCmac(macKey_, macInput, pkt.mac)) {
        stats_.rejectedMac++;     log("CMAC verification failed");
        return false;
    }
    type = pkt.type;                                          // ⑥ 解密
    plaintext = crypto_.aesCtrDecrypt(encKey_, pkt.nonce, pkt.body);
    return true;
}
```

发送侧对称：构造 Nonce → 加密 Body → 生成头部（含 `PayloadLen`）→ 算 CMAC（头部+密文）→ 组装 Packet → `network_.sendFrame(Frame(packetBytes))`。

**注意顺序**：`PayloadLen` 与 `Sequence` 都必须在「头部」里、且在加密之前就定好，因为它们要参与 MAC。

### 7.4 失败处理策略（要做成「可演示」的）

| 情况 | 行为 | 打印/日志（演示要看得见） |
| --- | --- | --- |
| 认证失败（tag 不对） | 发送 `kError(AUTH_FAILED)` 后关闭连接 | `Authentication Failed / Connection rejected` |
| MAC 校验失败 | 拒绝该包，发送 `kError(INTEGRITY_FAILED)` 并关闭会话 | `CMAC verification failed - Message rejected` |
| 检测到重放 | 拒绝该包，关闭会话，`rejectedReplay++` | `Replay Attack Detected - Packet rejected` |
| 格式/版本/SessionId 非法 | 静默丢弃该包（不回应，避免给攻击者反馈） | `WARN` 级别日志 |
| 握手超时 | 关闭连接 | `Handshake timeout` |

【建议】演示时关闭会话（而不是「只丢这一个包继续跑」）更容易讲清楚；同时统计计数器保留，便于报告里给出「拒绝了多少个攻击包」。

【建议】`kError` 的内容用明文（仅错误码 + 简短说明），因为此时会话已不可信；它只用于演示提示，不作为协议安全性的依据。

---

## 8. 密钥与配置管理

### 8.1 K_master 的由来（要求里的「带外预配置」）

```text
Alice:  K_master = <16 字节>      Bob:  K_master = <16 字节>      Eve:  不知道
```

课程 `project_q1.md` §2.1 明确说 `K_master` 不能通过网络传输。本方案采用**配置文件带外预置**：

```ini
# /home/SecureTransfer/configs/keys.conf   （权限必须 600，属主为运行用户）
# 注意：仅用于课程实验，不是真实密钥管理方案
[identity]
alice_id = alice
bob_id   = bob

[keys]
master_key = 0f1e2d3c4b5a69788796a5b4c3d2e1f0
```

* 加载代码放在 `include/security/keystore.h`，只有两个入口：`loadMasterKey(path)`、`loadIdentity(path)`；
* 文件缺失 / 长度不对 / 权限过于宽松（例如 group 或 other 可读）时**报警并拒绝启动**——这本身就是访问控制的一个真实体现，可以写进报告；
* 任何日志都不打印密钥内容；`ST_LOG_LEVEL=DEBUG` 时最多打印 `master_key = <16 bytes loaded>` 这样的元信息；
* `configs/demo_config.conf` 里已经写了「后续阶段需要的长期密钥 K_master 绝不应该以明文形式长期保存在这里」——按这条原则，密钥单独放 `keys.conf`，并在 `.gitignore` 里排除。

### 8.2 密钥派生（【待决策 D6】）

同一把 `K_session` 同时用于 CTR 加密和 CMAC 是可以的，但更好的做法是**派生两把用途分离的子密钥**：

```text
K_enc = CMAC(K_session, L("ST-DATA-ENC"))     // 数据加密
K_mac = CMAC(K_session, L("ST-DATA-MAC"))     // 数据完整性
```

优点：算法隔离（同一把密钥下不同密码学原语的输出不混用），便于在报告里说明「我们做了密钥分离」。
成本：多两次 CMAC（只在会话建立时算一次，开销可忽略）。

【建议】采用；如果希望严格「只用课程指定的 K_session」，保持现状也不影响功能正确性。

---

## 9. 代码结构与改动清单

在现有 `/home/SecureTransfer` 上**增量**添加（第一阶段代码保持不动，只改 `alice` / `bob` 的 main）：

```text
SecureTransfer/
├── include/
│   ├── common/
│   │   ├── log.h                  [已有]
│   │   ├── types.h                [新增] Byte/Bytes/Key128/Nonce/SessionId/MacTag/Direction
│   │   ├── byte_buffer.h          [新增] TLV 编码助手（writeU16/U32/U64、appendTlv、读取器）
│   │   └── random.h               [新增] RandomSource + SystemRandom(/dev/urandom) + FixedRandom(测试)
│   ├── crypto/
│   │   ├── crypto_provider.h      [新增] 接口（§4.2）
│   │   ├── mock_crypto_provider.h [新增] 开发期 Mock（标注 WARNING）
│   │   └── aes_crypto_provider.h  [新增] 用第一部分的 AES/CMAC 实现该接口（§10）
│   ├── network/                   [已有，不改]
│   ├── protocol/
│   │   ├── message_type.h         [新增] MessageType 枚举
│   │   ├── packet.h               [新增] Packet 结构 + 常量（kHeaderSize=49 / kMacSize=16）
│   │   ├── packet_codec.cpp       [新增] serialize / deserialize / 边界校验
│   │   └── transcript.h           [新增] 握手转录串构造（域分离 + TLV）
│   └── security/
│       ├── keystore.h             [新增] K_master / 身份加载
│       ├── replay_guard.h         [新增] 序号检查
│       ├── session.h              [新增] SecureSession（§4.3）
│       └── handshake.cpp          [新增] 握手实现（客户端/服务端两个方向）
├── src/
│   └── security/                  [新增] packet_codec.cpp / handshake.cpp / session.cpp 等
├── apps/
│   ├── alice/main.cpp             [改] 握手 + 发 4 条测试消息 + 打印状态
│   └── bob/main.cpp               [改] 握手 + 校验 + 应答 + 打印统计
├── tests/
│   ├── unit/
│   │   ├── test_packet.cpp        [新增]
│   │   ├── test_transcript.cpp    [新增] 握手转录串/域分离/防反射的已知值测试
│   │   ├── test_replay_guard.cpp  [新增]
│   │   └── test_session_state.cpp [新增]
│   └── integration/
│       ├── test_secure_roundtrip.cpp [新增] 完整握手 + 4 条消息（含中文/二进制）
│       ├── test_tamper.cpp           [新增] 改 1 字节 ⇒ 必须被拒
│       ├── test_forge.cpp            [新增] 错误 K_master ⇒ 认证失败
│       └── test_replay.cpp           [新增] 重发合法包 ⇒ 必须被拒
├── scripts/
│   ├── import_aes.sh              [新增] 把 AES 源码导入 + 转 UTF-8
│   ├── capture_eve.sh             [新增] tcpdump 抓包 + 明文检索（配合第三部分演示）
│   └── verify_in_vm.sh            [改] 增加安全测试与演示步骤
└── docs/
    ├── protocol.md                [改] 用真实格式替换「后续扩展」草稿
    ├── architecture.md            [改] 补第二部分分层图
    ├── interfaces.md              [改] 追加 Packet / SecureSession / CryptoProvider
    └── test_report.md             [改] 追加本次实测结果
```

**改动量估计**：新增约 1500–2000 行 C++（含测试），修改约 200 行。

---

## 10. 把 AES 成果接进来

### 10.1 导入步骤

```bash
# 在 Ubuntu6.21 里（源码先在 Windows 上，用共享文件夹/vmrun/scp 传进去）
cd /home/SecureTransfer
mkdir -p src/crypto include/crypto

cp aes.h  include/crypto/aes_core.h
cp aes.c  src/crypto/aes_core.c
cp test.c tests/unit/test_aes.c        # 或改写成 C++ 测试
```

### 10.2 两个必须处理的兼容问题

**（1）编码**：现有 `aes.h` / `aes.c` 的中文注释是 **GBK**。在 Ubuntu（默认 UTF-8）下打开会乱码，虽然不影响编译，但会污染代码评审。建议一次性转换：

```bash
iconv -f GBK -t UTF-8 aes.h > aes_core.h.utf8 && mv aes_core.h.utf8 aes_core.h
# 或者更省事：把中文注释统一换成英文
```

**（2）C/C++ 混合编译**：`aes.c` 按 C 编译，C++ 里 `#include "aes_core.h"` 会因为 name mangling 找不到符号。两种做法可以同时用：

```cpp
// 做法 A：头文件加 extern "C"
#ifdef __cplusplus
extern "C" {
#endif
void aes_key_expand(const uint8_t key[16], uint8_t rk[176]);
/* ... 其余声明 ... */
#ifdef __cplusplus
}
#endif
```

```cmake
# 做法 B：CMake 里明确按 C 编译 aes_core.c
add_library(st_crypto STATIC src/crypto/aes_core.c src/crypto/cmac.cpp)
set_source_files_properties(src/crypto/aes_core.c PROPERTIES LANGUAGE C)
```

### 10.3 第一部分还需要补的（第二部分会依赖）

1. **CMAC 算法**：目前完全没有。需要 `aes_encrypt_block` + GF(2^128) 子密钥生成，用 **RFC 4493** 的 4 条标准向量自测（空消息、1 块、恰好 1 块、跨块）——这是要求 3「使用标准数据进行算法正确性测试」的直接得分点。
2. **C++ 适配层**：把 `aes.c` 的 C 接口包成 `projects/team_interfaces_original.md` 约定的 `AES::encryptBlock` / `AES::encryptCTR` / `CMAC::generate` / `CMAC::verify`，再实现 `AesCryptoProvider : public CryptoProvider`。
3. **decrypt 的说明**：CTR 下加密/解密是同一个函数，这点要在报告里写清楚（`aes_ctr_xor` 调两次就回到明文）。

### 10.4 第二部分在 AES 未就绪时的推进方式

```text
第 1 步    用 MockCryptoProvider 跑通：Packet 编解码 + 握手状态机 + 4 条消息
第 2 步    AES 到位 → 换 AesCryptoProvider（只改工厂函数那一行）
第 3 步    CMAC 到位 → 打开真实的完整性校验与篡改测试
```

风险：Mock 下通过的用例，换成真算法后可能暴露长度/边界问题。所以 Mock 阶段就要覆盖：空 Body、1 字节、15 / 16 / 17 字节、跨块（>16）、1 MB 边界。

---

## 11. 测试与验证方案

### 11.1 单元测试

| 测试 | 用例 | 通过标准 |
| --- | --- | --- |
| `test_packet.cpp` | 编解码往返；空 Body；最大 Body（1048511）；Body 超限；Magic 错；Version 错；`PayloadLen` 与实际长度不符；截断（缺 MAC / 缺 Body / 缺头）；多余尾巴字节 | 往返逐字节一致；非法输入全部被拒且不崩溃、不分配超大内存 |
| `test_transcript.cpp` | 固定 `K_master` + 固定 Nonce ⇒ 固定 tag；`"S2C"` 与 `"C2S"` 的 tag 必须不同；调换 `AliceID` / `BobID` 顺序 ⇒ tag 必须不同；长度前缀歧义（`("ab","c")` vs `("a","bc")`）⇒ tag 必须不同 | **已知值测试（KAT）**，用固定向量锁死实现细节 |
| `test_replay_guard.cpp` | 1,2,3 通过；重复 3 拒绝；回退到 2 拒绝；跳号 5 接受并记录缺口；方向独立（C→S 的 seq 不影响 S→C） | 与 §7.2 规则一致 |
| `test_session_state.cpp` | 未认证就 `sendMessage` ⇒ 失败；握手阶段收到 `kData` ⇒ 拒绝；握手超时 ⇒ `kFailed`；重复 `close()` 安全 | 状态机无非法转移 |
| `test_aes.c`（沿用已有） | FIPS-197 单块向量 + 5 条 CTR 往返 | 与现有 `test.c` 一致 |

### 11.2 集成测试（课程要求的「不少于 4 条测试数据消息」）

`test_secure_roundtrip.cpp`：真实 TCP + 完整握手 + 4 条消息，逐条比对发送的明文与服务端收到的明文：

| # | 测试消息 | 覆盖点 |
| --- | --- | --- |
| 1 | `Hello Bob!` | 短消息、不足 1 个 AES 分组 |
| 2 | `A secure message between Alice and Bob.` | 普通英文、正好跨块 |
| 3 | `Transfer #1024: Alice->Bob, amount=500.00 USD; status=OK! (check: 9f8e7d6c)` | 长文本 + 数字 + 特殊字符 |
| 4 | `你好，Bob，这是一次安全通信测试。` + 37 字节二进制数据 | UTF-8 多字节（中文）+ 非文本二进制（模拟文件分块） |

每条记录：`明文 → 密文（hex）→ CMAC（hex）→ 接收方解密结果 → 完整性验证结果 → 明文是否一致`。这正好对应课程 `project_q1.md` §4.4 要求的输出格式，可以直接抄进报告。

### 11.3 安全测试（要求 3 与 Eve 演示的「证据」）

这四个测试是第二部分最有说服力的产出，建议都做成**自动化的独立测试程序**（而不是手敲命令）：

| 测试 | 做法 | 期望结果 |
| --- | --- | --- |
| **篡改** `test_tamper.cpp` | 握手后，用 `tests/raw_client.h`（第一阶段已有的「裸 socket 客户端」）把合法数据包的第 1 个密文字节翻转，再发给 Bob | Bob 打印 `CMAC verification failed`，拒绝该包，`rejectedMac >= 1`，**明文没有到达上层** |
| **伪造身份** `test_forge.cpp` | 客户端用**错误的 K_master** 完成 HELLO，收到 HELLO_ACK 后仍尝试发 AUTH | Bob 验证失败，打印 `Authentication Failed`，关闭连接 |
| **重放** `test_replay.cpp` | 录下 Alice 发出的一个合法数据包，握手完成后再原样发一次 | 第二次被拒，`rejectedReplay >= 1`；第一次的数据只被上层处理一次 |
| **窃听** `scripts/capture_eve.sh` | 抓一条明文已知的消息（`sudo tcpdump -i lo -X port 9000 -w /tmp/eve.pcap`），再 `strings /tmp/eve.pcap \| grep -c "Hello Bob"` | 抓到的是密文；**明文关键字出现次数为 0**；同时能看到 Magic / Version / Seq / Nonce / CMAC 这些公开字段 |

补充一条**反射攻击**测试（可选但很加分）：把 Bob 发出的合法包原样发给 Bob，因为 `Direction` 字节与 MAC 输入已区分方向，必须被拒绝。

### 11.4 回归基线

每次提交前必须全绿：

```bash
cd /home/SecureTransfer/build
cmake --build . && ctest --output-on-failure
# 期望：第一阶段的 3 个套件（27 个用例）+ 新增的 8 个测试套件全部通过
```

### 11.5 独立交叉验证（不需要额外装东西，虚拟机里现成能做）

虚拟机已有 OpenSSL 1.1.1f + libssl-dev，可以用它**独立验算**第一部分的自写算法，避免「自己写的实现自己验证」的循环论证：

```bash
# AES-128-CTR：与我们实现的密文逐字节对比
printf 'Hello Bob!' | openssl enc -aes-128-ctr -K 000102030405060708090a0b0c0d0e0f -iv <我们的 nonce hex> | xxd -p

# CMAC：与第一部分实现的 tag 对比（注意 cmac 的 iv 全 0）
printf '...' | openssl dgst -mac cmac -macopt cipher:aes-128-cbc -macopt hexkey:000102030405060708090a0b0c0d0e0f
```

虽然第二部分不实现算法，但**用 OpenSSL 验算协议中实际出现的密文与 tag**，是证明「协议没有用错算法」的最强证据（例如证明 Nonce 构造与 CTR 约定一致、`PayloadLen` 真的进了 MAC）。

### 11.6 建议的执行顺序（每个里程碑都留证据）

```text
1. cmake 配置 + 编译 + 第一阶段 27 用例回归        → 截图 / 日志
2. test_packet / test_transcript 通过              → 截图 / 日志
3. alice / bob 完成一次完整握手（打印每一步）        → 截图
4. 4 条消息全部正确解密 + MAC 通过                  → 截图 + hex 记录
5. 篡改 / 伪造 / 重放 / 窃听 四个测试                → 截图 + 计数统计
6.（可选）局域网双机或两台虚拟机跑一次同一个程序       → 截图
```

---

## 12. 里程碑与实施顺序

> 时间估计是**相对工作量**，按每天 2–3 小时投入估算。

| 阶段 | 内容 | 产出 | 验收标准 |
| --- | --- | --- | --- |
| **M0** 环境对齐（0.5 天） | 导入 AES 源码、转编码、加 `extern "C"`；建 `st_crypto` / `st_protocol` 两个 CMake target；`docs/interfaces.md` 追加 §4 的接口 | 能编译的最小骨架 | 第一阶段 27 用例仍全绿；`aes_core.c` 参与编译且原有 5 条 AES 自测通过 |
| **M1** 类型与包格式（1 天） | `types.h` / `byte_buffer.h` / `random.h` / `message_type.h` / `packet.*` + `test_packet` | Packet 编解码 | 编解码往返 + 全部非法输入被拒 |
| **M2** 密码接缝（0.5 天） | `CryptoProvider` + `MockCryptoProvider`（真 AES 到位后补 `AesCryptoProvider`） | 可插拔算法层 | Mock 下协议能跑；替换实现只改一处 |
| **M3** 握手与认证（2 天） | `transcript` / `keystore` / 握手状态机 / `test_transcript` / `test_session_state` | 完整握手 | 固定向量 KAT 通过；错误 K_master 必须失败 |
| **M4** 数据通道（1.5 天） | Nonce 构造 / `ReplayGuard` / 收发流程 / 4 条消息集成测试 | 加密数据传输 | 4/4 消息明文一致；`ctest` 全绿 |
| **M5** 安全验证与文档（1.5 天） | 篡改 / 伪造 / 重放 / 窃听测试 + 更新 `protocol.md`、`test_report.md` + 整理截图 | 可写进报告的实验证据 | 四项攻击全部被拒绝 / 无泄漏；文档与代码一致 |
| **M6**（可选加分） | 局域网或双机测试、`ST_LOG_LEVEL=DEBUG` 的协议追踪、把 `--help` 与错误码整理成表格 | 加分材料 | 双机连通 |

**排序原因**：M1（包格式）与 M3（握手转录串）都是「一旦定下来就被别人依赖」的东西，必须尽早冻结；M4 依赖 M1 + M2 + M3；M5 依赖 M4。**不要跳过 M2 直接写 M4**——否则第一部分的算法没到位时，第二部分的进度会被卡住。

---

## 13. 风险、限制与需要你决策的开放问题

### 13.1 需要你决策

| 编号 | 问题 | 选项 | 我的建议 |
| --- | --- | --- | --- |
| **D1** | SessionId 长度 | 16 字节（对齐 `team_interfaces_original.md`）/ 8 字节（对齐课程建议格式） | **已决策：8 字节（课程要求）**，见 §16.3 |
| **D2** | 握手消息的 Body 是否加密 | 明文 + CMAC（本方案）/ 用 `K_master` 加密 | 明文 + CMAC：此时还没有 `K_session`，且明文便于演示与教学 |
| **D3** | `K_master` 取值与保存 | `configs/keys.conf`（600 权限）/ 命令行参数 / 环境变量 | 配置文件；命令行传密钥会进 shell 历史，不安全 |
| **D4** | CMAC 由谁实现 | 第一部分 / 第二部分代写 | 第一部分（要求 3 明确指向密码算法部分）；第二部分先用 Mock |
| **D5** | 是否新增 `Direction` 字节 | 新增 / 不新增（靠两把方向密钥代替） | 新增：实现简单、演示时肉眼可见，防反射的证据更直观 |
| **D6** | 是否派生 `K_enc` / `K_mac` | 派生 / 直接用 `K_session` | 派生：多两次 CMAC，换来密钥分离 |
| **D7** | 代码是否在 OS 里做版本管理 | 在 `projects/secure-transfer/` 建仓库并同步 / 只放在虚拟机里 | **建仓库**：现在代码只在虚拟机和 zip 里，一旦虚拟机损坏就全没了 |
| **D8** | 日志级别默认值 | INFO / DEBUG | INFO：网络与协议日志足够；DEBUG 只在排查时开 |

### 13.2 已知限制（要诚实写进报告）

1. **`K_session` 是固定值**（课程规定），所以不同会话之间真正的隔离依赖**每会话随机的 SessionId + Nonce Prefix**，而不是「每会话一把新密钥」。真实系统应当每次会话随机生成密钥——本方案已经把这一处收敛到单个函数 `makeCourseSessionKey()`，属于「一行可替换」的设计。
2. **不做前向保密**：`K_master` 一旦泄露，历史抓包中包裹的 `K_session` 都能解开（因为固定 K_session 可复现）。这是预共享密钥方案的固有性质，应作为限制说明。
3. **不做重连 / 密钥轮换**：一次会话一条连接，没有 rekey。
4. **不做抗 DoS**：未认证的 HELLO 任何人都能发，Bob 会为它做一次随机数生成与状态分配。演示规模下可接受。
5. **`kError` 是明文**：攻击者可以伪造它造成连接中断（只影响可用性，不影响机密性 / 完整性）。
6. **安装了 `libssl-dev` 但按要求 4 不使用它实现算法**：它只用于 §11.5 的独立交叉验证，这一点要在报告里说清楚，避免被误认为「用了库」。

### 13.3 容易踩的坑（都是这次实际看到的）

| 坑 | 现象 | 处理 |
| --- | --- | --- |
| AES 源码是 **GBK** 编码 | Ubuntu 下打开注释乱码 | 导入时 `iconv` 或改英文注释（§10.2） |
| C/C++ 混合编译 | `undefined reference to aes_key_expand` | `extern "C"` + CMake 指定 `LANGUAGE C`（§10.2） |
| 用 `char*` 存数据 | 中文解密后乱码（AES 目录的说明文件已提醒） | 全链路统一 `uint8_t` / `Bytes` |
| CTR Nonce 复用 | 两条消息密文异或后能看出明文痕迹 | 用 §7.1 的结构化 Nonce，不用「纯随机碰运气」 |
| 长度不进 MAC | 攻击者可截断 Body | `PayloadLen` 必须参与 CMAC（§3.2 原则 3） |
| 从 Windows 拷文件进虚拟机 | `make` 报 `Clock skew detected` | `find /home/SecureTransfer -exec touch {} +`（`docs/development.md` 第 7 节已记录） |
| 在日志里打印密钥 | 报告 / 演示时泄露 | 密钥相关输出只允许 DEBUG 且默认关闭（`docs/interfaces.md` §4 已约定） |

---

## 14. 附：操作与命令速查

### 14.1 把文件送进虚拟机 / 取回结果（本次已验证可用的通道）

VM 的 VMware Tools 与 Guest 账号可用（账号密码不要写进代码仓库）：

```powershell
$vmrun = "D:\圈圈\ctf\资料\LINUX\新建文件夹\vmrun.exe"
$vmx   = "D:\ctf\ubuntu\newtry6.21\Ubuntu6.21.vmx"

# 送进去
& $vmrun -T ws -gu <user> -gp <password> copyFileFromHostToGuest $vmx "<本地文件>" "/home/SecureTransfer/<目标路径>"

# 取回来
& $vmrun -T ws -gu <user> -gp <password> copyFileFromGuestToHost $vmx "<guest 路径>" "<本地路径>"

# 在 guest 里执行命令（把输出重定向到文件再取回来，因为 vmrun 不回传 stdout）
& $vmrun -T ws -gu <user> -gp <password> runProgramInGuest $vmx /bin/sh /tmp/xxx.sh
```

【建议】这台虚拟机目前**只有 NAT 出网、没有 SSH 服务**（本次实测 22 端口不通），所以每次都要用 `vmrun` 搬文件，效率不高。三个可选改善：装 `openssh-server` 并在 `vmnetnat.conf` 里加端口转发（`8889 = 192.168.111.139:22`）、用 VMware 共享文件夹、或直接在虚拟机里的终端写代码。

### 14.2 虚拟机内：编译与测试

```bash
cd /home/SecureTransfer
mkdir -p build && cd build
cmake .. && cmake --build . -j4
ctest --output-on-failure
```

### 14.3 虚拟机内：跑一次完整的安全通信演示

```bash
# 终端 1
cd /home/SecureTransfer/build && ./bob 9000

# 终端 2
cd /home/SecureTransfer/build && ./alice 127.0.0.1 9000
```

期望输出（新增部分用 ★ 标出）：

```text
★ [INFO] [Handshake] HELLO sent (SessionId=3f2a..., NonceA=9c41...)
★ [INFO] [Handshake] HELLO_ACK received, verifying K_master ... OK
★ [INFO] [Handshake] Bob authenticated
★ [INFO] [Handshake] AUTH sent, waiting for KEY_EXCHANGE ...
★ [INFO] [Handshake] KEY_EXCHANGE received, wrapped session key unwrapped
★ [INFO] [Session] KEY_CONFIRM verified - session ESTABLISHED (K_session 双方一致)
  Sent: Hello Bob!
  ...
★ [INFO] [Session] 4/4 messages verified; rejected(mac)=0 rejected(replay)=0
```

### 14.4 攻击演示命令

```bash
# 篡改 / 伪造 / 重放（自动化测试）
./tests/test_tamper && ./tests/test_forge && ./tests/test_replay

# 窃听：另一个终端先开抓包，再跑 alice/bob
sudo tcpdump -i lo -X port 9000 -w /tmp/eve.pcap
strings /tmp/eve.pcap | grep -c "Hello Bob"      # 期望 0
```

---

## 15. 一句话总结

第一部分的 AES 已经就位、网络骨架（TCP + Frame）已经跑通并测过，**第二部分真正要做的是三件事：把包格式定死（§5）、把握手状态机写对（§6）、把 Encrypt-then-MAC + Sequence 组合对并用攻击测试证明（§7、§11.3）**。建议按 M0 → M5 的顺序推进，先在 Mock 密码算法下把协议跑通，再换成真 AES / CMAC，最后用篡改 / 伪造 / 重放 / 窃听四个测试把「安全」从「声称」变成「可验证」。

---

### 附：本方案的事实来源标注

**【已验证】**（本次在 Ubuntu6.21 中实际执行）：第一阶段编译成功、`ctest` 3/3 套件通过；虚拟机的系统 / 工具链 / 库 / 抓包工具版本；`/home/SecureTransfer` 与 `/home/urruna/SecureTransfer.zip` 的文件清单；虚拟机内不存在 AES 源码；虚拟机 IP 与 NAT 配置。

**【已有材料】**（读取现有文件得到，路径为第一轮时的情况）：
`projects/project_q1.md`、`projects/team_interfaces_original.md`（两者现已移入本项目 `docs/` 目录）、
第一阶段 `README.md` / `docs/*.md` / `include/*` / `src/*` / `tests/*`；
`D:\圈圈\课程\算法设计与实验\AES\大作业\aes.h` / `aes.c` / `test.c` / `aes.文件使用说明.txt`。

**【建议 / 待决策】**（本方案提出、尚未验证的设计选择）：§5 的 Packet 具体布局、§6 的握手消息与转录串定义、§7.1 的 Nonce 结构、§8 的密钥管理与派生方案、§12 的里程碑划分与工时估计，以及 §13.1 的 D1–D8 八个决策点。

---
