# 接口说明

标记约定：

* **[STABLE]** —— 对其它部分承诺的接口，签名不要随意修改；
* **[EXTENSION]** —— 便利接口，可在不破坏核心接口的前提下调整；
* **[TEST ONLY]** —— 只允许测试 / 演示代码使用。

---

## 1. `SecureSession`（[STABLE]）

头文件：`include/security/session.h`

```cpp
SecureSession(CryptoProvider& crypto,
              const SessionConfig& config,
              RandomSource& random = RandomSource::system());
~SecureSession();

// 建立会话
bool connectToServer();     // 客户端：TCP connect + 完整握手
bool acceptOneClient();     // 服务端：listen + accept + 完整握手

// 业务数据
bool sendMessage(MessageType type, const Bytes& plaintext);
bool receiveMessage(MessageType& type, Bytes& plaintext);

// 业务数据（非阻塞版，图形界面等工作线程用）
enum class ReceiveStatus { kMessage, kNothing, kClosed };
ReceiveStatus tryReceiveMessage(MessageType& type, Bytes& plaintext, int waitMs = 0);

void close();

// 诊断
SessionState state() const;
bool isEstablished() const;
const SessionId& sessionId() const;
const ProtocolStats& stats() const;
const std::string& lastError() const;
std::uint16_t listeningPort() const;
bool macIsCryptographicallySecure() const;
const Nonce& nonceA() const;  const Nonce& nonceB() const;
std::uint64_t sendSequence() const;  std::uint64_t receiveSequence() const;
const PacketTrace& lastSentTrace() const;
const PacketTrace& lastReceivedTrace() const;
```

| 方法 | 成功条件 | 常见失败原因 |
| --- | --- | --- |
| `connectToServer()` | 返回 true 时 `state() == kEstablished` | 服务端未启动、`K_master` 不一致（认证失败）、握手超时 |
| `acceptOneClient()` | 同上 | 端口被占用、对端认证失败 |
| `sendMessage()` | 消息已加密 + MAC 后写入 socket | 会话未建立、消息类型不允许、Body 超过 1048519 字节、序号耗尽 |
| `receiveMessage()` | 返回 true 且 `plaintext` 为解密结果（`type == kClose` 时为空） | 格式非法、SessionId/方向不符、重放、MAC 校验失败、对端关闭、超时 |
| `tryReceiveMessage(..., waitMs)` | 返回 `kMessage`（同 `receiveMessage()` 成功）；`kNothing` 表示在 `waitMs` 内没有数据（**不是错误**、不写 `lastError()`）；`kClosed` 表示会话不可继续 | 同 `receiveMessage()`（但"暂时没有数据"不算失败） |
| `close()` | 关闭 socket，可重复调用 | — |

`SessionConfig` 字段：

```cpp
std::string localId;            // 本端身份，如 "alice"
std::string peerId;             // 期望的对端身份，如 "bob"
std::string host = "127.0.0.1"; // 客户端使用
std::uint16_t port = 9000;      // 服务端监听 / 客户端连接；服务端传 0 由系统分配
Key128 masterKey{};             // K_master
bool hasMasterKey = false;
int handshakeTimeoutMs = 5000;  // 握手超时
int ioTimeoutMs = 10000;        // 数据阶段超时
bool logHandshake = true;
std::function<void(std::uint16_t)> onListening;  // 服务端开始监听的回调（拿真实端口）
```

`ProtocolStats`（用于报告与界面状态）：

```cpp
sentPackets / receivedPackets / sentBytes / receivedBytes
rejectedFormat / rejectedReplay / rejectedMac / rejectedState
handshakesOk / handshakesFailed
std::string summary() const;    // 单行摘要
```

## 2. `CryptoProvider`（[STABLE]，第一部分实现 / 第二部分调用）

```cpp
class CryptoProvider {
public:
    virtual const char* name() const = 0;
    virtual bool macIsCryptographicallySecure() const = 0;
    virtual Bytes aesCtrEncrypt(const Key128& key, const Nonce& nonce, const Bytes& plaintext) = 0;
    virtual Bytes aesCtrDecrypt(const Key128& key, const Nonce& nonce, const Bytes& ciphertext) = 0;
    virtual MacTag cmac(const Key128& key, const Bytes& data) = 0;
    virtual bool verifyCmac(const Key128& key, const Bytes& data, const MacTag& tag) = 0;
};
```

约束：

1. `aesCtrEncrypt/Decrypt` 支持任意长度（0 字节、1 字节、非 16 倍数、1 MiB），并且互为逆运算；
2. `verifyCmac` 必须使用常数时间比较；
3. 不允许在日志中输出密钥。

现有实现：

| 实现 | AES | MAC | 用途 |
| --- | --- | --- | --- |
| `AesCryptoProvider` | 真实 AES-128-CTR（第一部分 `AES`） | **默认真实 CMAC（第一部分 `CMAC`，经 `CmacEngine`）** | 正式运行 / 演示 |
| `MockCryptoProvider` | 占位 | 占位 | 协议联调（更快、更可控） |

`AesCryptoProvider` 构造函数：

```cpp
explicit AesCryptoProvider(MacEngine* macEngine = nullptr);
// nullptr（默认）=> 使用第一部分的 CMAC
// 传入其它 MacEngine => 用于演示"算法可替换"或做对比实验
```

## 3. `MacEngine`（[STABLE]，算法替换接缝）

```cpp
class MacEngine {
public:
    virtual const char* name() const = 0;
    virtual bool isCryptographicallySecure() const = 0;
    virtual MacTag compute(const Key128& key, const Bytes& data) = 0;
    virtual bool verify(const Key128& key, const Bytes& data, const MacTag& tag) = 0;
};
```

**当前状态**：第一部分的 CMAC 已交付并接入：

```cpp
// include/crypto/cmac_engine.h —— 唯一的粘合代码
class CmacEngine : public MacEngine {
    // name()  -> "CMAC(AES-128, RFC 4493)"
    // isCryptographicallySecure() -> true
    // compute/verify -> 直接转发给第一部分的 CMAC
};
```

即 `AesCryptoProvider` 默认使用真实 CMAC；
`PlaceholderMacEngine` 仍保留，仅在显式传入时使用（`--placeholder`），
用于演示"密码算法与协议层解耦"。

## 3.1 第一部分算法接口（[STABLE]，第一部分所有）

```cpp
// include/crypto/aes.h
void aes128_key_expand(const uint8_t key[16], uint8_t rk[AES128_RK_SIZE]);
void aes128_encrypt_block(const uint8_t rk[AES128_RK_SIZE], const uint8_t in[16], uint8_t out[16]);

class AES {
public:
    Bytes encryptBlock(const Key128& key, const Block128& block);   // 单分组（CMAC 使用）
    void  ctrXor(const Key128& key, const Block128& nonce,          // CTR 原地加解密
                 uint8_t* data, size_t len);
};

// include/crypto/cmac.h
class CMAC {
public:
    MacTag generate(const Key128& key, const Bytes& message);       // RFC 4493
    bool   verify(const Key128& key, const Bytes& message, const MacTag& tag);
};
```

约束：**第二部分不修改这两个文件**；它们已用标准向量验证
（FIPS-197 / NIST SP 800-38A / RFC 4493，见 `tests/unit/test_aes_cmac.cpp`）。

## 4. `Packet`（[STABLE]）

```cpp
struct Packet {
    static constexpr std::size_t kHeaderSize = 41;
    static constexpr std::size_t kMacSize = 16;
    static constexpr std::size_t kOverhead = 57;
    static constexpr std::size_t kMaxBodySize = 1024*1024 - 57;   // 1048519
    static constexpr Byte kMagic0 = 0x53, kMagic1 = 0x54, kVersion = 0x01;

    Byte version; MessageType type; Direction direction;
    SessionId sessionId; std::uint64_t sequence; Nonce nonce;
    Bytes body; MacTag mac;

    Bytes encode() const;             // [Version .. Body] = 数据包的 MAC 输入
    Bytes encodeWithMac() const;      // [Magic .. MacTag] = 完整线上字节
    std::size_t wireSize() const;
    bool isValid() const;
    static bool decode(const Bytes& wire, Packet& out, std::string* error = nullptr);
};
```

## 5. `KeyStore`（[EXTENSION]）

```cpp
struct KeyStoreConfig {
    std::string aliceId, bobId;
    Key128 masterKey{};
    bool hasMasterKey = false;
    std::string source;
};

static bool KeyStore::loadFile(path, KeyStoreConfig& out, std::string& error, std::string& warning);
static bool KeyStore::parse(text, out, error);
static bool KeyStore::parseKey(text, Key128& out, error);
static bool KeyStore::checkFilePermissions(path, warning);
static std::string KeyStore::keyFingerprint(const Key128& key);   // 只用于标识密钥
```

配置文件格式（`configs/keys.conf`，建议 `chmod 600`）：

```ini
[identity]
alice_id = alice
bob_id   = bob
[keys]
master_key = 0f1e2d3c4b5a69788796a5b4c3d2e1f0
```

## 6. `ReplayGuard`（[EXTENSION]）

```cpp
bool wouldAccept(std::uint64_t sequence, std::string* reason = nullptr) const;  // 只判断
bool commit(std::uint64_t sequence);                                            // 通过后推进
bool accept(std::uint64_t sequence, std::string* reason = nullptr);              // 两者合一
std::uint64_t lastSequence() const;
std::uint64_t acceptedCount() const; std::uint64_t rejectedCount() const;
std::uint64_t gapCount() const;
void reset();
```

## 7. 测试 / 演示专用接口（[TEST ONLY]）

```cpp
// SecureSession
bool sendRawWireForTesting(const Bytes& wire);      // 绕过加密与 MAC，直接发送原始字节
const Bytes& lastSentWireForTesting() const;        // 最近一次写进 socket 的原始字节
```

用途：

* `test_tamper`：修改密文字节后重发；
* `test_replay`：把截获的字节原样重发；
* 第三部分的 Eve 攻击演示。

**正式业务代码不得调用**。

## 8. 与 `docs/team_interfaces_original.md`（组内最初约定）的差异说明

`docs/team_interfaces_original.md` 是小组最初约定的接口草案。实现时为了让**第一阶段的网络层保持不变**、
并兼顾 CTR 原地加解密的效率，有三处差异。这些差异不影响功能，但为了避免
"文档写一套、代码是另一套"的误解，在此统一说明：

| 项目 | `team_interfaces_original.md` 的约定 | 实际实现 | 说明 |
| --- | --- | --- | --- |
| AES 单分组 | `Bytes AES::encryptBlock(const Key128&, const Block128&)` | 一致 | — |
| CMAC | `MacTag CMAC::generate(...)` / `bool CMAC::verify(...)` | 一致 | — |
| **AES-CTR** | `Bytes AES::encryptCTR(const Key128&, const Nonce&, const Bytes&)` | `void AES::ctrXor(const Key128&, const Block128&, uint8_t* data, size_t len)` | 语义完全等价（原地异或完成加解密）。第二部分在 `AesCryptoProvider` 内部包了一层返回 `Bytes` 的适配，因此**上层不受影响**；若要严格对齐组内签名，只需在第一部分补一个约 5 行的 `encryptCTR` 薄封装 |
| **Frame 字段** | `type / sessionId / sequence / nonce / payload / mac` 都放在 `Frame` 里，并给 `Frame` 加 `serialize(const Frame&)` / `deserialize(const Bytes&)` | `Frame` 仍是 `length + payload`；上述协议字段放在 `Packet`（塞进 `Frame::payload`） | 目的是**不改动第一阶段已验证的网络层**（27 个回归用例继续有效），协议字段的演进不会波及网络层；见 `docs/protocol.md` §2 |

**建议**：如果课程/组内要求严格按 `team_interfaces_original.md` 的签名检查，改动应放在**第一部分**
（补一个 `AES::encryptCTR` 薄封装，不动现有实现），而不是改第二部分——
因为第二部分已经把算法调用收口在 `CryptoProvider` 一处。

## 9. 应用层：文件 / 图像传输（[STABLE]）

头文件：`include/application/file_transfer.h`

```cpp
namespace transfer {

struct SendResult {
    bool ok; std::string fileName; Kind kind;
    std::uint64_t bytes; std::uint32_t crc32;
    std::size_t chunks; bool singleShot;
    double seconds; double megabytesPerSecond; std::string error;
};

class FileSender {
public:
    using ProgressCallback = std::function<void(std::uint64_t, std::uint64_t)>;
    static SendResult send(SecureSession& session, const std::string& path, Kind kind,
                           bool forceChunked = false,
                           const ProgressCallback& onProgress = nullptr);
};

class TransferReceiver {
public:
    explicit TransferReceiver(std::string outputDir);
    bool handle(MessageType type, const Bytes& body, std::string* error);  // true = 已消费
    bool inProgress() const;
    std::uint64_t receivedBytes() const;
    std::uint64_t expectedBytes() const;
    const std::string& currentFileName() const;
    const ReceiveResult& lastResult() const;
    std::size_t completedCount() const;
    std::size_t failedCount() const;
};

}  // namespace transfer
```

| 方法 | 行为 |
| --- | --- |
| `FileSender::send()` | 读取文件 → 自动选择单包（小图像）或分块（64 KiB）→ 逐块 `sendMessage` → 返回统计（字节数 / 分块数 / CRC32 / 耗时 / 吞吐） |
| `TransferReceiver::handle()` | 返回 `true` 表示这条消息属于文件传输流程（`FILE_START` / `FILE_CHUNK` / `FILE_END` / `IMAGE`），已由本类消费；返回 `false` 时应交回给普通消息处理 |
| `lastResult()` | 最近一次传输结果（成功或失败都记录：文件名、落盘路径、字节数、CRC32、失败原因） |

配套类型与常量在 `include/application/transfer_meta.h`：

```cpp
constexpr std::size_t kChunkSize = 64 * 1024;   // 分块大小
enum class Kind : Byte { kFile = 0, kImage = 1 };
enum class Mode : Byte { kSingleShot = 0, kChunked = 1 };
bool isSafeFileName(const std::string& name);   // 防目录穿越
```

CRC32 在 `include/application/crc32.h`（自实现，流式接口）：

```cpp
class Crc32 {
public:
    void update(const Byte* data, std::size_t length);
    void update(const Bytes& data);
    std::uint32_t value() const;
    void reset();
    static std::uint32_t compute(const Bytes& data);
};
```

## 10. 访问控制（[STABLE]）

头文件：`include/security/access_control.h`

```cpp
namespace access {

enum class Operation : Byte { kSendMessage, kSendFile, kSendImage, kViewLog, kManageUsers };
const char* operationToString(Operation);
bool operationFromMessageType(MessageType type, Operation& operation);  // 消息类型 → 受保护操作

class PermissionSet {
public:
    void grant(Operation);
    bool contains(Operation) const;
    std::string toString() const;   // "send_message, send_file"
};

class AccessController {
public:
    bool loadFile(const std::string& path, std::string& error, std::string& warning);
    bool loadText(const std::string& text, std::string& error);
    std::string roleOf(const std::string& identity) const;          // 未登记身份 → defaultRole
    PermissionSet permissionsOf(const std::string& identity) const; // 角色未定义 → 无权限
    bool isAllowed(const std::string& identity, Operation operation) const;
    bool setAuditLogFile(const std::string& path, std::string& error);
    void record(const std::string& identity, Operation operation, bool allowed,
                const std::string& detail);
    const std::vector<std::string>& recentDecisions() const;
    std::size_t allowedCount() const;
    std::size_t deniedCount() const;
    std::string policySummary() const;
};

}  // namespace access
```

约定：

1. **判定在服务端做**：客户端可以加载同一份策略用于提示，但不能作为授权依据；
2. **默认拒绝**：未登记身份落到 `defaultRole`；角色未定义权限时视为无权限；
3. **拒绝的是操作，不是会话**：越权只拒该操作并计数；篡改/重放仍按协议层规则终止会话；
4. `record()` 同时写内存（供 `VIEW_LOG` 返回）与审计文件。
