# 架构说明

## 1. 分层

```text
        ┌──────────────────────────────────────────────────────┐
        │  第三部分：UI（未实现）/ 短消息 / 文件 / 图像 ✅ / 访问控制 │
        └───────────────────────┬──────────────────────────────┘
                                │  FileSender / TransferReceiver
                                │   （文件、图像的加密传输）
                                │  SecureSession
                                ▼
        ┌──────────────────────────────────────────────────────┐
        │  第二部分（本仓库，已完成）                             │
        │  ┌────────────────────────────────────────────────┐  │
        │  │ security/session  ：握手状态机 + 记录层          │  │
        │  │ protocol/packet   ：统一数据包编解码             │  │
        │  │ protocol/transcript：握手 MAC 输入（转录串）      │  │
        │  │ security/replay_guard / keystore                │  │
        │  └────────────────────────────────────────────────┘  │
        └───────────┬───────────────────────────┬──────────────┘
                    │ CryptoProvider            │ Network::sendFrame
                    ▼                           ▼
        ┌───────────────────────────┐  ┌────────────────────────────┐
        │ 第一部分：AES-128 / CMAC   │  │ 第一阶段：Frame / Network   │
        │ （AES 已接入，CMAC 待交付） │  │ （未改动，27 用例回归基线）  │
        └───────────────────────────┘  └────────────────────────────┘
```

依赖方向是**单向**的：`apps → security → protocol → crypto / network`。
网络层不知道协议层的存在；协议层不知道业务类型（短消息 / 文件 / 图像）的存在。

## 2. 模块与职责

| 模块 | 目录 | 职责 |
| --- | --- | --- |
| `log` | `include/common/log.h` | 四级日志（第一阶段成果） |
| `types` / `byte_buffer` / `hex` / `constant_time` / `random` | `include/common/` | 统一类型、TLV 编解码、十六进制、常数时间比较、随机源抽象 |
| `AES`（第一部分） | `include/crypto/aes.h`、`src/crypto/aes.cpp` | 自实现 AES-128：单分组加密 + CTR 模式（原样导入，算法未改动） |
| `CMAC`（第一部分） | `include/crypto/cmac.h`、`src/crypto/cmac.cpp` | 自实现 CMAC（RFC 4493，基于 AES-128）（原样导入） |
| `CmacEngine` | `include/crypto/cmac_engine.h` | 把第一部分的 `CMAC` 适配成协议层的 `MacEngine`（**唯一的粘合代码**） |
| `CryptoProvider` | `include/crypto/crypto_provider.h` | 算法与协议之间的唯一接缝 |
| `MacEngine` | `include/crypto/mac_engine.h` | MAC 算法接缝（CMAC 通过 `CmacEngine` 接入） |
| `AesCryptoProvider` | `src/crypto/aes_crypto_provider.cpp` | 真实 AES-CTR + 默认注入真实 CMAC |
| `PlaceholderMacEngine` | `src/crypto/placeholder_mac_engine.cpp` | ⚠ 开发期占位 MAC（仅用于演示"算法可替换"，不具备密码学强度） |
| `MockCryptoProvider` | `src/crypto/mock_crypto_provider.cpp` | ⚠ 开发期占位（加密与 MAC 都是占位），用于协议联调 |
| `Frame` / `Network` | `include/network/`、`src/network/` | 第一阶段成果：长度前缀分帧、粘包拆包、错误处理 |
| `Packet` | `include/protocol/packet.h`、`src/protocol/packet.cpp` | 统一数据包格式、编解码、字段边界校验 |
| `transcript` | `include/protocol/transcript.h` | 握手 MAC 输入：TLV + 域分离 + 方向标签 |
| `ReplayGuard` | `include/security/replay_guard.h` | 防重放：`wouldAccept()` / `commit()` 两阶段 |
| `KeyStore` | `include/security/keystore.h` | `K_master` 与身份的带外配置读取、权限检查、密钥指纹 |
| `SecureSession` | `include/security/session.h`、`src/security/session.cpp` | 握手状态机、密钥分发、加密 / 完整性 / 防重放的数据通道 |
| `access_control` | `include/security/access_control.h`、`src/security/access_control.cpp` | 访问控制：身份 → 角色 → 权限，服务端权威判定 + 审计日志 |
| `ui`（Qt5） | `apps/ui/` | 图形界面：`MainWindow`（界面）+ `SessionWorker`（工作线程，独占 `SecureSession`）；不含任何密码学逻辑 |
| `application`（文件 / 图像） | `include/application/`、`src/application/` | `crc32`（自实现 CRC32）、`transfer_meta`（元数据与文件名安全校验）、`FileSender` / `TransferReceiver`（分块与重组） |
| `alice` / `bob` | `apps/` | 客户端 / 服务端演示程序 |

## 3. 关键设计决策

| 决策 | 取值 | 原因 |
| --- | --- | --- |
| 协议包放在哪里 | 放在 `Frame::payload` 内 | 复用第一阶段已验证的可靠分帧，网络层零改动 |
| 认证与加密顺序 | 握手用 MAC（明文 Body），数据阶段 Encrypt-then-MAC | 握手时还没有 `K_session`，不能循环依赖；数据阶段先加密可先拒包后解密 |
| MAC 覆盖范围 | 数据包 = `Version..Body`；握手包 = 显式转录串 | 覆盖长度、序号、方向、会话与所有语义字段 |
| SessionId 长度 | 8 字节 | 遵循课程 `project_q1.md` §5 的建议格式 |
| 会话密钥 | 固定值，但**真的传输**（CTR 包裹） | 课程要求"安全分发会话密钥"，且密钥是规定值 |
| 子密钥 | `K_enc` / `K_mac` 由 `K_session` 派生 | 密钥用途分离，避免同一把密钥跨原语使用 |
| Nonce | `随机前缀(8)‖0^4‖消息计数(4)` | `aes_ctr_xor` 会整体自增 128 位计数器，必须隔离计数区以免密钥流复用 |
| 防重放 | 严格递增 + 两阶段提交 | 两阶段避免"伪造大序号包把合法包挤掉"的拒绝服务 |
| 线程模型 | 单线程同步、单会话 | 与第一阶段 `Network` 的非线程安全约定一致，降低出错面 |
| 对外接口 | `SecureSession` 门面 | 第三部分不需要了解 Frame / Packet / 握手细节 |
| 非阻塞接收 | `Network::waitReadable()` + `SecureSession::tryReceiveMessage()` | 图形界面需要"边等数据边处理别的事"：`select()` 等可读，数据一到立刻返回，且"暂时没有数据"不被当作错误（详见 `Part2_transfer.md` §24） |

## 4. 扩展点

### 4.1 替换密码算法实现（保持协议层不变）

第一部分成果（`aes.cpp` / `cmac.cpp`）已经通过 `CmacEngine` 接入，
当前默认的完整性保护就是真实 CMAC。若将来需要换成别的实现（例如统一换成
某个性能更好的版本，或做"自实现 vs 库实现"的对比），只需实现 `MacEngine` 接口：

```cpp
class LibraryMacEngine : public MacEngine {
public:
    const char* name() const override { return "OpenSSL-CMAC"; }
    bool isCryptographicallySecure() const override { return true; }
    MacTag compute(const Key128& key, const Bytes& data) override;
    bool verify(const Key128& key, const Bytes& data, const MacTag& tag) override;
};

// 注入即可：协议层、测试、应用代码都不用改
AesCryptoProvider crypto(new LibraryMacEngine());
```

同理，`CryptoProvider` 也可整体替换（例如换成 `MockCryptoProvider` 做协议联调）。

### 4.2 支持文件 / 图像（第三部分）

协议已经预留 `FILE_START / FILE_CHUNK / FILE_END / IMAGE` 类型，
处理方式与 `DATA` 完全相同：

```cpp
for (每个 64 KiB 分块) {
    session.sendMessage(MessageType::kFileChunk, chunk);   // 自动加密 + MAC + 防重放
}
```

单包 Body 上限 `Packet::kMaxBodySize = 1048519` 字节（约 1 MiB），
建议按 64 KiB 分块以便显示进度。

### 4.3 访问控制（第三部分）

握手完成后 `SessionConfig::localId` / 认证出的对端身份已经确定，
第三部分据此做 Role/Permission 判断即可，第二部分不做权限决策。

## 5. 资源与线程模型

* 一个 `SecureSession` 持有一个 `Network`，析构时自动关闭 socket；禁止拷贝；
* `SecureSession` **不是线程安全的**：同一个对象应由同一线程使用；
* 随机源通过 `RandomSource&` 注入：正式运行用 `SystemRandom`（`/dev/urandom`），
  测试可注入 `FixedRandom` 做可复现的已知值测试；
* 所有 socket 资源在 `close()` / 析构中释放，异常路径同样会释放。

## 6. 与第一阶段的关系

第一阶段成果（`Frame` / `Network` / Alice / Bob / 27 个用例）**原样保留**：

* 位置：`include/network/`、`src/network/`、`tests/unit/test_frame.cpp`、
  `tests/unit/test_network.cpp`、`tests/integration/test_tcp_roundtrip.cpp`；
* 第一阶段文档保留在 `docs/stage1/`；
* 每次改动都必须重新运行这三个测试（回归基线）。
