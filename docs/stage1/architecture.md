# 架构说明

> ⚠ **这是第一阶段（纯 TCP 网络层）的历史文档存档，不代表当前状态。**
> 文中"暂未实现"的会话密钥分发、AES、CMAC、安全协议、性能对比等内容**现已全部完成**；
> 当前进展请看项目根目录的 `Part2_transfer.md` 与 [`../test_report.md`](../test_report.md)。

## 1. 本阶段的分层

```text
                    ┌───────────────────────────┐
                    │      Alice / Bob          │   apps/alice, apps/bob
                    │      （演示程序）          │
                    └─────────────┬─────────────┘
                                  ↓
                    ┌───────────────────────────┐
                    │        Network            │   include/network, src/network
                    │   connect / listen        │   ← 本阶段成果
                    │   accept / sendFrame      │
                    │   receiveFrame / close    │
                    └─────────────┬─────────────┘
                                  ↓
                    ┌───────────────────────────┐
                    │   POSIX Socket / TCP      │   Linux 系统调用
                    └───────────────────────────┘
```

## 2. 模块与职责

| 模块 | 目录 | 职责 |
| --- | --- | --- |
| `Frame` | `include/network/frame.h`、`src/network/frame.cpp` | 定义线上数据单元；负责序列化 / 反序列化；检查长度合法性 |
| `Network` | `include/network/network.h`、`src/network/network.cpp` | 建立 TCP 连接；把 `Frame` 可靠地按边界送出与收全；统一错误处理 |
| 日志 `stlog` | `include/common/log.h` | `DEBUG/INFO/WARN/ERROR` 四级日志，供全部模块共用 |
| Alice | `apps/alice/main.cpp` | 客户端流程演示：连接 → 发送 → 接收 → 关闭 |
| Bob | `apps/bob/main.cpp` | 服务端流程演示：监听 → 接受 → 接收 → 回复 → 关闭 |
| 测试 | `tests/` | Frame / Network / 集成测试，可用 `ctest` 运行 |

**依赖方向是单向的**：应用 → Network → Socket；Network 不依赖应用，
也不依赖任何未来的密码模块。密码模块将来是 Network 的**同级依赖**，
由上层（安全协议层）调用：

```text
Application / Security
        ↓
    CryptoProvider        （未来的 AES / CMAC 实现挂在这里）

Application
        ↓
    Network               （本阶段成果，不需要修改）
```

## 3. 关键设计决策

| 决策 | 取值 | 原因 |
| --- | --- | --- |
| 长度字段 | 4 字节，大端序 | TCP 是字节流，必须先给出消息边界；大端序与网络字节序一致，便于跨平台 |
| 最大 payload | 1 MB | 防止恶意或错误长度导致大额内存分配 |
| 分帧方式 | 读 4 字节长度 → 按长度读满 payload | 实现简单、边界清晰，任意二进制数据都能传 |
| 服务端并发 | 单连接（`backlog = 1`） | 课程演示足够；多连接可在网络层之外扩展（多线程 / epoll），协议不变 |
| 错误处理 | 返回 `bool` + `lastResult()` / `lastError()` | 不抛异常，调用点可控；同时给出可读原因，方便定位 |
| 超时 | 可选（默认阻塞） | 默认行为符合"一次完整通信"的演示逻辑；测试与健壮性场景可打开超时 |
| 命名空间 | `Frame`、`Network` 直接放在全局命名空间 | 与项目组约定的接口写法一致；后续若与其它模块冲突，可整体移入命名空间 |

## 4. 为后续安全模块预留的扩展点

### 4.1 目录预留（后续阶段创建）

```text
include/
├── common/       # 公共类型：Byte/Bytes、Key128、Nonce、SessionId、MacTag
├── crypto/       # CryptoProvider 接口 + AES/CMAC 实现
├── protocol/     # MessageType、Packet、PacketSerializer、状态机
├── security/     # 会话、密钥分发、访问控制
└── application/  # 文本 / 文件 / 图像传输

src/
├── crypto/
├── protocol/
├── security/
└── application/
```

### 4.2 需要新增的接口（建议）

```cpp
// include/crypto/crypto_provider.h
class CryptoProvider {
public:
    virtual ~CryptoProvider() = default;
    virtual Bytes aesCtrEncrypt(const Key128& key, const Nonce& nonce, const Bytes& plaintext) = 0;
    virtual Bytes aesCtrDecrypt(const Key128& key, const Nonce& nonce, const Bytes& ciphertext) = 0;
    virtual MacTag cmac(const Key128& key, const Bytes& data) = 0;
    virtual bool verifyCmac(const Key128& key, const Bytes& data, const MacTag& tag) = 0;
};
```

网络层与它的关系：

```text
安全协议层：明文 --AES-CTR--> 密文 --CMAC--> 认证标签
                                              ↓
                      组装成 Frame.payload（字节串）
                                              ↓
                            Network::sendFrame(frame)
```

也就是说，**安全机制完全在 `Frame::payload` 内部完成**，
`Network` 只负责"把这串字节按帧可靠地送到对端"。
这样 AES / CMAC 的实现替换不会影响网络层代码。

### 4.3 Frame 的扩展方式

后续需要携带 `MessageType`、`SessionId`、`Sequence`、`Nonce`、`MacTag` 时，
建议采用**新增头部字段**的方式扩展 Frame（例如把现在的 `length` 扩展为
`length + header`），并且：

1. `serialize()` / `deserialize()` 的**函数签名保持不变**；
2. `Network::sendFrame()` / `receiveFrame()` 的调用方式保持不变；
3. 版本号（Version 字段）用于区分新旧格式；
4. 扩展后必须同步更新 `docs/protocol.md` 与 `tests/unit/test_frame.cpp`。

现有测试（空 payload、1 MB、非法长度、截断等）在扩展后应继续通过，
这是保证"网络层不被推翻重写"的回归测试基线。

## 5. 线程与资源模型

* 一个 `Network` 对象持有 0~2 个 socket（监听 socket + 连接 socket）；
* 析构函数会自动 `close()`，不需要手动释放；禁止拷贝 / 移动，避免重复关闭；
* `Network` 本身**不是线程安全的**：同一个对象应由同一个线程使用；
  多连接场景应为每个连接建立独立的 `Network` 对象；
* 所有 socket 资源都在 `close()` 中关闭，异常路径（连接失败、帧非法）也会释放。
