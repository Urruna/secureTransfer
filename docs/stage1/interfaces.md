# 公共接口说明

> ⚠ **这是第一阶段（纯 TCP 网络层）的历史文档存档，不代表当前状态。**
> 文中"暂未实现"的安全机制**现已全部完成**；当前对外接口请看
> [`../interfaces.md`](../interfaces.md)。

标记约定：

* **[STABLE API]** —— 项目组约定的接口，**不要随意修改**签名；
* **[EXTENSION]** —— 为方便 demo / 测试 / 后续模块提供的接口，可以在保持
  核心接口不变的前提下调整；
* **[IMPLEMENTATION DETAIL]** —— 内部实现，外部不应依赖。

---

## 1. `Network`（[STABLE API]）

头文件：`include/network/network.h`

```cpp
class Network {
public:
    bool connect(const std::string& host, uint16_t port);
    bool listen(uint16_t port);
    bool accept();
    bool sendFrame(const Frame& frame);
    bool receiveFrame(Frame& frame);
    void close();
};
```

以下方法均为"成功返回 `true`，失败返回 `false`"，失败原因通过
`lastResult()` 与 `lastError()` 读取。

### `bool connect(const std::string& host, uint16_t port)`

| 项目 | 说明 |
| --- | --- |
| 输入 | `host`：主机名或 IP（如 `"127.0.0.1"`）；`port`：1~65535 |
| 输出 | 成功时内部保存已连接的 socket，`isConnected() == true` |
| 错误 | `INVALID_ARGUMENT`（host 为空 / port 为 0）、`SOCKET_FAILURE`（解析失败、连接被拒绝、网络不可达） |
| 调用时机 | 客户端（Alice）在最开始调用一次；必须在 `sendFrame()` 之前 |
| 备注 | 内部用 `getaddrinfo()` 解析，IPv4 / IPv6 都支持 |

### `bool listen(uint16_t port)`

| 项目 | 说明 |
| --- | --- |
| 输入 | `port`：监听端口；**传 0 表示由系统分配临时端口**（测试用） |
| 输出 | 成功时进入监听状态，`isListening() == true`；实际端口见 `boundPort()` |
| 错误 | `SOCKET_FAILURE`（`socket()` / `bind()` / `listen()` 失败，端口被占用时 bind 会失败） |
| 调用时机 | 服务端（Bob）在最开始调用一次；必须在 `accept()` 之前 |
| 备注 | 自动设置 `SO_REUSEADDR`；`backlog = 1`（单客户端演示） |

### `bool accept()`

| 项目 | 说明 |
| --- | --- |
| 输入 | 无 |
| 输出 | 成功时获得一个已连接 socket，`isConnected() == true` |
| 错误 | `NOT_CONNECTED`（没有先 `listen()`）、`SOCKET_FAILURE`（系统调用失败） |
| 调用时机 | 服务端在 `listen()` 之后调用；会阻塞直到有客户端接入 |
| 备注 | 若已存在旧连接，会先关闭旧连接再接受新连接（演示阶段的单连接策略） |

### `bool sendFrame(const Frame& frame)`

| 项目 | 说明 |
| --- | --- |
| 输入 | `frame`：待发送的 Frame（`length` 必须等于 `payload.size()`，且不超过 1 MB） |
| 输出 | 成功时保证 `4 + length` 个字节已全部按顺序交给内核发送 |
| 错误 | `NOT_CONNECTED`（未建立连接）、`INVALID_FRAME`（Frame 非法）、`TIMEOUT`、`PEER_CLOSED`、`SOCKET_FAILURE` |
| 调用时机 | 连接建立之后的任意时刻；内部循环发送以处理 partial send |
| 备注 | Frame 非法时**不发送任何字节**，因此不会破坏 TCP 字节流 |

### `bool receiveFrame(Frame& frame)`

| 项目 | 说明 |
| --- | --- |
| 输入 | `frame`：输出参数，仅在返回 `true` 时被覆盖 |
| 输出 | 成功时 `frame` 是一个完整 Frame |
| 错误 | `NOT_CONNECTED`、`INVALID_FRAME`（收到的 length 超过 1 MB）、`PEER_CLOSED`（对端关闭或中途断开）、`TIMEOUT`、`SOCKET_FAILURE` |
| 调用时机 | 连接建立之后；默认阻塞，可先用 `setReceiveTimeoutMs()` 设置超时 |
| 备注 | 内部先读 4 字节 length，再读满 payload，正确处理粘包 / 拆包 |

### `void close()`

| 项目 | 说明 |
| --- | --- |
| 输入 | 无 |
| 输出 | 关闭监听 socket 与连接 socket；可重复调用 |
| 错误 | 无（不会修改 `lastResult()` / `lastError()`） |
| 调用时机 | 通信结束、程序退出前；析构函数也会自动调用 |

## 2. `Network` 的扩展接口（[EXTENSION]）

```cpp
bool isConnected() const;          // 连接是否已建立
bool isListening() const;          // 是否处于监听状态
uint16_t boundPort() const;        // listen() 实际绑定的端口（port==0 时使用）
bool setTcpNoDelay(bool on);       // 是否关闭 Nagle 算法（默认在 accept() 中打开）
bool setReceiveTimeoutMs(int ms);  // recv 超时，0 = 永不超时
bool setSendTimeoutMs(int ms);     // send 超时，0 = 永不超时
Result lastResult() const;         // 最近一次操作结果
const std::string& lastError() const;  // 最近一次失败的详细描述
static const char* resultToString(Result result);
```

`Result` 取值：`OK`、`PEER_CLOSED`、`TIMEOUT`、`INVALID_FRAME`、
`NOT_CONNECTED`、`INVALID_ARGUMENT`、`SOCKET_FAILURE`。

`setReceiveTimeoutMs()` / `setSendTimeoutMs()` 必须在连接建立后调用
（它们作用于连接 socket）；`listen()` 阶段不需要超时。

## 3. `Frame`（[STABLE API]）

头文件：`include/network/frame.h`

```cpp
struct Frame {
    static constexpr std::size_t kLengthFieldSize = 4;
    static constexpr std::size_t kMaxPayloadSize = 1024u * 1024u;

    uint32_t length;
    std::vector<uint8_t> payload;

    Frame();
    explicit Frame(const std::vector<uint8_t>& data);
    Frame(uint32_t length, const std::vector<uint8_t>& payload);

    static Frame fromString(const std::string& text);
    static Frame fromBytes(const std::vector<uint8_t>& data);

    void setPayload(const std::vector<uint8_t>& data);
    void setPayload(const std::string& text);

    std::string toString() const;
    bool isEmpty() const;
    bool isValid() const;
    std::size_t wireSize() const;

    std::vector<uint8_t> serialize() const;
    static Status deserialize(const std::vector<uint8_t>& buffer,
                              Frame& frame,
                              std::size_t* consumed = nullptr);

    static void encodeLength(uint32_t length, uint8_t* out4Bytes);
    static uint32_t decodeLength(const uint8_t* in4Bytes);
    static bool isPayloadLengthValid(uint32_t length);
    static const char* statusToString(Status status);
};
```

| 方法 | 输入 | 输出 / 错误 |
| --- | --- | --- |
| `fromString(text)` | UTF-8 文本 | 新的 Frame（payload = 文本字节，不含 `'\0'`） |
| `fromBytes(data)` | 任意二进制 | 新的 Frame（`length` 自动等于 `data.size()`） |
| `setPayload(...)` | 数据 | 同步更新 `length` |
| `toString()` | — | payload 按字节原样转成 `std::string`（二进制数据不会被截断） |
| `isValid()` | — | `length == payload.size()` 且 `length <= 1 MB` |
| `wireSize()` | — | `4 + payload.size()` |
| `serialize()` | — | 成功返回 `[length][payload]`；Frame 非法时返回空 vector 并输出 `[ERROR]` 日志 |
| `deserialize(buffer, frame, consumed)` | 字节缓冲区（可含多个 Frame 的数据） | `Status::OK` / `INCOMPLETE` / `LENGTH_TOO_LARGE`；`consumed` 返回本次消耗的字节数 |
| `Frame::Status` | — | `OK`、`INCOMPLETE`（数据不够）、`LENGTH_TOO_LARGE`（length 超过 1 MB） |

`serialize()` / `deserialize()` 与 `Network::sendFrame()` / `receiveFrame()`
的分工：`Network` 负责"按边界收发字节"，`Frame` 负责"字节与结构体之间的转换"。

## 4. 日志接口（[EXTENSION]）

头文件：`include/common/log.h`

```cpp
stlog::setMinLevel(stlog::Level::DEBUG);        // 调整日志级别
stlog::initFromEnvironment();                   // 读取环境变量 ST_LOG_LEVEL

ST_LOG_INFO("Bob", "message");                  // [INFO] [Bob] message
ST_LOG_WARN_STREAM("Network", "port=" << 9000); // [WARN] [Network] port=9000
```

级别：`DEBUG < INFO < WARN < ERROR`，默认只输出 `INFO` 及以上。
**禁止**在日志里输出 `K_master`、会话密钥等敏感数据；
若确实需要，只能在 `DEBUG` 级别并且默认关闭。

## 5. 内部实现细节（[IMPLEMENTATION DETAIL]）

以下内容属于实现细节，上层不要依赖：

* `Network::writeAll()` / `readExact()`：解决 partial send / partial recv；
* `Network::applyTimeout()`：`setsockopt(SO_RCVTIMEO/SO_SNDTIMEO)` 的平台细节；
* `Network::fail()` / `resetError()`：统一错误记录方式；
* `listenSocket_` / `connectionSocket_`：内部保存的 socket 描述符；
* `kListenBacklog = 1`：监听队列长度；
* `kSendFlags = MSG_NOSIGNAL`：避免对端断开时进程被 `SIGPIPE` 终止；
* 测试用的 `tests/raw_client.h`：直接操作 socket 构造异常字节流。
