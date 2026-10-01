# 通信协议说明（第一阶段：Frame 层）

> ⚠ **这是第一阶段（纯 TCP 网络层）的历史文档存档，不代表当前状态。**
> 本文件描述的只是 `Frame = length + payload` 这一层；完整的协议格式
> （41 字节包头 + 密文 + CMAC）请看 [`../protocol.md`](../protocol.md)。

本文件描述**网络层**的线上格式与收发流程。
身份认证、密钥交换、加密与完整性保护属于后续阶段，见
`docs/requirements.md` 的"暂未实现"清单。

## 1. Frame 线上格式

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+-------------------------------+
|        length (4 bytes)       |                               |
+-------------------------------+                               |
|                    payload (length bytes)                     |
|                            ...                                |
+---------------------------------------------------------------+
```

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| `length` | 4 字节 | payload 的字节数，**大端序**（网络字节序），取值范围 `0 ~ 1048576` |
| `payload` | `length` 字节 | 任意二进制数据（本阶段是明文；后续放密文 + MAC 相关材料） |

* 一个 Frame 的线上总字节数 = `4 + length`（`Frame::wireSize()`）；
* `length = 0` 是合法的，表示空 payload；
* `length > 1048576` 直接判为非法，接收方**不会**为其分配内存；
* 字节序统一为大端，`Frame::encodeLength()` / `decodeLength()` 负责转换。

## 2. 为什么要长度前缀

TCP 提供的是**字节流**，不保留消息边界：

```text
发送方调用 3 次 send("A")  send("B")  send("C")

接收方可能收到：
    "ABC"        （一次 recv 收到三条消息 —— 粘包）
    "AB" "C"     （消息被切开 —— 拆包）
    "A" "BC"     （任意组合）
```

因此**不能**假设"一次 `send()` 对应一次 `recv()`"。
本阶段用长度前缀解决边界问题：

```text
发送：Frame -> serialize() -> [length][payload] -> writeAll() 反复 send 直到发完
接收：readExact(4) 读出 length -> 检查长度 -> readExact(length) 读满 payload -> deserialize()
```

## 3. 发送流程（writeAll）

```text
sendFrame(frame)
   │
   ├─ frame.isValid() ?  否 -> 返回 false，lastResult = INVALID_FRAME（不发送任何字节）
   │
   ├─ serialize() 得到 [length][payload]
   │
   └─ writeAll(buffer, size)
          while 还有剩余字节:
              n = send(剩余部分)
              n > 0 : 继续发送剩下的
              n = 0 : 视为异常
              n < 0 : EINTR -> 重试
                      EAGAIN/EWOULDBLOCK/ETIMEDOUT -> TIMEOUT
                      EPIPE/ECONNRESET/ENOTCONN -> PEER_CLOSED
                      其它 -> SOCKET_FAILURE
```

要点：`send()` 返回值可能**小于请求长度**，必须循环发送直到发完
（partial send），否则对端收到的字节流就会不完整。

## 4. 接收流程（readExact）

```text
receiveFrame(frame)
   │
   ├─ 已建立连接 ?  否 -> 返回 false，lastResult = NOT_CONNECTED
   │
   ├─ readExact(4 字节) 读出 length
   │      recv() = 0      -> PEER_CLOSED（对端关闭）
   │      recv() < 请求量 -> 继续读，直到读满或出错
   │
   ├─ length <= 1 MB ?  否 -> 返回 false，lastResult = INVALID_FRAME
   │                           （此时**不分配** 1 MB 以上内存）
   │
   └─ readExact(length 字节) 读满 payload
          -> 组装 Frame{length, payload} 返回 true
```

要点：`readExact()` 保证调用结束后缓冲区被填满，因此无论 TCP 如何切分数据，
上层拿到的永远是一个完整 Frame；多余的字节留在内核缓冲区里，
下一次 `receiveFrame()` 会继续读取，不会丢失或错位。

## 5. 错误处理对照表

| 场景 | 返回值 | `lastResult()` | 说明 |
| --- | --- | --- | --- |
| 正常收发 | `true` | `OK` | — |
| `connect()` 失败（没人监听） | `false` | `SOCKET_FAILURE` | 例如 `errno 111 (Connection refused)` |
| `bind()` 端口被占用 | `false` | `SOCKET_FAILURE` | 例如 `errno 98 (Address already in use)` |
| 未连接就 `sendFrame()` / `receiveFrame()` | `false` | `NOT_CONNECTED` | 接口使用顺序错误 |
| `accept()` 之前没有 `listen()` | `false` | `NOT_CONNECTED` | — |
| Frame 长度与 payload 不一致 / 超过 1 MB | `false` | `INVALID_FRAME` | 不会发送任何字节 |
| 收到的 `length` 超过 1 MB | `false` | `INVALID_FRAME` | 不会分配内存 |
| 对端关闭连接（`recv()` 返回 0） | `false` | `PEER_CLOSED` | 正常结束或对端崩溃 |
| 对端在 payload 中途断开 | `false` | `PEER_CLOSED` | 帧不完整，直接放弃该连接 |
| 设置了超时但对方一直不发送 | `false` | `TIMEOUT` | 可用于测试与健壮性场景 |
| `host` 为空 / `port` 为 0 | `false` | `INVALID_ARGUMENT` | 参数检查 |

## 6. 一次完整通信的时序

```text
Bob (服务端)                                  Alice (客户端)
-----------------                             -----------------
socket/bind/listen(9000)
                                              socket/connect(127.0.0.1, 9000)
accept()            <───────────────────────  TCP 三次握手完成
receiveFrame()      <──── [09]["Hello Bob"] ──  sendFrame("Hello Bob")
sendFrame("Hello Alice")                      receiveFrame()
                    ──── [0B]["Hello Alice"] ──> 打印 "Hello Alice"
close()                                       close()
```

（`[09]` 表示 length = 9 的 4 字节大端表示 `00 00 00 09`。）

## 7. 后续阶段的协议扩展

课程要求的安全协议（`project_q1.md`）会在本 Frame 之上扩展。
推荐做法是**新增头部字段**，而不是修改 `Network` 的接口：

```text
+----------------+----------------+----------------+----------------+
| Magic (2)      | Version (1)    | Type (2)       | Header Len (2) |
+----------------+----------------+----------------+----------------+
| Session ID (16)                                                  |
+------------------------------------------------------------------+
| Sequence (8)                                                     |
+------------------------------------------------------------------+
| Nonce (16)                                                       |
+------------------------------------------------------------------+
| Payload Length (4)                                               |
+------------------------------------------------------------------+
| Ciphertext (N)                                                   |
+------------------------------------------------------------------+
| CMAC (16)                                                        |
+------------------------------------------------------------------+
```

* `Type`：`HELLO / HELLO_ACK / AUTH_REQUEST / AUTH_RESPONSE / AUTH_SUCCESS /
  AUTH_FAILURE / KEY_EXCHANGE / KEY_CONFIRM / KEY_CONFIRM_ACK / DATA /
  FILE_START / FILE_CHUNK / FILE_END / ERROR / CLOSE`；
* 安全流程：`Encrypt-then-MAC`——先对明文做 AES-128-CTR 得到密文，
  再对 `Type || SessionId || Sequence || Nonce || 密文长度 || 密文` 计算 CMAC；
* 防重放：接收方维护 `last_received_sequence`，`Sequence <= last` 的数据包直接拒绝；
* `Nonce` 在同一个会话密钥下**绝不能重复**，否则 CTR 模式会被破解。

这些字段在本阶段**不实现**，`Frame` 当前只承载 `payload`，
所以网络层不需要为此改动。
