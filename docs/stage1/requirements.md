# 需求清单（课程要求 vs 本阶段范围）

> ⚠ **这是第一阶段（纯 TCP 网络层）的历史文档存档，不代表当前状态。**
> 表中标为"未实现"的要求 1、2、3、5、7、9 等**现已全部完成**；
> 最新的逐条对照请看 [`../requirements.md`](../requirements.md)。

本文档根据课程需求文件 `project_q1.md` 整理，
并明确区分以下三类内容，避免把"自行设计的内容"误认为课程规定内容：

1. **课程明确要求**：`project_q1.md` 中写明的内容；
2. **设计阶段自行确定的技术方案**：为满足课程要求而做的实现选择；
3. **当前阶段暂未实现的功能**：本阶段（网络通信模块）有意不做，留给后续阶段。

## 一、课程明确要求（来自 project_q1.md）

| 编号 | 课程要求 | 对应分值 | 本阶段状态 |
| --- | --- | --- | --- |
| 1 | 在 Alice 与 Bob 之间安全地分发会话密钥 `K_session = 000102030405060708090A0B0C0D0E0F` | 10 分 | 未实现（后续：安全协议 + AES） |
| 2 | 使用该密钥和 **AES** 算法实现 Alice/Bob 之间的加密数据传输，不少于 4 条测试消息 | 10 分 | 未实现（后续：AES 模块 + 应用层） |
| 3 | 消息完整性保护与校验，使用标准数据做算法正确性测试 | 10 分 | 未实现（后续：CMAC 模块） |
| 4 | 可以使用国际通用算法或国密算法，但必须**自己写代码**，不能直接用库 | 10 分 | 本阶段不涉及密码算法；网络层全部自行编写，未使用第三方库 |
| 5 | 与库文件/他人实现做全面的**性能对比** | 10 分 | 未实现（后续：benchmark 模块） |
| 6 | 信息交互必须**经过网络传输**（可本机收发） | 10 分 | **本阶段已完成**（TCP loopback，见 `tests/integration/`） |
| 7 | 设计并实现一套安全协议，包含加密、认证、密钥交换、访问控制 | 10 分 | 未实现（后续：协议层 + 安全层） |
| 8 | 良好的人机交互界面、需求分析、应用设计（加分项） | 10 分 | 未实现（后续：Qt GUI，本阶段不做） |
| 9 | 支持短消息、文件、图像等多种信息安全传输 | 10 分 | 未实现（后续：应用层；本阶段 Frame 已支持任意二进制数据） |
| 10 | 其他扩充功能（加分项） | 10 分 | 待定 |

课程还要求（不计分但属于要求的一部分）：

* 使用 **TCP 建立连接**，并在连接后先做身份认证与会话建立，再传输业务数据；
* 使用 **Challenge-Response** 做身份认证，使用 `Nonce` 防止重放；
* 使用 `MAC/CMAC` 做完整性保护，采用 **Encrypt-then-MAC**；
* 设计统一的 **Packet 格式**（Magic / Version / Type / Session ID / Sequence /
  Nonce / Payload Len / Ciphertext / CMAC）；
* 使用 `Sequence Number` + `Session ID` 做**防重放**；
* 提供 **Eve 攻击演示**（窃听、篡改、身份伪造、重放）；
* 提供访问控制（Authentication 决定"你是谁"，Access Control 决定"你能做什么"）。

## 二、本阶段（网络通信模块）范围

本阶段由网络通信模块负责，目标是把**网络这一层的骨架做对**：

| 本阶段要做 | 说明 |
| --- | --- |
| TCP 连接建立 | 服务端 `socket/bind/listen/accept`，客户端 `socket/connect` |
| 消息边界定义 | 统一 Frame：`length + payload` |
| 序列化 | `serialize()` / `deserialize()` |
| 粘包 / 拆包处理 | `writeAll()` / `readExact()`，不假设一次 `send()` 对应一次 `recv()` |
| 长度限制 | 最大 payload 1 MB，超长直接拒绝，避免恶意长度导致内存耗尽 |
| 错误处理 | connect/socket/bind/listen/accept/send/recv 失败、对端关闭、非法长度、帧不完整、超时 |
| 真实通信测试 | Alice 与 Bob 两个独立进程通过 TCP loopback 完成 `Hello Bob` / `Hello Alice` 往返 |
| 自动化测试 | Frame 测试、Network 测试、集成测试，可用 `ctest` 运行 |

## 三、设计阶段自行确定的技术方案（非课程规定）

以下内容**不是** `project_q1.md` 规定的，而是本阶段为了满足课程要求所做的设计选择，
后续如需调整，只需同步修改本文件与 `docs/protocol.md`：

1. `length` 字段固定 **4 字节、大端序（网络字节序）**；
2. 单个 Frame 的 payload 上限固定为 **1 MB**（`Frame::kMaxPayloadSize`）；
3. 服务端 `backlog = 1`，且**同一时刻只服务一个客户端**（演示够用，实现简单）；
4. `Network` 提供 `lastResult()` / `lastError()` 作为诊断接口，方便定位失败原因；
5. 提供 `listen(0)`（由系统分配端口）与 `boundPort()`，让测试程序可以并行运行、
   不会互相抢占端口；
6. 提供 `setReceiveTimeoutMs()` / `setSendTimeoutMs()`，避免程序在异常情况下永久阻塞；
7. 日志分成 `DEBUG/INFO/WARN/ERROR` 四级，默认 `INFO`，可用环境变量 `ST_LOG_LEVEL` 调整；
8. 文件与图像的传输协议（`FILE_START/FILE_CHUNK/FILE_END`）只预留设计，
   本阶段不实现。

## 四、当前阶段暂未实现的功能

* AES-128、AES-CTR；
* CMAC 及其标准向量测试；
* 与 OpenSSL 等库的性能对比 benchmark；
* 长期密钥 `K_master`、会话密钥 `K_session` 的分发流程；
* 身份认证（HELLO / HELLO_ACK / AUTH_REQUEST / AUTH_RESPONSE / AUTH_SUCCESS）；
* 会话状态机（DISCONNECTED → CONNECTED → AUTHENTICATING → ... → ESTABLISHED）；
* Session ID / Sequence Number / Nonce / Replay Protection；
* 访问控制（Role / Permission）；
* 文件传输、图像传输；
* Qt GUI；
* Eve 窃听、篡改、身份伪造、重放攻击演示程序。

这些功能的**目录位置、接口形态与调用关系**已在 `docs/architecture.md` 中预留，
后续组员可以在不推翻网络层的前提下继续开发。
