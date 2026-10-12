# 第一阶段存档：纯 TCP 网络层（已完成，代码仍在用）

> 第一阶段只做"网络这一层的骨架"：TCP 连接 + 统一分帧，**不含任何安全机制**。
> 当时它自己有一整套文档（6 份、约 1000 行），后续阶段把它们全部覆盖了；
> 2026-10-12 整理时**合并成本文件**，只保留"设计决策 + 与后续阶段的关系"这类仍有价值的内容，
> 细节一律以当前文档为准。
>
> 当前状态请看：[`requirements.md`](requirements.md)（课程要求完成情况）、
> [`protocol.md`](protocol.md)（协议）、[`architecture.md`](architecture.md)（分层）、
> [`test_report.md`](test_report.md)（测试）。

## 1. 这一层交付了什么

| 交付物 | 说明 | 现在在哪 |
| --- | --- | --- |
| `Frame` | 线上最小单元：`length(4 字节大端) + payload`，payload 上限 **1 MB** | `include/network/frame.h` |
| `Network` | TCP 封装：`connect / listen / accept / sendFrame / receiveFrame / close`，内部处理粘包拆包与超时 | `include/network/network.h` |
| `alice` / `bob` | 两个独立进程通过真实 TCP 完成 `Hello Bob` / `Hello Alice` 往返 | `apps/alice/`、`apps/bob/`（现已扩展为安全会话） |
| 27 个用例 | Frame 12 / Network 10 / 集成 5 | `tests/unit/test_frame.cpp`、`tests/unit/test_network.cpp`、`tests/integration/test_tcp_roundtrip.cpp` |

**这 27 个用例至今仍是回归基线**：任何一层改动都要保证它们继续通过。

## 2. 当时定下的关键设计决策（都还在用）

1. `length` 固定 **4 字节、大端序**——先读长度再读 payload，是解决粘包/拆包的根；
2. 单个 Frame 的 payload 上限 **1 MB**：先检查长度再分配内存，防"恶意长度吃内存"；
3. `sendFrame`/`receiveFrame` 内部处理 **partial send / partial recv**，
   调用方永远只面对"一个完整 Frame"；
4. 服务端 `backlog = 8`、同一时刻只服务一个客户端（演示够用、实现简单）；
5. `listen(0)` + `boundPort()`：端口由系统分配，测试程序可以并行、不会互相抢占；
6. `setReceiveTimeoutMs()` / `setSendTimeoutMs()`：异常情况下不会永久阻塞；
7. 日志分 `DEBUG/INFO/WARN/ERROR` 四级，默认 `INFO`，`ST_LOG_LEVEL` 可调；
8. `lastResult()` / `lastError()` 作为诊断接口，失败原因可查。

## 3. 与后续阶段的关系（最重要的一条）

**网络层在第二阶段之后一字未改。** 安全协议选的路线是：
把 `Packet`（Magic/Version/Type/SessionId/Sequence/Nonce/PayloadLen/Body/CMAC）
**整个放进 `Frame::payload` 里**，而不是去扩 Frame 的字段。

好处是：

* 网络层与协议层彻底解耦（网络层不知道有 Packet，协议层不关心 TCP）；
* 第一阶段的 27 个用例原样继续有效，成为"没被改坏"的硬证据；
* 目录预留（`crypto/` `protocol/` `security/` `application/`）在第二阶段一次填满，没有推翻重来。

## 4. 当时还没做的（现在都已完成）

第一阶段结束时，下面这些都还是"未实现"，全部由后续阶段补齐——
留在这里是为了说明**这个项目是分层推进的，不是一次性铺开**：

AES-128 / AES-CTR、CMAC 与标准向量测试、性能对比 benchmark、
`K_master` / `K_session` 的认证与分发、会话状态机、SessionId / Sequence / Nonce / 防重放、
访问控制（角色 / 权限）、文件与图像传输、Qt 图形界面、
Eve 攻击演示（窃听 / 篡改 / 伪造 / 重放 / 中间人）。

逐条完成情况见 [`requirements.md`](requirements.md)。
