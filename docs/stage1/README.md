# 第一阶段文档存档（纯 TCP 网络层）

本目录保存的是项目**第一阶段**（只做 TCP 连接与 Frame 分帧，还没有任何安全机制）
的 6 份文档原样存档：

| 文件 | 当时的内容 |
| --- | --- |
| `requirements.md` | 课程要求 vs 第一阶段范围的对照（当时大部分要求标为"未实现"） |
| `architecture.md` | 只有 Frame / Network / Alice / Bob 的分层 |
| `protocol.md` | 只有 `Frame = length(4) + payload` 的线上格式 |
| `interfaces.md` | `Network` / `Frame` 的接口说明 |
| `development.md` | 编译、运行、测试与"后续如何接入 AES/CMAC" |
| `test_report.md` | 27 个用例（Frame 12 / Network 10 / 集成 5）的实测结果 |

## 为什么保留

1. 这一层的代码与测试**仍在项目中继续使用**（`include/network`、`src/network`、
   `tests/unit/test_frame.cpp`、`tests/unit/test_network.cpp`、
   `tests/integration/test_tcp_roundtrip.cpp`），需要它们的设计记录；
2. 它是"先做扎实网络层、再加安全层"这一路线的证据，也是第二部分的**回归基线**
   （每次改动都要保证这 27 个用例继续通过）。

## 注意

这些文档描述的是**当时**的状态，其中标为"未实现"的要求
（会话密钥分发、AES、CMAC、安全协议、性能对比等）**现在已经全部完成**。
每份文档开头都加了历史提示，最新状态请看：

* 项目进展与决策记录：项目根目录的 `Part2_transfer.md`
* 当前测试结果：[`../test_report.md`](../test_report.md)
* 性能对比：[`../performance.md`](../performance.md)
* 局域网双机测试：[`../lan_test.md`](../lan_test.md)
* 课程要求对照：[`../requirements.md`](../requirements.md)
