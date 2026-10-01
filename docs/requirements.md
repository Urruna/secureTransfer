# 需求清单（课程要求 vs 实现状态）

本文档对照课程原始需求文档 `docs/project_q1.md`（原位于 `projects/project_q1.md`，
已随项目一起移入本目录），明确区分：

1. **课程明确要求**；
2. **设计阶段自行确定的技术方案**；
3. **尚未实现的功能**。

## 一、课程要求与实现状态

| 编号 | 课程要求 | 分值 | 状态 | 证据 |
| --- | --- | --- | --- | --- |
| 1 | Alice 与 Bob 之间安全地分发会话密钥 `K_session = 000102...0F` | 10 | **已实现** | `KEY_EXCHANGE` 用 `K_master` 做 CTR 包裹后传输，`KEY_CONFIRM` 双方确认；`docs/protocol.md` §4–§5 |
| 2 | 用该密钥和 AES 实现加密数据传输，不少于 4 条测试消息 | 10 | **已实现** | AES-128-CTR（第一部分成果）；4 条消息端到端验证：`docs/test_report.md` §4.1 |
| 3 | 消息完整性保护与校验，用标准数据做算法正确性测试 | 10 | **已实现** | CMAC（RFC 4493）已交付并集成；4 条标准向量通过：`tests/unit/test_aes_cmac.cpp`；篡改必拒：`test_tamper` |
| 4 | 必须自己写代码实现，不能用库 | 10 | **满足** | 未链接任何密码学库；AES 为第一部分自写，协议层全部自写 |
| 5 | 与库/他人实现做性能对比 | 10 | **已实现** | AES-CTR 与 CMAC 均与 OpenSSL 对比，覆盖 1 KB / 64 KB / 1 MB / 10 MB / 100 MB，并做“禁用 AES-NI 的纯软件对比”与正确性交叉验证：**`docs/performance.md`** |
| 6 | 信息必须经过网络传输 | 10 | **已实现** | 真实 TCP；两台独立主机（各自独立 IP 栈）经以太网链路的完整测试与抓包证据：**`docs/lan_test.md`** |
| 7 | 完整安全协议：加密、认证、密钥交换、访问控制，对用户透明 | 10 | **已实现** | 加密 / 认证 / 密钥交换 / 防重放已完成；访问控制（身份→角色→权限、服务端权威判定、审计日志、越权拒绝不中断会话）见 **`docs/access_control.md`** |
| 8 | 良好的人机交互界面、需求分析、应用设计 | 10 | **已实现** | Qt5 图形界面（连接/身份、会话状态、短消息、文件与图像传输、访问控制查询、攻击演示、运行日志），界面不实现任何密码学逻辑：**`docs/ui.md`** + `docs/screenshots/` |
| 9 | 支持短消息、文件、图像等多种信息 | 10 | **已实现** | 短消息 `DATA`；文件 `FILE_START/CHUNK/END`（64 KiB 分块）；小图像单包 `IMAGE`、大图像自动分块；接收端校验总字节数与整文件 CRC32，实测逐字节一致：**`docs/file_transfer.md`** |
| 10 | 其他扩充功能 | 10 | 部分达成 | 已有：协议统计、密钥指纹、`--mock`/`--placeholder` 联调、Eve 攻击测试、性能对比工具、局域网双机脚本、实验数据与一键验证脚本 |

## 二、课程流程要求的落实情况

| 要求 | 落实方式 |
| --- | --- |
| 先用 TCP 建立连接，再做认证与会话建立 | `SecureSession::connectToServer()` / `acceptOneClient()` 内部按顺序完成 |
| Challenge-Response 身份认证，Nonce 防重放 | `NonceA` / `NonceB` 均进入转录串；Bob 每次连接生成新 `NonceB` |
| MAC/CMAC 做完整性保护，采用 Encrypt-then-MAC | `docs/protocol.md` §6.2；MAC 覆盖头部 + 密文 |
| 统一 Packet 格式（Magic/Version/Type/SessionID/Sequence/Nonce/PayloadLen/Ciphertext/CMAC） | 完全一致（另加 1 字节 `Direction` 防反射） |
| Sequence + Session ID 防重放 | `ReplayGuard` + SessionId 校验 |
| Eve 攻击演示（窃听 / 篡改 / 身份伪造 / 重放） | 篡改 `test_tamper`、伪造 `test_forge`、重放 `test_replay`、窃听 `scripts/capture_eve.sh` |
| 访问控制（Authentication 决定"你是谁"，Access Control 决定"你能做什么"） | 本部分负责"你是谁"（认证后产出身份）；"能做什么"由第三部分实现 |

## 三、自行确定的技术方案（非课程规定）

以下内容不是课程明文规定的，而是本实现的设计选择，均已在 `docs/protocol.md` 与
`docs/architecture.md` 中给出理由：

1. 数据包放在 `Frame::payload` 内部（网络层零改动）；
2. 头部增加 1 字节 `Direction`；
3. 握手 MAC 输入采用显式转录串：TLV 编码 + 域分离前缀 + 方向标签；
4. 由 `K_session` 派生 `K_enc` / `K_mac` 两把子密钥（密钥用途分离）；
5. Nonce 结构为 `随机前缀(8) ‖ 0^4 ‖ 消息计数(4)`；
6. `ReplayGuard` 采用"只判断 / 通过后提交"两阶段；
7. 服务端 `port = 0` 时通过 `onListening` 回调上报真实端口（测试与演示用）；
8. 握手失败 / MAC 失败 / 重放时关闭会话，并保留统计计数供报告引用。

## 四、尚未实现的功能

* 多客户端并发、密钥轮换（rekey）、前向保密；
* 每个身份独立凭证（当前实验环境下所有身份共用一把 K_master，见 `docs/access_control.md` §8）；
* 与"两台真实物理机"的对照数据（命名空间模拟两机已完成，见 `docs/lan_test.md`；
  真机双机的命令已就绪，若课程要求必须是两台物理设备，可直接按该文档 §4 执行）。
