# 课程要求完成情况（唯一权威对照表）

> 对照课程原始需求 [`project_q1.md`](project_q1.md)。
>
> **本文件是"完成情况"的唯一出处**：README、项目全景、Part2 只做摘要并链接到这里。
> （2026-10 之前同一个表格在 README / 全景 / 本文件里各有一份，三份逐渐对不上，已合并。）
>
> 最后核对：**2026-10-12**｜`ctest` **18/18**（Windows MinGW-w64 + Ubuntu 20.04 双平台，0 编译告警）

## 1. 十条评分点

| # | 课程要求 | 分值 | 状态 | 实现要点 | 代码位置 | 证据 / 测试 |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 安全分发会话密钥 `K_session = 000102…0F` | 10 | ✅ | `KEY_EXCHANGE` 用 `K_master` 做 CTR 包裹后**真的传输**，再用 `KEY_CONFIRM(_ACK)` 双向确认双方持有同一把 | `src/security/session.cpp`（握手 ④⑤⑥⑦）、`include/security/transcript.h` | [`protocol.md`](protocol.md) §4–§5；`test_secure_roundtrip` |
| 2 | 用该密钥 + AES 加密数据传输，≥ 4 条测试消息 | 10 | ✅ | AES-128-CTR（第一部分自实现）；4 条课程消息（10/39/75/85 字节，含中文 UTF-8 与二进制）端到端验证 | `src/crypto/aes_crypto_provider.cpp`、`apps/alice` | [`test_report.md`](test_report.md) §4.1；`experiment_data/text_messages.txt` |
| 3 | 完整性保护 + 用标准数据做算法正确性测试 | 10 | ✅ | CMAC（RFC 4493，Encrypt-then-MAC）；FIPS-197 / NIST SP 800-38A / RFC 4493 标准向量；篡改一个字节必被拒 | `reference/part1-aes-cmac/`、`tests/unit/test_aes_cmac.cpp` | [`protocol.md`](protocol.md) §6；`test_tamper`、`test_reject_gate` |
| 4 | 必须自己写代码实现，不能用库 | 10 | ✅ | 系统本体（`alice`/`bob`/`st_ui`/`st_*`）**零密码库依赖**；唯一例外是性能对比工具 | `CMakeLists.txt`（只有 `crypto_benchmark*` 链接库） | [`performance.md`](performance.md) §9.1；`tests/unit/test_aes_cmac.cpp` |
| 5 | 与库 / 他人实现做性能对比 | 10 | ✅ | AES-CTR 与 CMAC × 1 KB~100 MB，对比 **OpenSSL / Mbed TLS / Botan**，并额外做"禁用硬件加速的纯软件对照"与四方正确性交叉验证 | `tools/crypto_benchmark.cpp`、`tools/bench_backend_*.cpp` | [`performance.md`](performance.md) §2–§5、§9；`experiment_data/benchmarks/` |
| 6 | 信息必须经过网络传输 | 10 | ✅ | 真实 TCP；Linux netns 两台独立主机 + **Windows ↔ Ubuntu 跨系统双机**，抓包含 SYN/SYN-ACK 与明文零命中 | `src/network/`、`scripts/lan_test.sh` | [`lan_test.md`](lan_test.md)、[`eavesdrop.md`](eavesdrop.md) |
| 7 | 完整安全协议（加密 / 认证 / 密钥交换 / 访问控制），对用户透明 | 10 | ✅ | 七步握手（双向认证 + 密钥分发）、AES-CTR、CMAC、防重放；访问控制为"身份→角色→权限"，服务端权威判定 + 审计日志，越权只拒操作不中断会话 | `src/security/session.cpp`、`src/security/access_control.cpp`、`configs/access_policy.conf` | [`protocol.md`](protocol.md)、[`access_control.md`](access_control.md)；`test_access_control*` |
| 8 | 良好的人机交互界面 + 需求分析 + 应用设计 | 10 | ✅ | Qt5 三栏界面：握手 7 步进度、短消息气泡、文件/图像传输、访问控制查询、**Eve 攻击面板**、统计数字块、分级日志；界面不实现任何密码学逻辑 | `apps/ui/` | [`ui.md`](ui.md)、[`screenshots/`](screenshots/README.md)；`dist/` 与 GitHub Release |
| 9 | 支持短消息 / 文件 / 图像等多种信息 | 10 | ✅ | 短消息 `DATA`；文件 `FILE_START/CHUNK/END`（64 KiB 分块）；小图像单包 `IMAGE`、大图像自动分块；接收端核对总字节数 + 整文件 CRC32 | `src/application/file_transfer.cpp` | [`file_transfer.md`](file_transfer.md)；`test_file_transfer` |
| 10 | 其他扩充功能 | 10 | 🟡 部分 | 已有：**真实链路中间人（MITM）攻击工具**、攻击拦截关卡（`RejectGate`）+ 攻击回执、协议统计、CI 自动测试与自动出包、Windows 免环境发布包、Wireshark 抓包脚本、实验数据与一键验证脚本 | `apps/eve/`、`src/attack/`、`.github/workflows/`、`scripts/` | [`eve_mitm.md`](eve_mitm.md)、[`release_notes.md`](release_notes.md) |

## 2. 课程流程要求

| 要求 | 落实方式 |
| --- | --- |
| 先用 TCP 建连，再做认证与会话建立 | `SecureSession::connectToServer()` / `acceptOneClient()` 内部按序完成，TCP 成功后才进入握手 |
| Challenge-Response 认证，Nonce 防重放 | `NonceA` / `NonceB` 均进入转录串；Bob 每次连接生成新的 `NonceB` |
| MAC/CMAC 做完整性保护，Encrypt-then-MAC | 先 `aesCtrEncrypt`，再对「头部 + 密文」算 CMAC（[`protocol.md`](protocol.md) §6.2） |
| 统一 Packet 格式（Magic/Version/Type/SessionID/Sequence/Nonce/PayloadLen/Ciphertext/CMAC） | 完全一致，**另加 1 字节 `Direction`** 防反射 |
| Sequence + Session ID 防重放 | `ReplayGuard` 两阶段（只判断 / 通过后提交）+ SessionId 绑定校验 |
| Eve 攻击演示（窃听 / 篡改 / 身份伪造 / 重放） | 窃听 [`eavesdrop.md`](eavesdrop.md)、篡改 `test_tamper`、伪造 `test_forge`、重放 `test_replay`；**中间人** [`eve_mitm.md`](eve_mitm.md) + `test_mitm` |
| 访问控制（认证决定"你是谁"，访问控制决定"你能做什么"） | 认证后产出身份 → 角色 → 权限；服务端权威判定 + 审计日志 |

## 3. 自行确定的技术方案（非课程规定）

以下不是课程明文要求，而是实现时的设计选择，理由见 [`protocol.md`](protocol.md) 与 [`architecture.md`](architecture.md)：

1. 数据包放在 `Frame::payload` 内部（网络层零改动）；
2. 头部增加 1 字节 `Direction`；
3. 握手 MAC 输入采用显式转录串：TLV 编码 + 域分离前缀 + 方向标签；
4. 由 `K_session` 派生 `K_enc` / `K_mac` 两把子密钥（用途分离）；
5. Nonce 结构为 `随机前缀(8) ‖ 0^4 ‖ 消息计数(4)`；
6. `ReplayGuard` 采用两阶段提交；
7. 服务端 `port = 0` 时通过 `onListening` 回调上报真实端口（测试与演示用）；
8. 拒绝即终止会话（不做"只拒该包、继续跑"），并用 `RejectGate` 记录倒在哪一关；
9. 攻击演示分两档：**端点视角**（本端构造攻击包，证明"收包方会校验"）与**链路中间人**（独立进程 `eve.exe`，证明"第三方攻不进来"）。

## 4. 尚未实现 / 明确限制（主动写明，答辩时不会被问住）

| 项 | 现状 | 原因 / 说明 |
| --- | --- | --- |
| 前向保密（PFS） | ❌ 不支持 | 要求 1 规定会话密钥是**固定值**，结构上做不到；改点在 `makeCourseSessionKey()` |
| 抗 DoS（握手入口） | ❌ 未设计 | 未认证的 HELLO 也会被处理；但数据通道防住了（两阶段提交 + 握手总时限） |
| **抗丢弃 / 延迟（可用性攻击）** | ❌ 无法防御 | 中间人可用性攻击密码学防不住，只能靠超时与重连恢复：见 [`eve_mitm.md`](eve_mitm.md) §5 |
| 多客户端并发 / 密钥轮换 | ❌ | 单会话、单线程模型；服务端常驻但一次只服务一个连接 |
| 每身份独立凭证 | ❌ | 实验环境下所有身份共用一把 `K_master`（[`access_control.md`](access_control.md) §8） |
| 真机双机（两台物理主机） | 🟡 命令就绪 | netns 双机已完成；Windows↔Ubuntu 属"宿主↔虚拟机"，真机步骤见 [`lan_test.md`](lan_test.md) §4 |
