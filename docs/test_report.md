# 测试报告（第二部分：安全通信协议与网络）

首次执行：2026-09-26（Linux 虚拟机 `Ubuntu6.21`）
**最后更新：2026-10-12** —— 现已在 **Windows（MSYS2 MinGW-w64）与 Ubuntu 20.04 两端**
各跑一遍，测试程序从 14 个增加到 **18 个**（新增 `test_reject_gate`、`test_mitm` 等）。
下表保留首次执行的环境，Windows 侧环境见 [`development.md`](development.md) §1。

| 项目 | 实测值 |
| --- | --- |
| 操作系统 | Ubuntu 20.04.6 LTS (focal)，内核 5.15.0-140-generic，x86_64 |
| 编译器 | g++ (Ubuntu 9.4.0-1ubuntu1~20.04.3) 9.4.0 |
| 构建工具 | CMake 3.16.3 + GNU Make 4.2.1 |
| 虚拟机配置 | 2 vCPU / 4 GB |
| 项目路径 | `/home/securityTransfer` |
| 构建方式 | `cmake .. && cmake --build . -j4` |
| 依赖 | 无第三方库（OpenSSL 仅用于独立交叉验证，未参与实现） |

---

## 1. 结论摘要

* 编译：`-Wall -Wextra` 下**无警告、无错误**；
* `ctest`：**18 个测试程序全部通过**，Windows 与 Ubuntu 两端一致（0 编译告警）；
* 端到端：Alice 与 Bob 通过真实 TCP 完成「握手 → 4 条消息 → 双向确认 → CLOSE」，双方退出码均为 0；
* 攻击测试：**篡改、身份伪造、数据包重放、窃听、链路中间人**五项全部按预期被阻止 / 无泄漏；
* 密码算法：**AES-128 与 CMAC 均为第一部分自实现，且已用标准向量验证**
  （FIPS-197、NIST SP 800-38A、RFC 4493），完整性保护具备真实密码学强度。

## 2. 如何复现

```bash
cd /home/securityTransfer
mkdir -p build && cd build
cmake .. && cmake --build . -j4
ctest --output-on-failure
```

也可使用一键脚本：`bash scripts/verify_in_vm.sh`（编译 + 测试 + 演示 + 攻击测试）。

## 3. ctest 实测结果

```text
Test project .../build-win            （Ubuntu 侧同样 18/18）
   1: test_frame             6: test_transcript      11: test_reject_gate      16: test_forge
   2: test_network           7: test_replay_guard    12: test_secure_roundtrip 17: test_replay
   3: test_tcp_roundtrip     8: test_session_state   13: test_file_transfer    18: test_mitm
   4: test_aes_cmac          9: test_transfer_meta   14: test_access_control_e2e
   5: test_packet           10: test_access_control  15: test_tamper

100% tests passed, 0 tests failed out of 18
```

### 3.1 各测试程序覆盖的内容

| 测试程序 | 归属 | 覆盖内容 |
| --- | --- | --- |
| `test_frame`（12 例） | 第一阶段回归 | Frame 序列化、1 MB 边界、非法长度、粘包拆分 |
| `test_network`（10 例） | 第一阶段回归 | 连接失败、端口占用、超时、对端断开、非法参数 |
| `test_tcp_roundtrip`（5 例） | 第一阶段回归 | 多消息往返、200 帧粘包、1 MB 大帧、多客户端 |
| `test_aes_cmac`（9 例） | 第一部分回归 | FIPS-197 单分组向量、NIST SP 800-38A CTR 向量、RFC 4493 的 4 条 CMAC 向量、CTR 往返（含中文/二进制/空串）、CMAC 篡改检测、1 MiB 数据、`CmacEngine` 适配、默认使用真实 CMAC |
| `test_packet`（8 例） | 第二部分 | 编解码往返、空 Body、最大 Body、字段偏移与大端序、MAC 输入范围、全部非法输入 |
| `test_transcript`（8 例） | 第二部分 | 确定性、域分离、方向分离、TLV 消除歧义、Nonce 绑定、包裹内容绑定 |
| `test_replay_guard`（7 例） | 第二部分 | 严格递增、重复拒绝、回退拒绝、跳号、`wouldAccept` 不推进水位 |
| `test_session_state`（9 例） | 第二部分 | 状态机边界、未认证不可收发、无 K_master 拒绝、密钥配置解析 |
| `test_reject_gate`（4 例） | 第二部分 | 篡改 ⇒ `kMac`、重放 ⇒ `kReplay`、改 SessionId ⇒ `kSessionId`、连续两次拒绝不读陈旧值（"倒在哪一关"的精确记录） |
| `test_mitm`（7 例） | 第二部分安全 | **独立进程中间人**：纯中继下会话照常建立；篡改 ⇒ ⑦、重放 ⇒ ⑥、丢弃 ⇒ 只能超时（可用性防不住）；"按类型 / 最近一条"选包；**序号过期必须立刻报错** |
| `test_transfer_meta`（9 例） | 第三部分 | CRC32 已知值与分块累积、元数据编解码、非法文件名（目录穿越）拒绝、单包模式、接收器的正常 / 篡改 / 单包 / 非传输消息四种场景 |
| `test_file_transfer`（1 例，含 3 条传输路径） | 第三部分 | 真实 TCP + 握手 + 文本 + 300 KB 文件（分块）+ 40 KB 小图像（单包）+ 2 MB 大图像（分块），逐字节比对与 CRC32 一致 |
| `test_access_control`（8 例） | 第三部分 | 策略解析、判定矩阵（管理员/普通用户/访客/未登记身份）、默认拒绝、非法策略拒绝、消息类型→操作映射、审计记录与写文件 |
| `test_access_control_e2e`（1 例） | 第三部分 | 端到端：管理员发文件成功落盘；访客发文件被拒绝且**不落盘**、会话继续可用、审计里同时出现 ALLOW 与 DENY |
| `test_secure_roundtrip`（2 例） | 第二部分 | 完整握手 + 4 条消息双向传输、同会话内 Nonce/密文不重复 |
| `test_tamper` | 第二部分安全 | 篡改密文 ⇒ 必须被拒绝 |
| `test_forge`（2 例） | 第二部分安全 | 错误 `K_master` 的伪造者 ⇒ 双方都必须拒绝 |
| `test_replay`（2 例） | 第二部分安全 | 重放合法数据包 ⇒ 必须被拒绝；会话新鲜性 |

## 4. 端到端演示实测输出（关键片段）

命令：`./bob 9100 --quiet` 与 `./alice 127.0.0.1 9100 --quiet`

```text
==================== Bob (服务端) ====================
身份          : bob（期望对端: alice）
K_master 指纹 : 8409fd42b2df5cb3（仅指纹，不打印密钥内容）
密码算法      : AesCryptoProvider(AES-128-CTR)
完整性算法    : CMAC(AES-128, RFC 4493)（密码学强度：达标）

安全会话已建立。SessionId = 369e3fe1d7654dcf
NonceA = 7936f5cffe9db66578cddaa6e74003b8
NonceB = da52ade126bca02ebe76b5cddeaa782b
---------- 第 1 条消息 ----------
  Type        : DATA
  Sequence    : 1
  Nonce       : b93ffb1b6074a1950000000000000001
  密文(hex)   : 6102ef06b653477e0f19
  CMAC        : 2c274a5402ec40bc4f836c5423018c08
  MAC 验证    : 通过（数据未被篡改）
  解密明文    : Hello Bob!
  明文长度    : 10 字节
...
收到对端 CLOSE 消息，会话正常结束。
共接收 4 条加密消息。
统计: sent=7 recv=9 bytes=564/765 reject(format/replay/mac/state)=0/0/0/0 handshake(ok/fail)=1/0
```

Alice 侧：

```text
---------- 测试1 短文本 ----------
  发送明文    : Hello Bob!
  明文长度    : 10 字节
  密文(hex)   : 6102ef06b653477e0f19
  CMAC        : 2c274a5402ec40bc4f836c5423018c08
  Sequence    : 1
  Nonce       : b93ffb1b6074a1950000000000000001
  对端回复    : Bob ACK #1 (收到 10 字节)
  回复完整性  : MAC 验证通过
...
统计: sent=9 recv=7 bytes=765/564 reject(format/replay/mac/state)=0/0/0/0 handshake(ok/fail)=1/0
=== 4 条测试消息全部安全传输成功 ===
```

### 4.0 CMAC 性能实测（第一部分自实现）

`./cmac_benchmark 5`（每档重复 5 次取平均；测试数据为重复字节，密钥为全零测试值）：

| 数据大小 | 平均耗时 | 吞吐率 |
| --- | --- | --- |
| 1 KB | 0.010 ms | 95.4 MB/s |
| 64 KB | 0.539 ms | 115.9 MB/s |
| 1 MB | 8.725 ms | 114.6 MB/s |
| 10 MB | 88.351 ms | 113.2 MB/s |

这是课程要求 5「与库实现做性能对比」中**自实现侧**的数据；
库实现（OpenSSL）侧的对照命令见 `docs/development.md` §8。

可以从 Nonce 直接看出 §6.1 的设计：
`91ec56997296e271 | 00000000 | 00000001` = 随机会话前缀 + 计数值隔离区 + 消息序号，
4 条消息的 Nonce 只有最后 4 字节变化，区间互不重叠 ⇒ 密钥流不会复用。

### 4.1 4 条测试消息（课程要求"不少于 4 条"）

| # | 明文 | 长度 | 结果 |
| --- | --- | --- | --- |
| 1 | `Hello Bob!` | 10 B | 解密一致，MAC 通过 |
| 2 | `A secure message between Alice and Bob.` | 39 B | 解密一致，MAC 通过 |
| 3 | `Transfer #1024: Alice->Bob, amount=500.00 USD; status=OK! (check: 9f8e7d6c)` | 75 B | 解密一致，MAC 通过 |
| 4 | `你好，Bob，这是一次安全通信测试。`（UTF-8）+ 37 字节二进制 | 85 B | 逐字节一致，MAC 通过 |

第 4 条同时覆盖了中文多字节与非文本二进制（模拟文件分块），
证明协议对任意二进制数据都成立（统一使用 `uint8_t` / `Bytes`，不用 `char*`）。

## 5. 安全测试实测结果

### 5.1 篡改攻击（`test_tamper`）

做法：握手成功后，把合法数据包的**第 1 个密文字节翻转**，并把序号 +1
（序号必须变化，否则会先被防重放逻辑拦住，测不到完整性校验），再发给 Bob。

```text
  [PASS] tamper: 修改密文字节后必须被拒绝
         server.stats.rejectedMac == 1, rejectedReplay == 0
         server.error = "CMAC verification failed: 数据包完整性校验未通过，已拒绝该消息"
         上层只收到 1 条消息（被篡改的那条没有交付上层）
```

### 5.2 身份伪造（`test_forge`）

做法：攻击者使用错误的 `K_master` 连接 Bob。

```text
  [PASS] forge: 使用错误 K_master 的客户端无法通过认证
  [PASS] forge: 服务端使用不同 K_master 时客户端也应拒绝
```

实际日志：

```text
[ERROR] [Handshake] Authentication Failed：对端未能通过 K_master 认证
[ERROR] [Network] recv() 返回 0：对端关闭了连接 (已接收 0/4 字节)
```

两条用例分别验证了：伪装的客户端过不了 Bob 的认证；Bob 端密钥不对时 Alice 也会拒绝。
（双向认证，只保护一侧是不够的。）

### 5.3 重放攻击（`test_replay`）

做法：Eve 截获一个合法数据包（序列号 1），在之后再原样发送一次。

```text
  [PASS] replay: 重放同一个数据包必须被拒绝
         server.stats.rejectedReplay == 1, rejectedMac == 0
         server.error = "Replay Attack Detected: 序号 1 不大于已接收的最大序号 1"
         上层只收到 1 条消息（重放的那条没有交付上层）
```

注意 `rejectedMac == 0` 说明它是在**防重放阶段**被拦住的，符合 §6.2 的处理顺序。

### 5.4 窃听攻击（`scripts/capture_eve.sh`，tcpdump）

做法：在 loopback 上抓 `port 9101` 的包，然后跑一次 Alice/Bob，检索明文关键字。

```text
capture_size      = 3501 字节
plaintext_hits    = 0        ← "Hello Bob" 在抓包结果中出现 0 次
alice_log_hits    = 1        ← Alice 终端确实发送过这条消息
bob_log_hits      = 1        ← Bob 终端确实收到并解密了这条消息

抓包中出现的 ASCII 片段（前 40 行）：
alice / C-]X / wf[6 / dPb$ / C-]X / df2X / kf8? ...
```

结论：Eve 能看到 TCP 数据包、密文、Nonce、Sequence、MacTag 等公开字段，
但**看不到任何明文**，也看不到 `K_master` 与 `K_session`。

### 5.5 反射攻击（设计层面的防御）

`Direction` 字节与握手转录串中的 `L("C2S")` / `L("S2C")` 方向标签，
以及 `tests/unit/test_transcript.cpp` 中的
`transcript: C2S 与 S2C 不同（防反射）` 用例，共同保证：
把对方发来的合法包原样返回，会被方向校验或 MAC 校验拒绝。

## 6. 尚未覆盖 / 未验证的部分

* **长时间稳定性 / 高并发**：当前设计是单会话、单线程，未做压力测试；
* **真机双机（两台物理主机）**：已完成的是 Linux netns 两个独立 IP 栈、
  以及 Windows ↔ Ubuntu 跨系统；真机命令见 [`lan_test.md`](lan_test.md) §4；
* **可用性攻击**：丢弃 / 延迟**无法防御**（中继实测只能观察到超时），
  见 [`eve_mitm.md`](eve_mitm.md) §5 —— 这是设计限制，不是漏测。

## 7. 与第一部分的衔接

第一部分交付的 AES 与 CMAC 已通过 `CmacEngine` 接入本部分的协议栈，
且**算法实现文件没有被修改**：

| 交付物 | 位置 | 验证方式 |
| --- | --- | --- |
| AES-128（单分组 + CTR） | `include/crypto/aes.h`、`src/crypto/aes.cpp` | FIPS-197 单分组向量；NIST SP 800-38A F.5.1 CTR 向量；5 条 CTR 往返（含中文、二进制、空串） |
| CMAC（RFC 4493） | `include/crypto/cmac.h`、`src/crypto/cmac.cpp` | RFC 4493 的 4 条标准向量（空消息 / 16B / 40B / 64B）；篡改 1 字节必须验证失败；1 MiB 数据一致性 |
| 性能测试工具 | `tools/cmac_benchmark.cpp` | §4.0 的实测数据 |
| 原始工程存档 | `reference/part1-aes-cmac/` | 原样保留（Windows/VS 工程，不参与构建） |

接入后，协议层的篡改测试（§5.1）从"协议流程正确"升级为**真实的密码学保证**：
修改任何一个密文字节，CMAC 校验必然失败。

## 8. 专项报告

| 主题 | 文档 | 覆盖内容 |
| --- | --- | --- |
| 密码算法性能对比（要求 5） | [`performance.md`](performance.md) | AES-CTR 与 CMAC，自实现 vs **OpenSSL / Mbed TLS / Botan**，1 KB~100 MB；含"禁用硬件加速的纯软件对照"与四方正确性交叉验证 |
| 局域网双机通信（要求 6） | [`lan_test.md`](lan_test.md) | 两个独立 IP 栈经以太网链路的握手与数据传输、ARP 与 TCP 抓包证据；真机双机的复现步骤 |
| 窃听证据 | [`eavesdrop.md`](eavesdrop.md) | Windows + tshark 跨机抓包：75 帧、明文/密钥 **0 命中** |
| **中间人攻击（独立进程）** | [`eve_mitm.md`](eve_mitm.md) | 纯中继下会话照常建立；篡改 ⇒ ⑦、重放 ⇒ ⑥、丢弃 ⇒ 只能超时；攻击者视角的边界 |
| **文件与图像传输（要求 9）** | [`file_transfer.md`](file_transfer.md) | 分块 / 单包两条路径、正文格式、4 个文件的耗时与吞吐、逐字节一致与 sha256 对照 |
| **访问控制（要求 7）** | [`access_control.md`](access_control.md) | 策略配置、判定流程、用户透明性、管理员 vs 访客实测、审计日志样例、局限说明 |
| **图形界面（要求 8）** | [`ui.md`](ui.md) + [`screenshots/`](screenshots/README.md) | 方案选择（Qt5）、三栏布局、线程模型、改版与修复记录、截图、已知限制 |
| **课程要求逐条对照** | [`requirements.md`](requirements.md) | 十条评分点 → 实现要点 / 代码位置 / 证据 / 测试（唯一权威） |
