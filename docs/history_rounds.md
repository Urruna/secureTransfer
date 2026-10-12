# 第二部分研发历程（分轮完整记录）

> 这是原 `Part2_transfer.md` 里 §16–§31 的分轮记录，2026-10-12 整理时**原样搬迁**到这里，
> 让主方案文件读起来轻一些。**正文没有删改**，只修正了两处轮次编号：
> 原 §29/§30/§31 曾被误标成"第八/九/十轮"，实际是第 **14/15/16** 轮
> （第 8–13 轮在 §23–§28）。
>
> 与之配套的文档：
> * 方案本身 → [`../Part2_transfer.md`](../Part2_transfer.md)
> * 课程要求完成情况 → [`requirements.md`](requirements.md)
> * 中间人攻击专项 → [`eve_mitm.md`](eve_mitm.md)；界面专项 → [`ui.md`](ui.md)
>
> 阅读提示：早期轮次里写的"当前进度/剩余工作"是**当时**的状态，请以
> `requirements.md` 为准。

---

# 16. 实施结果与方案修订（2026-09-26）

## 16.1 一句话结果

方案按 M0 → M5 全部落地：**协议层、握手、密钥分发、数据通道、防重放、安全测试、文档**均已完成；
唯一未完成的是**CMAC 算法本身**（属于第一部分，仍在开发中）——
第二部分为此预留了一个 `MacEngine` 接口，并放入一个明确标注"不具备密码学强度"的占位实现，
使得协议流程可以先被完整验证，等 CMAC 到位后**只需替换一处**。

## 16.2 代码落地位置与规模

| 位置 | 说明 |
| --- | --- |
| `projects/securityTransfer/` | 项目主目录（新建），71 个文件、约 9200 行；51 个 C/C++ 源文件 |
| `/home/securityTransfer`（虚拟机） | 实际编译、测试、运行的位置（源码 + `build/`） |
| `projects/securityTransfer/docs/stage1/` | 第一阶段（纯 TCP）6 份文档原样保留 |

目录结构与本方案 §9 的规划一致，实际新增/调整如下：

* 新增 `include/common/constant_time.h`（常数时间比较，独立成文件）；
* 新增 `include/crypto/mac_engine.h`（CMAC 挂载点，方案里没有单独列出）；
* `include/security/` 与 `src/security/` 中：`session.h/.cpp` 同时包含握手状态机与记录层
  （方案里把 `handshake.cpp` 单独列出，实现时合并了，因为二者共享大量状态）；
* `tests/` 下实际的 12 个测试程序见 §16.5。

## 16.3 与原始方案的差异（重要）

| 项目 | 方案 | 实际实现 | 原因 |
| --- | --- | --- | --- |
| **SessionId 长度** | 16 字节（待决策 D1） | **8 字节** | 你确认按课程 `project_q1.md` §5 的建议格式 |
| **Packet 包头** | 49 字节，总开销 65 | **41 字节，总开销 57** | SessionId 由 16 改 8，直接少 8 字节 |
| **单包 Body 上限** | 1048511 | **1048519** | 同上（`1 MiB − 57`） |
| **握手 MAC 放哪里** | 放在 Body 里 | **放在统一的 `MacTag` 字段**，输入是转录串 | 让所有包的"最后 16 字节 = 认证标签"保持一致，收发路径统一 |
| **防重放检查** | 单个 `accept()` | **`wouldAccept()` + `commit()` 两阶段** | 实现时发现：若检查时就推进水位，攻击者伪造一个序号极大的包（MAC 必然失败）就能把水位推高，导致后续合法包全被误判为重放——这是拒绝服务漏洞 |
| **密钥派生** | 待决策 D6 | **已采用**：`K_enc` / `K_mac` 由 `K_session` 派生 | 密钥用途分离 |
| **AES 使用方式** | 直接用 `aes_ctr_xor` | 通过 `CryptoProvider` → `AesCryptoProvider` 调用 | 保留算法可替换性 |
| **CMAC** | 由第一部分提供 | **未就绪 → `PlaceholderMacEngine` 占位** | CMAC 仍在第一部分开发中 |
| **测试端口** | `pickFreePort()` 取空闲端口 | **服务端 `port = 0` + `onListening` 回调** | 取空闲端口的写法存在"客户端早于服务端 listen"的竞态，实测中确实触发了 `Connection refused` |

## 16.4 实施中新增的接口（方案里没有，但对第三部分有用）

```cpp
// 1) 服务端监听回调：port 传 0 时拿真实端口（测试与演示避免竞态）
std::function<void(std::uint16_t)> SessionConfig::onListening;

// 2) 数据包可观测信息：直接支撑"明文 → 密文 → CMAC → 解密结果"的报告格式
struct PacketTrace { bool valid; MessageType type; uint64_t sequence;
                     Nonce nonce; Bytes ciphertext; MacTag mac; };
const PacketTrace& SecureSession::lastSentTrace() const;
const PacketTrace& SecureSession::lastReceivedTrace() const;

// 3) 测试 / 攻击演示专用（第三部分 Eve 演示会直接复用）
bool SecureSession::sendRawWireForTesting(const Bytes& wire);   // 绕过加密与 MAC 发送原始字节
const Bytes& SecureSession::lastSentWireForTesting() const;     // 取刚发出的原始字节
```

## 16.5 实测结果（Ubuntu 20.04 / g++ 9.4.0 / CMake 3.16.3）

### 16.5.1 编译与自动化测试

```text
$ cd /home/securityTransfer/build && cmake .. && cmake --build . -j4 && ctest --output-on-failure

 1/12 test_frame              Passed   0.01 sec     ← 第一阶段回归
 2/12 test_network            Passed   0.33 sec     ← 第一阶段回归
 3/12 test_tcp_roundtrip      Passed   0.03 sec     ← 第一阶段回归
 4/12 test_aes_core           Passed   0.00 sec     ← 第一部分回归（FIPS-197 向量）
 5/12 test_packet             Passed   0.02 sec     ← 第二部分：包格式
 6/12 test_transcript         Passed   0.00 sec     ← 第二部分：转录串/域分离/防反射
 7/12 test_replay_guard       Passed   0.00 sec     ← 第二部分：防重放
 8/12 test_session_state      Passed   0.00 sec     ← 第二部分：状态机与密钥配置
 9/12 test_secure_roundtrip   Passed   0.09 sec     ← 第二部分：握手 + 4 条消息
10/12 test_tamper             Passed   0.05 sec     ← 安全：篡改
11/12 test_forge              Passed   0.01 sec     ← 安全：身份伪造
12/12 test_replay             Passed   0.14 sec     ← 安全：重放

100% tests passed, 0 tests failed out of 12
Total Test time (real) =   0.69 sec
```

编译在 `-Wall -Wextra` 下**无警告**。

> 上表是第一轮（C 版 AES 时期）的记录。第二轮接入第一部分交付的 C++ 版
> AES+CMAC 后，该测试程序已升级为 `test_aes_cmac`（覆盖 FIPS-197、
> NIST SP 800-38A 与 RFC 4493），最新的测试清单见 §17.3.1 与
> `docs/test_report.md`。

### 16.5.2 端到端演示（真实 TCP，实测输出节选）

```text
安全会话已建立。SessionId = c932366a556cb94e
NonceA = e9cb9882f0d202ab24141ad1d57024c3
NonceB = 901e9ca6d568bdb67f44f1c6d7f7ee74
---------- 第 1 条消息 ----------
  Sequence    : 1
  Nonce       : 91ec56997296e2710000000000000001
  密文(hex)   : fefa5558749f4929e9a9
  CMAC        : 55890cf1024c290325baf21a45dcf511
  MAC 验证    : 通过（数据未被篡改）
  解密明文    : Hello Bob!
...
统计: sent=7 recv=9 bytes=564/765 reject(format/replay/mac/state)=0/0/0/0 handshake(ok/fail)=1/0
```

**Nonce 的结构在真实输出里可以直接看到**：
`91ec56997296e271 | 00000000 | 00000001` = 随机会话前缀 + 计数值隔离区 + 消息序号，
4 条消息只有最后 4 字节变化，区间互不重叠 ⇒ 密钥流不会复用（§7.1 的设计被真实验证）。

4 条测试消息（课程要求 ≥ 4 条，全部解密一致、MAC 通过）：

| # | 明文 | 长度 |
| --- | --- | --- |
| 1 | `Hello Bob!` | 10 B |
| 2 | `A secure message between Alice and Bob.` | 39 B |
| 3 | `Transfer #1024: Alice->Bob, amount=500.00 USD; status=OK! (check: 9f8e7d6c)` | 75 B |
| 4 | `你好，Bob，这是一次安全通信测试。` + 37 字节二进制 | 85 B |

### 16.5.3 四项安全测试

| 攻击 | 做法 | 实测结果 |
| --- | --- | --- |
| **篡改** | 翻转 1 个密文字节并把序号 +1 后发送 | Bob 在 MAC 阶段拒绝：`rejectedMac = 1`、`rejectedReplay = 0`，上层只收到 1 条（被篡改的那条没有交付） |
| **身份伪造** | 用错误的 `K_master` 连接 Bob | 双向都拒绝：攻击者报 `Authentication Failed`，Bob 的 `handshakesFailed ≥ 1` |
| **重放** | 把截获的合法数据包原样再发一次 | Bob 在防重放阶段拒绝：`rejectedReplay = 1`、`rejectedMac = 0`（说明是在防重放阶段被拦住的，符合预期顺序） |
| **窃听** | `tcpdump -U -i lo port 9101 -w /tmp/eve.pcap` 抓一次完整通信 | 抓包 3501 字节；明文关键字 `Hello Bob` 出现 **0 次**，而 Alice/Bob 终端日志中各出现 1 次（说明消息确实发过）；抓包中只有密文与随机字节 |

> 说明：由于 MAC 目前是占位实现，"篡改被检出"验证的是**协议流程与覆盖范围正确**；
> CMAC 到位后，同一套测试会自动升级为真实的密码学保证，测试代码不需要改动。

## 16.6 §13.1 八个决策点的最终状态

| 编号 | 问题 | 决定与结果 |
| --- | --- | --- |
| **D1** | SessionId 长度 | ✅ **8 字节**（按课程要求），包头相应为 41 字节 |
| **D2** | 握手 Body 是否加密 | ✅ 明文 + MAC（与方案一致） |
| **D3** | `K_master` 保存方式 | ✅ `configs/keys.conf`，部署时 `chmod 600`，启动时检查权限并给警告 |
| **D4** | CMAC 由谁实现 | ⏳ **仍属第一部分**；第二部分提供 `MacEngine` 接口 + 占位实现，启动时明确警告 |
| **D5** | 是否新增 `Direction` 字节 | ✅ 已新增（1 字节，进 MAC） |
| **D6** | 是否派生 `K_enc` / `K_mac` | ✅ 已派生（`MAC(K_session, "ST-DATA-ENC"/"ST-DATA-MAC")`） |
| **D7** | 代码是否在 OS 里做版本管理 | ✅ **已在 `projects/securityTransfer/` 建立项目**（71 个文件）；建议下一步 `git init` 并提交 |
| **D8** | 默认日志级别 | ✅ `INFO`（可用 `ST_LOG_LEVEL` 调整） |

## 16.7 下一步剩余工作（按优先级）

> **（本节写于第一轮结束时，保留作为历史记录）**：其中第 1 项（CMAC 接入）
> 已在 §17 完成，第 3、4、5 项（性能对比、局域网双机、报告整理）已在 §18 完成。
> 当前真正剩余的工作见 §18.5。

1. **第一部分交付 CMAC** → 实现 `MacEngine` 接口并注入 `AesCryptoProvider`
   （步骤见 `projects/securityTransfer/docs/development.md` §5，其它代码零改动）；
   同时用 RFC 4493 的 4 条标准向量补单元测试（对应课程要求 3）。
2. **第三部分**：Qt/命令行友好的界面、短消息、文件（按 64 KiB 分块）、图像、
   访问控制、Eve 攻击演示界面。协议侧接口只有 `SecureSession` 一个，已经稳定。
3. **性能对比**（第一部分）：1 KB / 64 KB / 1 MB / 10 MB / 100 MB，
   与 OpenSSL 对比；虚拟机里 `libssl-dev` 已装，可直接用。
4. **局域网双机测试**：两台主机共用同一 `configs/keys.conf`，命令见 `docs/development.md` §6；
   建议补一张截图或抓包记录作为"信息确实经过网络"的证据。
5. **报告整理**：`projects/securityTransfer/docs/test_report.md` 已按课程要求的记录格式
   （明文 → 密文 → CMAC → 解密结果 → 完整性验证结果）写好，可直接引用。

## 16.8 本次实施留下的经验（值得写进复盘）

1. **"取空闲端口"是伪安全**：`listen(0)` 拿到端口再关掉、然后让服务端重新绑定，
   中间存在竞态；实测中就出现了 `Connection refused`。
   改成"服务端 `port=0` + 监听成功回调"，问题消失——这类测试基础设施的坑往往比协议本身更耗时。
2. **失败路径上的资源管理同样重要**：测试里断言失败抛异常时，若后台线程没有 join，
   会直接 `std::terminate`（表现为 `Child aborted`）。用 RAII 的 `ThreadGuard` 兜住。
3. **防重放和完整性校验的顺序有安全含义**：不是"谁先谁后都行"，
   必须"先便宜地判重放但不改状态，MAC 通过后才提交水位"，否则引入 DoS 漏洞。
4. **CTR 模式的 Nonce 不能想当然**：`aes_ctr_xor` 内部把 128 位计数器整体自增，
   所以 `prefix‖seq` 这种常见写法在长消息下会复用密钥流；把计数区隔离在低 32 位才是安全的。

---

# 17. 第二轮：资源整合与 CMAC 集成（2026-09-26）

## 17.1 本轮的输入

第一部分交付了一个新的 C++ 工程 `SecureTransfer`（加入了 CMAC 的 AES），内容：

| 文件 | 作用 |
| --- | --- |
| `aes.h` / `aes.cpp` | `AES::encryptBlock`（单分组）+ `AES::ctrXor`（CTR 模式），并暴露 `aes128_key_expand` / `aes128_encrypt_block` |
| `cmac.h` / `cmac.cpp` | `CMAC::generate` / `CMAC::verify`（RFC 4493，K1/K2 子密钥 + Rb=0x87） |
| `test_cmac.cpp` | RFC 4493 的 4 条标准向量自测（空消息 / 16B / 40B / 64B） |
| `cmac_benchmark.cpp` | CMAC 性能测试 |
| `types.h` | `Bytes` / `Key128` / `Block128` / `MacTag` |
| `usage_notes.pdf` | 第一部分的使用说明 |

这批代码正好补上了上一轮唯一的缺口（§16.1：MAC 只能用占位实现）。

## 17.2 本轮做了什么

**（1）算法接入：只写一层薄适配，算法零修改**

| 步骤 | 说明 |
| --- | --- |
| 导入源码 | `aes.h`/`aes.cpp`/`cmac.h`/`cmac.cpp` 复制进 `include/crypto/` 与 `src/crypto/`；只做了两件事：GBK → UTF-8、`#include "types.h"` → `#include "common/types.h"` 与 `"crypto/aes.h"` |
| 新增适配层 | `include/crypto/cmac_engine.h`：`CmacEngine : public MacEngine`，约 30 行，只做转发 |
| 切换默认实现 | `AesCryptoProvider` 构造参数为 `nullptr` 时默认使用第一部分的 CMAC；`PlaceholderMacEngine` 仍保留，用 `--placeholder` 显式启用（用于演示"算法可替换"） |
| 退役旧实现 | 上一轮导入的 C 版 AES（`aes_core.c/h`）移入 `reference/aes-c-legacy/` 留档，不再参与构建 |
| 算法文件保持原样 | `src/crypto/aes.cpp` 与 `src/crypto/cmac.cpp` 的算法逻辑**没有改过一行**，只加了文件头注释 |

**（2）补标准向量回归测试**：新增 `tests/unit/test_aes_cmac.cpp`（9 个用例）

1. FIPS-197 单分组向量（同时验证 C 接口与 `AES::encryptBlock`）；
2. NIST SP 800-38A F.5.1 的 CTR 向量（2 个分组）；
3. RFC 4493 的 4 条 CMAC 标准向量；
4. CMAC 验证语义（换密钥 / 改消息 / 改标签都必须失败）；
5. AES-CTR 往返（短文本 / 英文 / 长文本 / 中文 UTF-8 / 空串 / 37 字节非整块二进制）；
6. `CmacEngine` 与直接调用 `CMAC` 结果完全一致；
7. `AesCryptoProvider` 默认使用真实 CMAC（`macIsCryptographicallySecure() == true`）；
8. 显式切换到占位实现仍然可用（接缝可替换的证明）；
9. 1 MiB 数据的 CMAC 一致性与篡改检测。

**（3）项目结构整理**（把属于本项目的文件全部收进一个目录）

| 原位置 | 现位置 |
| --- | --- |
| `projects/project_q1.md` | `projects/securityTransfer/docs/project_q1.md` |
| `projects/team_interfaces_original.md` | `projects/securityTransfer/docs/team_interfaces_original.md` |
| `projects/Part2_transfer.md` | `projects/securityTransfer/Part2_transfer.md` |
| 用户放入的 `securityTransfer/SecureTransfer/...` | `projects/securityTransfer/reference/part1-aes-cmac/`（第一部分原件存档） |
| 上一轮的 C 版 AES | `projects/securityTransfer/reference/aes-c-legacy/`（留档） |
| `cmac_benchmark.cpp` | `projects/securityTransfer/tools/cmac_benchmark.cpp`（改造成可指定重复次数的命令行工具） |

`projects/` 根目录现在只剩 `README.md`（目录说明）与 `securityTransfer/`（唯一项目目录）。

> 说明：第一部分原件的**源码、VS 工程文件、使用说明 PDF 全部完整保留**；
> 只对重复的编译产物（`.obj` / `.pdb` / `.exe` 之类的中间文件）做了合并，
> 没有删除任何源码或文档。

**（4）文档同步**：README、architecture、interfaces、protocol、development、
requirements、test_report 全部更新到"CMAC 已集成"的状态。

## 17.3 实测结果

### 17.3.0 规模

| 项目 | 数值 |
| --- | --- |
| 目录下的文件总数 | 120（含第一部分原件存档与课程文档） |
| C/C++ 源文件 | 64（本部分自写 49，第一部分交付 4，其余为测试/存档） |
| C/C++ 代码行数 | 约 7700 行 |
| 含文档的总行数 | 约 12900 行 |

### 17.3.1 编译与测试

```text
== build ==   （-Wall -Wextra，无警告）
[ 21%] Built target st_crypto        [ 38%] Built target st_security
[ 46%] Built target test_frame       [ 80%] Built target test_aes_cmac
[ 97%] Built target test_tamper      [100%] Built target test_secure_roundtrip

== ctest ==
 1/12 test_frame            Passed  0.01 s
 2/12 test_network          Passed  0.31 s
 3/12 test_tcp_roundtrip    Passed  0.02 s
 4/12 test_aes_cmac         Passed  0.04 s   ← FIPS-197 + SP 800-38A + RFC 4493
 5/12 test_packet           Passed  0.01 s
 6/12 test_transcript       Passed  0.00 s
 7/12 test_replay_guard     Passed  0.00 s
 8/12 test_session_state    Passed  0.00 s
 9/12 test_secure_roundtrip Passed  0.09 s
10/12 test_tamper           Passed  0.05 s
11/12 test_forge            Passed  0.01 s
12/12 test_replay           Passed  0.13 s

100% tests passed, 0 tests failed out of 12
Total Test Time (real) = 0.69 sec
```

### 17.3.2 端到端演示（现在使用真实 CMAC）

```text
身份          : bob（期望对端: alice）
密码算法      : AesCryptoProvider(AES-128-CTR)
完整性算法    : CMAC(AES-128, RFC 4493)（密码学强度：达标）
安全会话已建立。SessionId = 369e3fe1d7654dcf
---------- 第 1 条消息 ----------
  Sequence    : 1
  Nonce       : b93ffb1b6074a1950000000000000001
  密文(hex)   : 6102ef06b653477e0f19
  CMAC        : 2c274a5402ec40bc4f836c5423018c08
  MAC 验证    : 通过（数据未被篡改）
  解密明文    : Hello Bob!
...
统计: sent=7 recv=9 reject(format/replay/mac/state)=0/0/0/0 handshake(ok/fail)=1/0
=== 4 条测试消息全部安全传输成功 ===
```

### 17.3.3 CMAC 性能（第一部分自实现，`./cmac_benchmark 5`）

| 数据大小 | 平均耗时 | 吞吐率 |
| --- | --- | --- |
| 1 KB | 0.010 ms | 95.4 MB/s |
| 64 KB | 0.539 ms | 115.9 MB/s |
| 1 MB | 8.725 ms | 114.6 MB/s |
| 10 MB | 88.351 ms | 113.2 MB/s |

### 17.3.4 安全测试

四项攻击测试仍然全部通过；其中**篡改测试的结论已经升级**：
上一轮是"协议流程证明占位 MAC 能发现改动"，现在是"真实 CMAC 拒绝被篡改的数据包"。

## 17.4 最终目录结构

```text
projects/
├── README.md                      # projects/ 目录说明 + 项目入口索引
└── securityTransfer/              # 唯一项目目录
    ├── README.md                  # 项目总说明（目标 / 架构 / 接口 / 运行 / 状态）
    ├── Part2_transfer.md          # 本文件：第二部分方案 + 进度 + 实测
    ├── CMakeLists.txt
    ├── apps/                      # alice / bob 演示程序
    ├── configs/                   # keys.conf（K_master，600 权限）/ demo_config.conf
    ├── include/                   # common / crypto / network / protocol / security
    ├── src/                       # 对应实现（含第一部分 aes.cpp / cmac.cpp）
    ├── tests/                     # unit/ 与 integration/，共 12 个测试程序
    ├── tools/                     # cmac_benchmark（性能测试）
    ├── scripts/                   # verify_in_vm / capture_eve / deploy_to_home 等
    ├── docs/
    │   ├── project_q1.md          # 课程原始需求（原件）
    │   ├── team_interfaces_original.md                 # 组内接口约定（原件）
    │   ├── requirements.md        # 课程要求 vs 实现状态对照
    │   ├── architecture.md        # 分层与模块
    │   ├── protocol.md            # 数据包格式与协议流程
    │   ├── interfaces.md          # 对外接口
    │   ├── development.md         # 编译 / 运行 / 扩展
    │   ├── test_report.md         # 实测结果（含攻击测试与性能）
    │   └── stage1/                # 第一阶段（纯 TCP）文档存档
    └── reference/
        ├── part1-aes-cmac/        # 第一部分交付原件（VS 工程，不参与构建）
        └── aes-c-legacy/          # 更早的 C 版 AES（已退役，留档）
```

## 17.5 决策点更新

| 编号 | 状态 |
| --- | --- |
| **D4**（CMAC 由谁实现） | ✅ **已解决**：第一部分交付并集成，RFC 4493 向量通过 |
| 其余 D1 / D2 / D3 / D5 / D6 / D7 / D8 | 保持 §16.6 的结论不变 |

## 17.6 剩余工作（更新版）

> **（本节写于第二轮结束时，保留作为历史记录）**：其中第 1 项（与库的性能对比）
> 与第 2 项（1 MB~100 MB 吞吐测试）已在 §18 完成，第 4 项（局域网双机）
> 已完成命名空间版测试（真机双机命令已就绪）。当前剩余工作见 §18.5。

1. **与库实现的性能对比**（课程要求 5）：自实现侧数据已有（§17.3.3），
   需要补 OpenSSL 侧的对照数据（VM 已装 `libssl-dev`）；
2. **AES-CTR 的 1 MB ~ 100 MB 吞吐测试**（要求 5 的另一半）；
3. **第三部分**：Qt/界面、短消息、文件（64 KiB 分块）、图像、访问控制、Eve 演示界面
   （接口只有 `SecureSession` 一个，已稳定）；
4. **局域网双机测试**：两台主机共用同一 `keys.conf`，补一张截图/抓包记录；
5. **报告整合**：技术报告可直接引用 `docs/test_report.md` 的数据与截图。

## 17.7 本轮的经验

1. **算法与协议之间的"薄适配层"很值钱**：这一轮接入真实 CMAC，
   协议层、测试、应用代码**一行都没有改**，只新增了 30 行 `CmacEngine`
   并把默认实现换了一处——这正是上一轮预留接缝的回报。
2. **标准向量测试要在集成之后再跑一遍**：算法单独测过 ≠ 集成后没问题。
   接入后重跑 FIPS-197 / SP 800-38A / RFC 4493，才能证明"接入没有破坏算法"。
3. **交付件的编码与路径差异是最常见的摩擦点**：这次遇到 GBK 注释与
   `#include "types.h"` 两类问题，都是"编译能过但会埋雷"的类型，导入时一次处理干净。
4. **归档优于删除**：第一部分的 VS 工程原件与更早的 C 版 AES 都保留在 `reference/` 下，
   既让项目目录保持规整，又不丢历史（万一需要对照"哪一版跑出的数据"还能查）。

---

# 18. 第三轮：与库实现的性能对比 + 局域网双机测试（2026-09-26）

## 18.1 本轮目标（对应课程要求 5、6）

* 要求 5：与库实现（OpenSSL）做**全面的性能对比**，覆盖 `project_q1.md` §10
  指定的 1 KB / 64 KB / 1 MB / 10 MB / 100 MB，记录加密时间、解密时间、吞吐率，
  并**结合算法实现方式、代码优化、硬件加速解释差异**；
* 要求 6：把通信放到**两台独立主机**之间，用抓包证明数据确实经过网络。

## 18.2 性能对比：怎么做才公平

新增 `tools/crypto_benchmark.cpp`（**只有这个工具链接 OpenSSL**，系统本体仍然完全自实现，
满足要求 4）。为保证结论可靠，做了五件事：

1. 两侧处理同一份数据、同一把密钥、同一个 nonce；
2. 都按“一次性调用”计时（我们的 `AES::ctrXor` 含密钥扩展，OpenSSL 含 `EVP_EncryptInit`），
   这正是两者在真实系统里的调用方式；
3. 每档先预热、再重复多次取平均（重复次数按规模自适应，最少 3 次）；
4. **先做正确性交叉验证再比性能**：同一密钥/nonce 下，自实现与 OpenSSL 的
   AES-CTR 密文与 CMAC 标签**逐字节一致**；
5. 跑两组：默认（OpenSSL 使用 AES-NI）与 `OPENSSL_ia32cap=~0x200000200000000`
   （禁用硬件指令，得到**纯软件对纯软件**的对比）。

## 18.3 关键结果

**AES-128-CTR（默认，库使用 AES-NI）**

| 数据大小 | 自实现加密(ms) | 库实现加密(ms) | 自实现解密(ms) | 库实现解密(ms) | 自实现吞吐率(MB/s) | 库实现吞吐率(MB/s) | 倍率 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 KB | 0.008 | 0.000 | 0.008 | 0.000 | 117.0 | 5086.2 | 43.5x |
| 64 KB | 0.542 | 0.007 | 0.544 | 0.007 | 115.2 | 9408.7 | 81.7x |
| 1 MB | 8.553 | 0.122 | 8.697 | 0.152 | 116.9 | 8222.3 | 70.3x |
| 10 MB | 87.243 | 2.319 | 91.711 | 2.227 | 114.6 | 4311.9 | 37.6x |
| 100 MB | 896.565 | 189.836 | 1063.996 | 182.109 | 111.5 | 526.8 | 4.72x |

**禁用 AES-NI（纯软件对纯软件）**

| 数据大小 | 自实现吞吐率(MB/s) | 库实现吞吐率(MB/s) | 倍率 |
| --- | --- | --- | --- |
| 1 KB | 99.6 | 290.2 | 2.91x |
| 64 KB | 118.1 | 328.7 | 2.78x |
| 1 MB | 115.5 | 330.7 | 2.86x |
| 10 MB | 113.7 | 307.3 | 2.70x |

**CMAC**：默认 1 KB~100 MB 为 11.8x ~ 17.2x（库 1286~1773 MB/s，自实现 103~111 MB/s）；
禁用 AES-NI 后为 3.3x ~ 3.6x。

**结论**

1. 数量级差距来自 **AES-NI 硬件加速**（同一台机器、同一份数据，只切换这一个开关，
   倍率从 70~82 倍掉到 2.7~2.9 倍）；
2. 剩下的 2~3 倍来自**工程优化**：OpenSSL 用手写汇编、向量化与多分组并行，
   我们是逐字节查表、逐分组串行的 C++ 实现；
3. **数据规模会改变倍率**：100 MB 时库实现变成内存带宽受限（9409 → 527 MB/s），
   我们始终保持 ~111 MB/s，倍率降到 4.7 倍——所以报告性能必须写明规模；
4. 固定开销（密钥扩展 0.036 µs/次 ≈ 1 KB 消息的 0.4%）可忽略；
5. 正确性：两侧 AES-CTR 密文与 CMAC 标签完全一致，且通过 FIPS-197 /
   NIST SP 800-38A / RFC 4493 标准向量。

完整数据、分析与优化建议见 **`docs/performance.md`**。

## 18.4 局域网双机测试

环境里只有一台可用虚拟机，因此用 **Linux 网络命名空间**造出两台独立主机
（各自独立网卡 / IP / 路由表 / ARP 表），中间用一条虚拟以太网链路相连——
在网络层面就等价于两台机器用网线直连。新增 `scripts/lan_test.sh`，
一条命令完成拓扑搭建、抓包、通信、取证与清理。

实测结果：

```text
主机 Alice : st-alice  网卡 stva  10.10.0.1/24
主机 Bob   : st-bob    网卡 stvb  10.10.0.2/24
Alice -> Bob ping 可达 ✅
ARP 表：10.10.0.2 dev stva lladdr 36:0a:64:5e:6b:b7 REACHABLE
抓包：32 个包 / 2 个 TCP SYN / 明文关键字出现 0 次
TCP 握手：10.10.0.1.54756 > 10.10.0.2.9000: Flags [S]
          10.10.0.2.9000 > 10.10.0.1.54756: Flags [S.]
Alice / Bob 退出码：0 / 0，4 条消息全部成功，reject(...)=0/0/0/0
```

脚本同时支持**真机双机**：

```bash
# Bob 所在机器
bash scripts/lan_test.sh --server 9000
# Alice 所在机器
bash scripts/lan_test.sh --client 192.168.x.x 9000
```

证据解读、两步复现说明与"命名空间模拟 ≈ 真机到什么程度"的说明见 **`docs/lan_test.md`**。

## 18.5 本轮的决策点与剩余工作

**决策点**

| 编号 | 状态 |
| --- | --- |
| 要求 5（性能对比） | ✅ 完成（自实现 vs OpenSSL，含硬件加速开关对比） |
| 要求 6（网络传输） | ✅ 完成（两独立主机 + 抓包证据；真机脚本已就绪） |

**剩余工作**

1. **第三部分**：Qt/界面、短消息、文件（64 KiB 分块）、图像、访问控制、Eve 演示界面；
2. **真实两台物理机/虚拟机**的证据（如果老师要求"必须是两台机器"）：
   用 `scripts/lan_test.sh --server/--client`，两台机器共用同一 `keys.conf` 即可；
3. 可选的性能扩展：AES-NI 版本实现、CTR 多分组并行（见 `docs/performance.md` §6）；
4. `git init` + 首次提交（决策 D7，仍未做）。

## 18.6 本轮的经验

1. **做性能对比一定要先对答案**：如果两侧算出的密文/标签不一致，
   后面的速度数字毫无意义。先把"算得对"钉死，再谈"算得快"。
2. **必须区分"算法差距"和"硬件差距"**：只测一组数字会得出
   "我们的实现慢 80 倍"的误导结论；把 AES-NI 关掉再测，
   结论立刻变成"慢 2.8 倍，且差距来自工程优化"——这才是可解释、可改进的结论。
3. **网络测试的失败往往不在协议层**：第一次用网桥做虚拟局域网时 ping 不通，
   原因是 Docker 装过之后 `br_netfilter` 生效、iptables FORWARD 默认 DROP，
   把桥接流量丢了；换成 veth 直连后问题消失。排查时"先 ping 通再跑协议"能立刻定位层次。
4. **脚本要能自己在错误的地方停下**：给测试加上 `timeout` 之后，
   "Bob 卡在 accept() 永远不退出"这类问题从"挂死"变成了"30 秒后给出结论"。

---

# 19. 第四轮：文件与图像安全传输（课程要求 9，2026-09-28）

## 19.1 目标

课程要求 9（10 分）：**能够支持多种信息（短消息、文件、图像等）安全传输**。
短消息在 §16 已完成（`DATA` 消息）；本轮补上**文件**与**图像**。

## 19.2 设计：复用安全通道，只加"分块与重组"

关键决策：**不新增任何密码学代码**。文件与图像仍然通过
`SecureSession::sendMessage()` 发送，因此自动获得：
AES-128-CTR 加密、CMAC 完整性、Sequence 防重放、方向校验与会话绑定。
应用层只做三件事：分块、重组、整文件校验。

两条传输路径：

```text
分块传输（普通文件、大图像）
    FILE_START  元数据{kind, mode=分块, 文件名, 总字节数, CRC32}
    FILE_CHUNK  ×N   每块 64 KiB（顺序由协议头的 Sequence 保证）
    FILE_END    {总字节数, CRC32}

单包传输（不超过约 1 MiB 的小图像）
    IMAGE       元数据{kind=图像, mode=单包, ..., 数据长度} + 数据（同一个包）
```

细节与理由：

1. **块大小 64 KiB**：协议单包正文上限约 1 MiB（`Packet::kMaxBodySize = 1048519`），
   留足余量，也便于打印进度；
2. **顺序不另设偏移量**：块顺序由协议头的 `Sequence` 保证，
   重复或过期的块会被防重放逻辑直接拒绝，所以块里不需要冗余的偏移字段；
3. **小图像单包**：避免"一张 100 KB 的图也要走三次往返"；
   超过上限时自动退化为分块（起始包仍是 `IMAGE`，`kind = 图像`）；
4. **文件名安全校验**：只接受基本名，禁止 `/`、`\`、`..` 与控制字符，
   防止接收端被诱导写到任意路径（目录穿越）；
5. **两道校验分工**：每块的 CMAC 负责**防篡改**（密码学强度），
   总字节数 + 整文件 CRC32 负责**确认重组结果正确**（非密码学差错检测）。
   两者不可互相替代——这一点在报告里必须写清楚。

## 19.3 实验数据（主机与虚拟机各一份）

全部放在 `experiment_data/`，两边**内容完全相同**（`.bin` 为确定性伪随机字节，
PNG 由标准库 `zlib` 手工构造并逐块校验过 PNG 的 CRC 与解压长度）：

| 文件 | 大小 | 用途 |
| --- | --- | --- |
| `text_messages.txt` | 521 B | 4 条文本测试消息的明文备份 |
| `test_file_1KB.bin` | 1 KB | 小文件 |
| `test_file_64KB.bin` | 64 KB | 恰好 1 个分块的边界 |
| `test_file_1MB.bin` | 1 MB | 16 个分块 |
| `test_image_256x256.png` | 147 KB | 小图像 → 单包 `IMAGE` |
| `test_image_1024x768.png` | 2.2 MB | 大图像 → 自动分块（起始包 `IMAGE`） |
| `received/` | — | 接收端落盘目录（主机上的那份是从虚拟机取回的结果，用于留档） |

## 19.4 实测结果（Ubuntu 20.04 虚拟机，真实 TCP）

```text
  文件名      : test_file_64KB.bin        传输方式: 分块(1 块)         耗时  2.06 ms  30.4 MB/s
  文件名      : test_file_1MB.bin         传输方式: 分块(16 块)        耗时 27.31 ms  36.6 MB/s
  文件名      : test_image_256x256.png     传输方式: 单包（IMAGE）      耗时  4.45 ms  31.5 MB/s
  文件名      : test_image_1024x768.png    传输方式: 分块(34 块, kind=图像) 耗时 50.14 ms  42.3 MB/s
统计: sent=67 recv=11 bytes=3487487/1067 reject(format/replay/mac/state)=0/0/0/0
```

接收端：4/4 校验通过（字节数一致 + CRC32 一致），
逐字节核对与 sha256 对照**全部一致**：

```text
[一致] test_file_64KB.bin (65536 字节)        源=5eb4ca70d0ee472b 收=5eb4ca70d0ee472b
[一致] test_file_1MB.bin (1048576 字节)       源=d824bde2acff5ab2 收=d824bde2acff5ab2
[一致] test_image_256x256.png (147133 字节)    源=f8ea510fbcb5e006 收=f8ea510fbcb5e006
[一致] test_image_1024x768.png (2221729 字节)  源=baa39e9c9864962e 收=baa39e9c9864962e
```

**应用层吞吐 30~42 MB/s**（低于纯加密的约 110 MB/s）：差距来自每次 `sendMessage` 的固定开销、
磁盘读写、每块一次 CMAC，以及 64 KiB 小块带来的调用次数。
若要提速，把块大小调到 256 KiB / 512 KiB 即可（仍远低于单包上限），属于可调参数。

## 19.5 新增代码与测试

| 文件 | 作用 |
| --- | --- |
| `include/application/crc32.h` | 自实现 CRC32（IEEE 802.3，查表法），流式接口 |
| `include/application/transfer_meta.h`、`src/application/transfer_meta.cpp` | 元数据编解码、文件名安全校验、类型推断 |
| `include/application/file_transfer.h`、`src/application/file_transfer.cpp` | `FileSender`（发送）与 `TransferReceiver`（接收 / 重组 / 校验） |
| `apps/alice`、`apps/bob` | 新增 `--file` / `--image` / `--data-dir` / `--out-dir` 参数与接收落盘、ACK |
| `tests/unit/test_transfer_meta.cpp`（9 例） | CRC32 已知值与分块累积、元数据往返、目录穿越拒绝、接收器正常/篡改/单包/非传输消息 |
| `tests/integration/test_file_transfer.cpp` | 真实 TCP：文本 + 300 KB 文件 + 40 KB 小图像 + 2 MB 大图像，逐字节比对 |

`ctest`：**14 个测试程序全部通过**（构建零警告）。

## 19.6 剩余工作（更新）

1. **访问控制**（要求 7 的一部分）：目前只有认证出的身份，还没有 Role/Permission；
2. **图形/交互界面**（要求 8，加分）：仍是命令行；
3. **实验报告与提交材料**：报告 `.docx`（6 章 + 封面）、源程序文件夹命名、
   **剔除工程文件与中间文件**（`build/`、`reference/part1-aes-cmac/` 里的 `.sln/.vcxproj/.vs/Debug/x64`）、
   30 道 LeetCode 题、打包成 rar；
4. **真机双机截图**（若老师要求两台物理设备）：命令已在 `docs/lan_test.md` §4；
5. `git init` + 首次提交（决策 D7）。

## 19.7 本轮的经验

1. **"复用安全通道"让新功能变得很便宜**：文件/图像传输没有写一行密码学代码，
   只加了 CRC32、元数据和分块重组，安全性却与短消息完全同级——
   这是前几轮坚持"安全逻辑收口在 SecurePacket + SecureSession"的回报。
2. **应用层协议要有"边界"字段**：块大小、总长度、单包/分块模式、文件名，
   缺一个都会在异常情况下出错；尤其是**文件名必须做安全校验**，
   否则接收端会被诱导写到任意路径。
3. **区分"密码学校验"和"差错检测"**：CMAC 防篡改，CRC32 只是重组自检；
   两者混为一谈是报告里常见的扣分点。
4. **实验数据要两边留档、可复现**：数据由确定性算法生成，
   主机与虚拟机各一份，接收结果也留档，复查时可以直接 `cmp`/`sha256`。

---

# 20. 第五轮：访问控制（课程要求 7 的组成部分，2026-09-28）

## 20.1 目标

课程要求 7 要求安全协议"包含加密、认证、密钥交换和**访问控制**等功能"。
前四轮已完成加密 / 认证 / 密钥交换 / 防重放，本轮补上访问控制
（对应 `project_q1.md` §6：认证回答"你是谁"，访问控制回答"你能做什么"）。

## 20.2 设计

```text
身份认证（第二部分，已完成） → 身份 → 角色（Role） → 权限（Permission） → 允许 / 拒绝
```

五条设计决策：

1. **策略与代码分离**：角色、权限、身份→角色的映射全部写在 `configs/access_policy.conf`，
   增加用户只需加一行；权限名写错、默认角色没定义权限等一律**拒绝加载**（不静默放开）；
2. **默认拒绝**：未登记身份落到 `defaultRole`（默认 `guest`）；
   角色没有定义权限时视为"无权限"，而不是"无限制"；
3. **服务端权威**：判定在服务端（Bob）做，用的是**握手阶段认证过的对端身份**，
   不是消息里自称的名字；客户端可以加载同一份策略做本地提示，但不参与决策；
4. **拒绝操作 ≠ 中断会话**：越权只拒绝该操作、计数并回一条明确原因；
   而篡改（MAC 失败）/重放仍按协议层规则终止会话——两者策略不同，报告里要讲清楚；
5. **被拒绝的传输必须整体丢弃**：`FILE_START` 被拒绝后，后续 `FILE_CHUNK`
   不能再落盘（否则等于"拒绝了却还是写了文件"），实现上用 `droppingTransfer`
   状态把该次传输剩余的数据块与结束包静默丢弃。

操作粒度：`send_message` / `send_file` / `send_image` / `view_log` / `manage_users`。

## 20.3 实测结果

**场景 1：管理员 alice（角色 admin）**

```text
本端角色      : admin [send_message, send_file, send_image, view_log, manage_users]
  服务端返回  : ROLE admin : send_message, send_file, send_image, view_log, manage_users
  服务端返回  : AUDIT LOG (最近 7 条, 允许 7 次 / 拒绝 0 次)
  对端确认    : FILE OK test_file_64KB.bin (65536 字节, CRC32=0x1f50c2e7)
  对端确认    : FILE OK test_image_256x256.png (147133 字节, CRC32=0xe30eac16)
```

**场景 2：访客 mallory（角色 guest）**

```text
本端角色      : guest [send_message]
  服务端返回  : ROLE guest : send_message
  服务端返回  : ACCESS DENIED: view_log 仅管理员可用（当前角色 guest）
  [本地提示] 角色 guest 缺少权限 send_file，服务端预计会拒绝
  对端确认    : ACCESS DENIED: send_file 需要更高权限（当前角色 guest）
  对端确认    : ACCESS DENIED: send_image 需要更高权限（当前角色 guest）

服务端：共接收 4 条加密消息，0 个文件/图像；访问控制拒绝 3 次（允许 6 次 / 拒绝 3 次）
```

**审计日志**（`experiment_data/access_log.txt`，主机与虚拟机各留一份）：

```text
2026-09-27 18:37:10 ALLOW alice(admin) send_message
2026-09-27 18:37:10 ALLOW alice(admin) view_log
2026-09-27 18:37:10 ALLOW alice(admin) send_file
2026-09-27 18:37:11 ALLOW mallory(guest) send_message
2026-09-27 18:37:11 DENY  mallory(guest) view_log 尝试查看审计日志
2026-09-27 18:37:11 DENY  mallory(guest) send_file 服务端判定无权限
2026-09-27 18:37:11 DENY  mallory(guest) send_image 服务端判定无权限
```

要点：访客的**短消息全部正常**（证明拒绝是按操作粒度的）；文件与图像被拒绝且
**磁盘上没有产生任何访客文件**（集成测试里用"文件不存在"断言）；**会话没有中断**。

## 20.4 新增代码与测试

| 文件 | 作用 |
| --- | --- |
| `include/security/access_control.h`、`src/security/access_control.cpp` | `Operation` / `PermissionSet` / `Policy` / `AccessController`（策略加载、判定、审计、策略总览） |
| `configs/access_policy.conf` | 角色 / 权限 / 身份映射（含 admin / user / guest 三个角色示例） |
| `include/common/path_utils.h` | 递归创建目录（避免依赖 `std::filesystem` 的额外链接项） |
| `apps/bob` | `--policy` / `--access-log` / `--id` / `--peer`；服务端权威判定、越权丢弃传输、`CMD WHOAMI` / `CMD VIEW_LOG` |
| `apps/alice` | `--id` / `--policy`（本地提示）/ `--whoami` / `--view-log` |
| `tests/unit/test_access_control.cpp`（8 例） | 策略解析、判定矩阵、默认拒绝、非法策略、消息类型映射、审计记录与写文件 |
| `tests/integration/test_access_control.cpp` | 端到端：管理员成功落盘；访客被拒绝且不落盘、会话继续、审计含 ALLOW 与 DENY |

`ctest`：**16 个测试程序全部通过**（构建零警告）。

## 20.5 剩余工作（更新）

功能层面，课程要求的 1~7、9 与部分加分项（5、10）已完成，剩下：

1. **图形/交互界面**（要求 8，加分项）：仍是命令行；
2. **实验报告与提交材料**：报告 `.docx`（六章 + 封面）、源程序文件夹命名、
   **提交前剔除工程文件与中间文件**、30 道 LeetCode 题、打包 rar；
3. **真机双机截图**（若要求两台物理设备）：命令见 `docs/lan_test.md` §4；
4. **每个身份独立凭证**：当前实验环境下所有身份共用一把 `K_master`
   （见 `docs/access_control.md` §8），真实系统应改为每个身份独立密钥/证书；
5. `git init` + 首次提交（决策 D7）。

## 20.6 本轮的经验

1. **"拒绝操作"和"拒绝会话"必须分开设计**：越权只该拒该操作，
   否则一个越权请求就能把正常通信打断（可用性问题）；而篡改/重放是协议级违规，
   终止会话才是正确选择。两者混淆是这类实验常见的逻辑漏洞。
2. **被拒绝的传输要一路拒到底**：只拒 `FILE_START` 而不处理后续 `FILE_CHUNK`，
   会出现"已经拒绝却仍写了文件"的假拒绝。用一个小状态机把整条传输丢弃才干净。
3. **授权要用"认证过的身份"**：如果用消息里自称的名字做权限判断，
   任何人都能写"我是 alice"来提权——身份必须来自握手阶段。
4. **默认拒绝比默认允许安全得多**：策略写漏一个用户、一个角色没定义权限，
   默认拒绝只会"不让人做事"，默认允许会造成真实越权。

---

# 21. 第六轮：图形界面（课程要求 8，2026-09-28）

## 21.1 方案选择（先给方案、由用户决策）

先探测了环境，再给四个可行方案由用户决策（本轮记录保留这个决策过程）：

| 方案 | 技术栈 | 需要装什么 | 代码量 | 界面效果 | 结论 |
| --- | --- | --- | --- | --- | --- |
| **A. Qt5 Widgets** | C++，与内核同进程 | `qtbase5-dev`（~100 MB，apt 可用） | ~1100 行 | 真图形界面 | ✅ **用户选定** |
| B. ncurses TUI | C++ | 零安装（头文件已在） | ~450 行 | 终端全屏 | 备选 |
| C. Python tkinter 前端 | 界面在 Windows，内核在 Linux | Windows 零安装 | ~550 行 | 真窗口，但要自定控制协议 | 备选 |
| D. 浏览器 Web UI | 浏览器 + Linux 控制服务 | 零安装 | ~600 行 | 网页界面 | 备选 |

选 A 的理由：课程明确要求"人机交互界面"，Qt 图形界面加分最直接；与现有代码同进程，
能直接展示握手每一步、会话标识、统计与访问控制；只需新增一个开发包依赖。

## 21.2 界面设计

七个分区（详见 `docs/ui.md`）：

1. **连接与身份**：角色（客户端/服务端）、地址、端口、本端身份（alice/eve/mallory/bob）、
   对端身份、密钥配置、访问策略、接收目录、审计日志、启动/断开；
2. **安全会话状态**：状态灯 + SessionId + 两个 Nonce + 我的角色与权限；
3. **统计与访问控制**：收发统计 + `WHOAMI` + 查看审计日志；
4. **短消息**：历史 + 输入框 + 发送；
5. **文件 / 图像传输**：文件选择器 + 进度条 + CRC32 校验结果；
6. **Eve 攻击演示**：一键"篡改上一个包" / "重放上一个包"；
7. **运行日志**：握手每一步、访问控制判定、传输细节。

## 21.3 两个关键设计

**（1）线程模型：把阻塞的接收放到工作线程**

```text
GUI 线程  ──(加锁队列下发命令)──▶  SessionWorker 线程
   ▲                                   │ 独占 SecureSession
   └──────(Qt 信号：日志/状态/进度)─────┘ 握手 → 发送 → 接收（见 §24：改为 tryReceiveMessage）
```

`SecureSession` 不是线程安全的，所以规定**只有工作线程碰它**；
界面永远不卡（当时的实现是对端消息最多延迟 250 ms 显示；
2026-10-01 已改为 `tryReceiveMessage()`，延迟与日志噪声问题都已解决，见 §24）。

**（2）界面不含任何密码学逻辑**

界面只调用 `SecureSession`（握手 + 加密通道）、`FileSender`/`TransferReceiver`（文件图像）、
`AccessController`（访问控制与审计）。这既满足"密码算法自己写"的要求 4，
也让界面代码保持在约 1100 行。

## 21.4 实测结果

| 场景 | 结果 |
| --- | --- |
| 图形界面作**服务端**（Bob, admin） | 命令行 Alice 驱动：4 条短消息 + `WHOAMI` + `VIEW_LOG` + 1 MB 文件（16 块，CRC32 通过）+ 147 KB 图像（单包），界面日志完整记录握手 7 步 |
| 图形界面作**客户端**（Alice, admin） | 界面自动发送：中文短消息 + `WHOAMI` + 1 MB 文件 + 图像，对端（命令行 Bob）显示解出明文 `你好，Bob，这是从图形界面发出的安全消息。` |
| 审计日志 | 本轮 51 条 ALLOW/DENY（与命令行版本行为一致） |
| 窗口验证 | `xwininfo` 确认窗口 `SecureTransfer — 安全的信息传输套件 952x700` 已显示；截图颜色数 >1000（不是空白图） |

截图见 `docs/screenshots/ui_server.png` 与 `ui_client.png`。

## 21.5 本轮发现并修复的真实缺陷

第一次"图形界面作客户端 + 命令行 Bob"联调时出现**消息死循环**：
界面收到 Bob 的确认后又自动回确认，Bob 再回确认……短时间内产生
**34,000+ 条消息、12.8 MB 审计日志**（把消息序号推到了 34,563）。

* **原因**：两端都对"收到的消息"自动回确认，而确认本身也是消息；
* **修复**：约定自动回复统一以 `ACK:` 开头，收到 `ACK:` / `FILE OK` / `ROLE ` /
  `AUDIT LOG` / `ACCESS DENIED` 等"回复型"消息时不再自动回复
  （`include/common/demo_reply.h`，两个程序共用同一判定）；
* **验证**：修复后同样的演示只产生 51 条审计记录，命令行的
  `test_access_control_e2e`、`test_file_transfer` 等 16 个测试仍全部通过。

## 21.6 已知限制

1. ~~接收用 250 ms 超时轮询（`SecureSession` 目前只有阻塞接收接口）~~ —— 已于 §24 解决；
2. ~~"接收失败是否为超时"依赖错误文本判断（接口未暴露 `Network::Result`）~~ —— 已于 §24 解决；
3. 一次只服务一个会话；文件发送没有队列 / 断点续传；
4. 攻击演示按钮会导致对端拒绝并终止会话（这正是演示目的），演示后需重新连接；
5. 界面需要图形会话（`DISPLAY`），因此在 `verify_in_vm.sh` 里**不跑**，
   而是单独提供 `scripts/ui_demo.sh`。

## 21.7 剩余工作（更新）

课程要求的 1~10 项现在都有对应实现与证据。剩下的是**交付层面**的工作：

1. **实验报告 `.docx`**（六章 + 封面：报告题目/班级/学号/姓名/承担工作与贡献度）；
2. **提交包整理**：源程序文件夹命名（`小组序号-小组名称-题目名称`）、
   **剔除工程文件与中间文件**（`build/`、`reference/part1-aes-cmac/` 里的
   `.sln/.vcxproj/.vs/Debug/x64`）、前 16 学时 30 道 LeetCode 题、打包 rar；
3. 真机双机截图（若要求两台物理设备）；
4. `git init` + 首次提交（决策 D7）；
5. 可选：把 Qt 界面也编译到 Windows（需要独立的前端/内核拆分，当前不做）。

## 21.8 本轮的经验

1. **先把方案摊开再动手**：先探测环境（Qt 有没有、能不能装包、有没有显示），
   再给四个方案与代价，最后由用户拍板——避免了"选错技术栈返工"。
2. **自动回应必须有终止条件**：这次的死循环与安全无关，却能把系统打爆；
   任何"收到就回"的设计都要先想清楚"什么时候停"。
3. **GUI 的阻塞调用要隔离**：把 `SecureSession` 关进工作线程，
   界面只通过队列与信号交互，既保证不卡顿，也避免多线程触碰非线程安全对象。
4. **截图要会自证**：`vmrun captureScreen` 抓到的是虚拟机控制台（桌面黑屏时只有 2 KB 单色图），
   改用 X 会话里的 `xwd` 抓窗口并统计颜色数（>1000）才能确认"真的截到了界面"。

---

# 22. 第七轮：路径英文化、GitHub 备份与 Windows 迁移方案（2026-10-01）

## 22.1 为什么要把中文路径改成英文

迁移到 Windows 时有一个**不会在编译期报错、只在运行时报错**的坑：
Windows 默认 ANSI 代码页是 GBK，而我们的源码是 UTF-8；
`std::ifstream("实验数据/测试文件-1MB.bin")` 会把 UTF-8 字节按 GBK 解释 → **找不到文件**。
影响范围包括密钥文件、实验数据、审计日志、文件/图像传输的落盘路径。

因此在迁移前先把**所有文件名与路径改为英文**（正文仍保留中文），
这样即使暂时不做 UTF-8→UTF-16 封装，Windows 上也能正常打开这些文件。

改名清单与验证结果见第七次更新横幅；要点是：

* 改名 1 个目录 + 12 个文件，同步替换 20 个文件里的 69 处路径引用；
* 干净重部署后 **16/16 测试通过、6 步验证全 PASS**；
* 虚拟机内 `find` 确认**零非 ASCII 路径名**。

## 22.2 GitHub 备份（已完成）

| 项目 | 内容 |
| --- | --- |
| 仓库 | <https://github.com/Urruna/secureTransfer>（**Private**） |
| 分支 / 标签 | `main` / `v1.0-linux-verified` |
| 首次提交 | `0295729`（作者 Urruna <1956274291@qq.com>） |
| 入库规模 | 132 个文件 / 4.92 MB |
| 未入库 | `build/`、`.vs/`（579 MB）、`Debug/`、`x64/`、`configs/keys.conf`、`experiment_data/received/`、`access_log.txt`、二进制文件 —— 合计 585 MB |

**为什么先在 Linux 虚拟机里建仓**：当时 Windows 主机还没有 git。
做法是：虚拟机内 `git init` + 提交 + 打标签 → 把 `.git` 目录取回主机 →
再由主机侧的 **Git for Windows 2.47.1（安装于 `D:\AppGallery\Git`）** 完成署名修改、
分支改名与推送。一致性是通过"把主机工作区打包送回虚拟机、在原仓库里跑 `git status`"
验证的（结果为空 = 完全一致）。

遇到的一个环境问题值得记录：沙箱身份创建的文件，其**所有者**是
`CodexSandboxOffline`，而 git 以真实账号运行时会报
`detected dubious ownership`。因为 ACL 已经给了真实账号读写权限，
**不需要改所有权**，只需在用户级 git 配置里加一条
`safe.directory` 例外（已添加，另加了 OS 根目录）。

## 22.3 Windows 迁移方案（路线 A）要点

**平台相关代码集中在 5 个文件**（其余是纯 C++17，不用改）：

| 文件 | 依赖 | 迁移做法 |
| --- | --- | --- |
| `src/network/network.cpp` | POSIX socket 全套 | `#ifdef _WIN32` 双路径：`winsock2.h/ws2tcpip.h`、`WSAStartup/WSACleanup`、`closesocket`、`WSAGetLastError` 错误码映射、超时从 `timeval` 改 `DWORD` 毫秒、`kInvalidSocket` 改 `INVALID_SOCKET`（约 200–250 行） |
| `tests/raw_client.h` | 同上 | 同一套 `#ifdef`（约 30 行） |
| `src/common/random.cpp` | `/dev/urandom` | 改用 `BCryptGenRandom`（随机数允许用系统 API，密码算法仍须自写） |
| `include/common/path_utils.h` | `mkdir()` | 改用 `_mkdir()`（`<direct.h>`） |
| `src/security/keystore.cpp` | `stat()` 权限位 | Windows 无 POSIX 权限位 → 跳过该检查 + 文档提示用 ACL |

另外两项通用工作：

1. **UTF-8 → UTF-16 路径封装**（约 10 处文件打开点）：虽然路径已英文化，
   但为了稳健（用户可能用中文目录名），仍建议统一走
   `std::filesystem::u8path` 或 `_wfopen`；
2. **控制台编码**：每个程序启动时 `SetConsoleOutputCP(CP_UTF8)`，否则中文日志乱码。

Windows 侧需要准备：**MinGW-w64（MSYS2）或 MSVC**、CMake、Qt5（MSYS2 包或 Qt 官方安装器）、
OpenSSL（仅性能对比工具需要）、Wireshark（替代 tcpdump）、Python（已装）。
已安装：**Git for Windows 2.47.1 → `D:\AppGallery\Git`**。

实施顺序（每步都有验收标准）：

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| M1 | 先编译**无平台依赖**的库与测试（aes/cmac/packet/transcript/replay_guard/transfer_meta） | 标准向量（FIPS-197 / SP 800-38A / RFC 4493）在 Windows 通过 |
| M2 | 移植网络层 | `test_frame`/`test_network`/`test_tcp_roundtrip` 通过 |
| M3 | 路径与文件 I/O、`%TEMP%`、权限检查降级 | `test_file_transfer`、`test_transfer_meta` 通过 |
| M4 | 控制台中文输出 | `alice`/`bob` 中文不乱码 |
| M5 | Qt 界面 | `st_ui` 在 Windows 桌面完成一次会话 |
| M6 | 全量回归 + 重新采集证据 | 当时是 16 个测试全绿（现为 18 个）；要求 5 的性能表、要求 6 的双机测试、要求 9 的逐字节一致 |
| M7 | 文档同步 | Linux / Windows 两套实测数据分别标注 |

## 22.4 本轮的经验

1. **跨平台迁移的第一道坎往往不是代码，而是路径与编码**：
   中文文件名在 GBK 环境下"编译能过、运行打不开"，先英文化是最省事的解法。
2. **备份要在改动之前做**：这一轮先改名、再建仓、再推送，顺序刚好；
   如果先改代码再备份，一旦迁移出错就没有可回退的干净点。
3. **沙箱/容器环境会带来"文件所有者"问题**：git 的 `safe.directory` 检查、
   以及某些工具的所有权校验，都可能在"文件能被读写但仍被拒绝"的情况下出现——
   先分清楚是**权限**问题还是**所有权校验**问题，再决定改 ACL 还是加例外。

## 22.5 Windows 侧环境与 M1 结果（2026-10-01 实测）

**环境**

| 项目 | 结果 |
| --- | --- |
| Git | Git for Windows **2.47.1**，安装于 `D:\AppGallery\Git` |
| 工具链 | MSYS2 安装于 **`D:\AppGallery\dev-tools\msys64`**；`g++ 16.2.0`、`CMake 4.4.3`、`Ninja 1.13.2` |
| Qt | ⚠ 主机上**只有 Qt Creator（IDE，6.0.1），没有 Qt SDK**（注册表中无 Qt 版本、无 qmake；全盘找到的 `Qt5Core.dll` 都是 Autodesk/华为应用市场/腾讯会议自带的）。因此 Qt 改用 **MSYS2 的 `mingw-w64-x86_64-qt5`**（与 g++ 同一套 ABI，且我们的代码就是 Qt5 API，CMake 无需改动） |
| 其它 | Wireshark、Python 已装（用户提供） |

**M1 结果（只编译与平台无关的部分）**

用一份临时 CMake 工程（仅列出以下源文件，不依赖 Network）在 `-Wall -Wextra` 下编译并运行：

```text
编译：g++ 16.2.0，0 警告 0 错误

1/4 test_aes_cmac      Passed   0.20 sec   ← FIPS-197 单分组 + NIST SP 800-38A CTR + RFC 4493 四条 CMAC 向量
2/4 test_packet        Passed   0.14 sec   ← 数据包编解码 / 边界 / 非法输入
3/4 test_transcript    Passed   0.17 sec   ← 握手转录串、域分离、防反射、TLV 无歧义
4/4 test_replay_guard  Passed   0.17 sec   ← 防重放（含 wouldAccept 不推进水位）

100% tests passed out of 4
```

**结论**：自写的 AES/CMAC 在 Windows（MSVC 之外的 MinGW-w64 16.2）上**与标准向量完全一致**，
协议层中与平台无关的部分（数据包、转录串、防重放）也全部通过——
说明后续网络层移植只涉及"平台适配"，不涉及算法与协议逻辑。

**M2 要考虑的一个细节**：主机上的 CMake 是 **4.x**，而项目 `CMakeLists.txt` 里写的是
`cmake_minimum_required(VERSION 3.10)`；CMake 4 对过低的版本声明会报错/告警，
M2 时需要把它提升到 3.16（Linux 侧的 CMake 3.16 也满足）。

---

# 23. 第八轮：Windows 迁移 M2–M6 实施与两端回归（2026-10-01）

> 本轮把 §22.3 的迁移计划真正落地：网络层移植（M2）、路径与文件 I/O（M3）、
> 控制台编码（M4）、全量回归（M6），并在**同一台 Windows 主机**上跑通了
> 「Windows Alice ↔ Ubuntu Bob」的跨系统双机通信与性能对比（M6 的证据补齐）。
>
> **M5（Qt 界面）已在用户决策后完成**：按方案 A 在 MSYS2 里安装
> `mingw-w64-x86_64-qt5`（Qt 5.15.19），`st_ui` 在 Windows 上编译通过
> （0 错误 0 警告），并完成一次自动化会话 + 界面截图存档（见 §23.10）。

## 23.1 里程碑对照

| 阶段 | 内容 | 状态 | 验收结果 |
| --- | --- | --- | --- |
| M1 | 平台无关部分编译与标准向量 | ✅ 上一轮完成 | 4/4 通过 |
| M2 | 网络层移植（winsock2 + WSA 错误码 + 超时/关闭语义） | ✅ 本轮完成 | `test_frame` / `test_network` / `test_tcp_roundtrip` 通过 |
| M3 | 路径与文件 I/O、`%TEMP%`、权限检查降级 | ✅ 本轮完成 | `test_file_transfer` / `test_transfer_meta` / `test_access_control*` 通过 |
| M4 | 控制台中文输出 | ✅ 本轮完成 | `alice` / `bob` 中文日志、握手与文件表头均不乱码 |
| M5 | Qt 界面 | ✅ 本轮完成（方案 A） | MSYS2 Qt 5.15.19；`st_ui` 0 错误 0 警告，离屏自动化会话通过，截图见 §23.10 |
| M6 | 全量回归 + 重新采集证据 | ✅ 本轮完成 | Windows 与 Linux **各 16/16 测试全绿** + 跨系统双机 + 性能对比 |
| M7 | 文档同步 | ✅ 本轮完成 | 本节 + `README.md` + `docs/performance.md` |

## 23.2 代码改动清单（本轮，共 13 个文件改动 + 2 个新文件）

| 文件 | 改动 | 为什么 |
| --- | --- | --- |
| `src/network/network.cpp` | `#if defined(_WIN32)` 双路径：`winsock2.h/ws2tcpip.h`、`WSAStartup/WSACleanup`（静态守卫）、`closesocket`、`WSAGetLastError` + `std::system_category()` 错误映射、超时由 `timeval` 改 `DWORD` 毫秒、`SD_BOTH` 关闭 | 网络层唯一的平台相关实现 |
| `tests/raw_client.h` | 同样的双路径 + 新增 `kInvalidHandle`（`INVALID_SOCKET` / `-1`） | 测试里的裸 socket 客户端；顺带修掉 MinGW 下 3 条 `-Wtype-limits` 警告 |
| `include/common/path_utils.h` | Windows 用 `_mkdir()`（`<direct.h>`） | `mkdir()` 在 Windows 叫 `_mkdir()` |
| `tests/test_util.h` | 新增 `tempDir()`（`%TEMP%/st_tests` 与 `/tmp/st_tests`）与 `workDir()` | 测试不再写死 `/tmp`（原来在 Windows 上会执行 `mkdir -p` 而报错） |
| `tests/unit/test_transfer_meta.cpp`<br>`tests/integration/test_file_transfer.cpp`<br>`tests/integration/test_access_control.cpp`<br>`tests/unit/test_access_control.cpp` | 路径改用 `testutil::tempDir()/workDir()`，去掉 `std::system("mkdir -p ...")` | 同上；顺带修掉 `"/tmp/x/photo.PNG"` 这种绝对路径断言 |
| `src/common/random.cpp` | Windows 用 `BCryptGenRandom`（`bcrypt.h`），POSIX 分支保留 `/dev/urandom` | Windows 没有 `/dev/urandom`；随机数允许调用系统 API，密码算法仍然全部自写 |
| `src/security/keystore.cpp` | Windows 跳过 POSIX 权限位检查（`stat`/`S_IRGRP`） | Windows 无权限位语义，密钥文件由 NTFS ACL 保护；否则每个密钥文件都会误报"权限过宽" |
| `include/common/log.h` | `#ifdef ERROR #undef ERROR` | `<windows.h>` 把 `ERROR` 定义成整数宏，与 `stlog::Level::ERROR` 冲突 |
| **`include/common/console.h`（新）**<br>**`src/common/console.cpp`（新）** | `stconsole::ensureUtf8()`：Windows 下调 `SetConsoleOutputCP(CP_UTF8)`，POSIX 下空实现 | 中文日志在 Windows 控制台默认 GBK 下会乱码 |
| `apps/alice/main.cpp`、`apps/bob/main.cpp`、`apps/ui/main.cpp` | `main()` 首行调用 `stconsole::ensureUtf8()` | 同上 |
| `apps/ui/session_worker.cpp`、`include/security/access_control.h`、`src/security/access_control.cpp` 等 7 处 | 命名空间 `access` → **`acl`** | MinGW 的 `<unistd.h>` 里有 `access()` 函数，与命名空间同名会冲突；纯改名，逻辑不变 |
| `CMakeLists.txt` | ① `cmake_minimum_required` 3.10 → **3.16**；② `if(WIN32)` 链接 `ws2_32`；③ `if(WIN32)` 链接 `bcrypt`；④ `crypto_benchmark` 单独加 `-Wno-deprecated-declarations` | CMake 4.x 不再接受 3.10 声明；Winsock/BCrypt 需显式链接；OpenSSL 3.x 对经典 `CMAC_*` 接口有弃用告警（该工具刻意用它以对齐虚拟机里的 OpenSSL 1.1.1） |
| `tools/crypto_benchmark.cpp` | `cpuAesCapability()` 增加 Windows 分支（`__builtin_cpu_supports("aes")`） | 原来只读 `/proc/cpuinfo`，在 Windows 上**必然**误报"不支持 AES-NI"（本机 i5-1340P 实际支持），会让性能对比结论失真 |

**没有改动的部分**：`src/crypto/aes.cpp`、`src/crypto/cmac.cpp`（第一部分成果原样保留）、
协议/安全/应用层的业务逻辑、`Session` 状态机、数据包格式。

## 23.3 Windows 侧实测结果

**构建（MSYS2 MinGW-w64 / Ninja / Release）**

```text
g++ 16.2.0，CMake 4.4.3，Ninja 1.13.2
cmake --build build-win -j8   → 0 error，0 warning
```

**自动化测试**

```text
100% tests passed out of 16        （16/16，耗时 6.07 s）
```

其中原来在 Windows 上失败的 5 个用例（`test_network`、`test_transfer_meta`、
`test_access_control`、`test_file_transfer`、`test_access_control_e2e`）
分别由「`/tmp` + `mkdir -p`」和「`SO_REUSEADDR` 语义差异」两条原因修复。

**端到端演示（Windows 本机 loopback）**

```text
alice_rc=0  bob_rc=0
4 条测试消息：全部安全传输成功
文件/图像：test_file_64KB.bin / test_file_1MB.bin /
           test_image_256x256.png / test_image_1024x768.png
接收端校验：4/4「字节数一致 + CRC32 一致」
sha256 复核：4/4 与源文件逐字节一致
访问控制：admin 全部允许（含 WHOAMI、查看审计日志）；
          guest（mallory）view_log / send_file 被服务端拒绝并写入 DENY 审计记录
```

## 23.4 Linux 回归（防止"为 Windows 破坏了 Linux"）

迁移改动全部是 `#if defined(_WIN32)` 分支，但必须实测验证：

```text
Ubuntu 20.04.6 / g++ 9.4.0 / CMake 3.16.3
cmake .. && cmake --build . -j4   → 0 error，0 warning
ctest                              → 100% tests passed out of 16
Alice/Bob 演示                     → 4 条消息 + 2 个文件/图像全部成功
文件校验                           → 4/4 逐字节一致
```

有一处**恰好证明改动是"Windows 局部"**的证据：在 Ubuntu 上运行 `alice` 仍会打印

```text
[WARN] 密钥文件 ../configs/keys.conf 对 group/other 可读，建议执行 chmod 600 收紧权限
```

即密钥权限检查在 Linux 上依然生效（刚部署到 `/home/securityTransfer` 时 `keys.conf`
是 644），只有 Windows 分支才跳过。

## 23.5 平台差异清单（报告里会被追问的部分）

| 项目 | Linux（Ubuntu 621） | Windows | 我们的处理 |
| --- | --- | --- | --- |
| 套接字 API | POSIX `socket/recv/send`，`errno` | Winsock2，`SOCKET`/`INVALID_SOCKET`，`WSAGetLastError()` | `#ifdef` 双路径，错误码各自映射成同一条中文错误消息；`WSAStartup` 用静态对象在 `main` 之前完成 |
| 关闭语义 | `shutdown(fd, SHUT_RDWR)` + `close()` | `shutdown(SD_BOTH)` + `closesocket()` | 统一封装成 `kShutdownBoth` / `closeSocket()` |
| 超时 | `setsockopt(SO_RCVTIMEO, timeval)` | 同一 API 但参数是 `DWORD` 毫秒 | `applyTimeout()` 内部按平台构造参数 |
| 监听端口的复用 | `SO_REUSEADDR` 只影响 TIME_WAIT 套接字 | `SO_REUSEADDR` **允许第二个 socket 抢占已监听端口** | **保留 `SO_REUSEADDR`**（保证服务端重启后能立刻重新绑定端口）；把「同一端口重复 listen 必须失败」的断言用 `#ifndef _WIN32` 限定为 Linux 语义。**是否要改成更严格的 `SO_EXCLUSIVEADDRUSE` 见 §23.8 决策点 2** |
| 系统随机数 | `/dev/urandom` | `BCryptGenRandom`（CNG） | 两个分支都是操作系统级 CSPRNG；失败才回退 `std::random_device` |
| 密钥文件权限 | `stat()` + `S_IRGRP/S_IROTH` | 无权限位概念 | Windows 跳过该检查，文档提示用 NTFS ACL |
| 临时目录 | `/tmp/st_tests` | `%TEMP%/st_tests` | 测试改用 `testutil::tempDir()` |
| 控制台编码 | 终端本身 UTF-8 | 默认 GBK，中文日志乱码 | `SetConsoleOutputCP(CP_UTF8)` |
| 对比用的 OpenSSL | 1.1.1f（`libssl-dev`） | 3.6.5（MSYS2 `mingw-w64-x86_64-openssl`） | 性能对比工具两版都能编；3.x 对 `CMAC_*` 有弃用告警，已单独关闭 |
| 编译期警告 | — | MinGW 报 `namespace access` 与 `access()` 冲突、`<windows.h>` 的 `ERROR` 宏冲突 | 改名 `acl`；`#undef ERROR` |

**一个实际踩到的坑（与代码无关）**：在受限沙箱里运行 `alice.exe` 连接虚拟机时，
`connect()` 会直接失败并返回 `WSAEACCES (10013)`（"以一种访问权限不允许的方式做了一个访问套接字的尝试"）。
这不是程序缺陷也不是 Windows 防火墙：在正常（非沙箱）环境下同一条命令一次通过。
遇到 10013 时先确认是不是被沙箱/安全软件限制了出站套接字。

## 23.6 跨系统"双机"测试：Windows Alice ↔ Ubuntu Bob

这是迁移后的关键验证——**两台不同操作系统的机器之间**跑完整安全会话，
而不是同一台机器上的 loopback。拓扑：主机 `192.168.111.1`（VMnet8）↔ 虚拟机 `192.168.111.139`。

| 方向 | 命令 | 结果 |
| --- | --- | --- |
| A：Windows Alice → Ubuntu Bob | `alice.exe 192.168.111.139 9800 --quiet --whoami --file ... --image ...` | `alice_rc=0`；`SessionId = 8d06811d4dfb3c4a`；4 条消息 + 2 个文件/图像全部成功；应用层吞吐 **54.51 MB/s** |
| B：Ubuntu Alice → Windows Bob | `./alice 192.168.111.1 9801 --quiet --file ...` | `alice_rc=0`；`SessionId = 9b4aff3f40ee0f01`；4 条消息 + 1 个文件成功；应用层吞吐 **28.28 MB/s** |

两侧 `K_master` 指纹一致（`8409fd42b2df5cb3`），说明密钥预配置在两台机器上是对齐的；
接收端文件用 **sha256** 复核，与发送端**逐字节一致**：

```text
test_file_64KB.bin        5eb4ca70d0ee472b...  （VM 侧 received_lan/ 与主机侧 received_lan_win/ 均一致）
test_image_256x256.png    f8ea510fbcb5e006...  （VM 侧一致）
```

反方向（B）能成功也顺带说明：Windows 侧**不需要**为 `bob.exe` 单独放行入站规则，
因为 VMnet8 属于 VMware 虚拟网络，来宾到主机的这一条回程是通的。

## 23.7 与库实现的性能对比（Windows 侧，课程要求 5）

**环境**

| 项目 | 说明 |
| --- | --- |
| 机器 | 物理机：13th Gen Intel Core i5-1340P（Windows 主机，非虚拟机） |
| 编译器 | MinGW-w64 g++ 16.2.0，`-O3`（CMake `Release`，Ninja） |
| 对比库 | OpenSSL **3.6.5**（MSYS2 `mingw-w64-x86_64-openssl`） |
| CPU 能力 | **支持 AES-NI**（原来的 `/proc/cpuinfo` 检测在 Windows 上失效，本轮已修，见 §23.2） |

### 23.7.1 AES-128-CTR（默认：OpenSSL 使用 AES-NI）

| 数据大小 | 自实现(MB/s) | 库实现(MB/s) | 吞吐率比(库/自) |
| --- | --- | --- | --- |
| 1 KB | 132.2 | 1614.2 | 12.21x |
| 64 KB | 131.3 | 1857.1 | 14.15x |
| 1 MB | 129.6 | 3029.6 | 23.37x |
| 10 MB | 121.5 | 2599.9 | 21.39x |
| 100 MB | 121.3 | 2254.5 | 18.58x |

### 23.7.2 AES-128-CTR（`OPENSSL_ia32cap=~0x200000200000000`，禁用硬件加速，纯软件对纯软件）

| 数据大小 | 自实现(MB/s) | 库实现(MB/s) | 吞吐率比(库/自) |
| --- | --- | --- | --- |
| 1 KB | 140.1 | 522.6 | 3.73x |
| 64 KB | 132.5 | 500.9 | 3.78x |
| 1 MB | 127.5 | 525.9 | 4.13x |
| 10 MB | 131.4 | 571.5 | 4.35x |

### 23.7.3 CMAC

| 数据大小 | 自实现(MB/s) | 库实现(MB/s)（默认） | 吞吐率比 | 库实现(MB/s)（禁 AES-NI） | 吞吐率比 |
| --- | --- | --- | --- | --- | --- |
| 1 KB | 139.3 | 901.3 | 6.47x | 312.8 | 2.50x |
| 64 KB | 130.8 | 1951.4 | 14.92x | 390.5 | 2.93x |
| 1 MB | 140.7 | 1940.1 | 13.79x | 394.0 | 2.96x |
| 10 MB | 138.0 | 1912.6 | 13.86x | 398.6 | 2.93x |
| 100 MB | 118.5 | 1956.2 | 16.51x | — | — |

**结论与 Linux 侧完全一致**（机制上的结论，而不是巧合）：

1. 默认情况下库快 **12 ~ 23 倍**（AES-CTR）与 **6 ~ 17 倍**（CMAC）——
   差距主要来自 **AES-NI 硬件指令**；
2. 关掉硬件加速后差距缩小到 **2.5 ~ 4.4 倍**，这部分来自工程优化
   （汇编实现、多分组并行、查表/流水线），不是算法错误；
3. 正确性交叉验证在 Windows 上也一致：AES-CTR 密文 `a38b4e54…2521`、
   CMAC `070a16b4…287c` 与 OpenSSL **逐字节相同**——先证明"算的是同一个结果"，
   性能数字才有意义。

## 23.8 剩余工作与需要你决策的问题

**决策点 1（已决策并完成）：Qt 界面怎么装？**

主机上现有的 `D:\AppGallery\Qt\qt` **只是 Qt Creator 6.0.1 IDE**（自带 Qt 6 运行时 DLL），
没有头文件、没有 `qmake`、没有 CMake 的 Qt5/Qt6 配置包，**无法用来编译 `st_ui`**。
当时给出三条路线，**用户选择 A**：

| 方案 | 做法 | 代价 | 说明 |
| --- | --- | --- | --- |
| A（推荐） | MSYS2 装 `mingw-w64-x86_64-qt5` | 约 1 GB 安装体积，装在已有的 `D:\AppGallery\dev-tools\msys64`（D 盘，不需要管理员） | 与现有 g++ 16.2.0 **同一套 ABI**，CMake 里 `find_package(Qt5)` 直接可用，代码零改动 |
| B | 官方 Qt 安装器装 Qt 6 + MinGW 套件 | 需要登录 Qt 账号，几 GB | 会多出一套 MinGW，与 MSYS2 那套并存 |
| C | UI 保持在 Linux 演示，Windows 只交付命令行 | 0 | 课程要求 8 已在 Ubuntu 上完成并留了截图；但 Windows 上就不能演示界面 |

**执行结果（2026-10-01）**：已安装 `mingw-w64-x86_64-qt5`（Qt 5.15.19）到
`D:\AppGallery\dev-tools\msys64`；期间遇到镜像 404 与下载超时，
用 `pacman -Syy` + `--disable-download-timeout` 重试后成功（共尝试 1 轮即通过）。
CMake 重新探测后 `st_ui` 直接用 Qt5 构建，**代码零改动**。

**决策点 2（已决策：保持现状）：Windows 的监听端口要不要更严格？**

现在 Windows 上沿用 `SO_REUSEADDR`，好处是服务端重启后能立刻重新绑定同一端口；
代价是**同一台机器上的另一个进程可以抢占同一个端口**（Windows 的语义与 Linux 不同）。
如果更看重"端口不可被抢占"（安全课的角度），可以把 Windows 分支改成 `SO_EXCLUSIVEADDRUSE`；
代价是该端口处于 TIME_WAIT 时（例如刚结束一次会话就重启 Bob）需要等几分钟才能重新监听。
**用户选择保持现状**（`SO_REUSEADDR`），不改动。

**其它剩余项（都不阻塞交付）**

1. 中文文件名的 UTF-16 路径封装（`std::filesystem::u8path` 或 `_wfopen`）：现在路径已全部英文化，
   属于"稳健性增强"，不是必需；
2. Windows 侧打包发布（`windeployqt` 或静态链接）与"一键启动脚本"（`scripts/*.bat`）；
3. Wireshark 抓包证据（要求 6/7 的"窃听演示"）：主机装了 Wireshark，
   但需要图形界面操作，适合演示时现场录屏；
4. 全部跑通后再做 GitHub 提交（用户明确要求：**先跑通，再提交**）。

## 23.9 本轮的经验

1. **"能编译"和"能跑通"是两件事**：移植后代码一次编译通过、0 警告，
   但仍有 5 个测试失败——原因全在**测试代码写死了平台相关的路径与外部命令**
   （`/tmp`、`mkdir -p`）。跨平台化要连测试一起做。
2. **平台差异要写在文档里，而不是藏在 `#ifdef` 里**：`SO_REUSEADDR` 在 Windows 上
   是"允许抢占"，在 Linux 上是"允许复用 TIME_WAIT"，同名不同义；
   这类差异如果不说清楚，报告里被问到会答不上来。
3. **性能对比的"环境说明"本身就是结论的一部分**：本轮发现 `cpuAesCapability()`
   在 Windows 上读不到 `/proc/cpuinfo` 而误报"不支持 AES-NI"。
   如果不查这一点，就会把"库用硬件、我们纯软件"的 20 倍差距说成"实现水平差距"。
4. **迁移必须有反方向的回归**：Windows 全绿不代表 Linux 还活着；
   本轮两端各跑了一遍完整 `ctest` + 端到端演示，才算真正验证。

## 23.10 Windows 图形界面（M5）验证

**安装（方案 A）**

| 项 | 结果 |
| --- | --- |
| 包 | `mingw-w64-x86_64-qt5`（Qt **5.15.19**） |
| 位置 | `D:\AppGallery\dev-tools\msys64`（D 盘，与现有工具链同一套 ABI，未改动任何系统配置） |
| 踩的坑 | 首次 `pacman -Sy` 后部分包 404（镜像同步滞后）+ 一个包下载超时；改用 `pacman -Syy` + `--disable-download-timeout` 重试即成功 |

**构建**

```text
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release   → 已启用图形界面目标 st_ui（Qt 5.15.19）
cmake --build build-win -j8                                    → 0 error，0 warning
build-win/st_ui.exe（558 KB）
```

**运行前的一个必要条件**：`st_ui.exe` 依赖 `Qt5Core.dll / Qt5Gui.dll / Qt5Widgets.dll`，
直接双击运行会因为找不到 DLL 而启动失败（Windows 错误码 `0xC0000135`）。
两种做法：把 `D:\AppGallery\dev-tools\msys64\mingw64\bin` 加进 `PATH`，
或用 `windeployqt` 把 DLL 复制到 exe 旁边（见下面的剩余项）。

**自动化验证（不依赖人工点击）**

界面自带 `--auto`、`--send-text / --send-file / --send-image / --cmd` 等参数，
因此可以用两个实例跑完整会话：

```bash
export QT_QPA_PLATFORM=offscreen
./build-win/st_ui.exe --server --auto --port 9820 --out-dir experiment_data/received_ui &
./build-win/st_ui.exe --client --auto --host 127.0.0.1 --port 9820 \
    --send-text "Hello from Qt UI on Windows" \
    --send-file experiment_data/test_file_64KB.bin --cmd WHOAMI
```

实测结果：

```text
服务端：收到 HELLO → 发送 HELLO_ACK → AUTH 验证通过 → KEY_EXCHANGE 已发送
        → KEY_CONFIRM 验证通过 → KEY_CONFIRM_ACK 已发送（握手 7 步完整）
        [AccessControl] ALLOW alice(admin) send_message / send_file
        [Transfer] 已接收 文件 test_file_64KB.bin（65536 字节，1 块，CRC32 校验通过）
客户端：HELLO_ACK / AUTH / KEY_EXCHANGE / KEY_CONFIRM_ACK 全部验证通过
接收端文件 sha256 与源文件一致（5eb4ca70d0ee472b…）
```

**界面截图**：`docs/screenshots/windows_ui_client.png`（801×545，Windows 桌面会话中实际渲染）。
获取方式：脚本启动两个 `st_ui` 实例跑完一次会话后用 `PrintWindow` 抓取客户端窗口；
复现命令见 `docs/screenshots/README.md`。

**本轮发现的问题（已在本轮后续修复，见 §24）**：界面在**空闲**时按 250 ms 轮询接收，
每次超时都由 `Network` / `Session` 以 **ERROR** 级别打印一行
`recv() 超时，已接收 0/4 字节`（实测几秒钟就刷出 200+ 行）。
这是**迁移前就存在**的行为（`docs/ui.md` §8 已记录"250 ms 轮询"这一设计妥协），
不是 Windows 引入的。当时的三个备选改法是：

1. 在 `Network::receiveFrame()` / `SecureSession::receiveMessage()` 里把**超时**降为 DEBUG 级
   （真正的错误仍用 ERROR）；
2. 或给 `SecureSession` 增加一个"非阻塞尝试接收"接口，
   让界面不必靠超时来轮询（同时消除最多 250 ms 的消息延迟）；
3. 或仅在界面层静默（不改动网络/会话层）。

**用户选择第 2 条**，实现与实测结果见 §24。

---

# 24. 第九轮：给 SecureSession 增加"非阻塞尝试接收"，替换界面的超时轮询（2026-10-01）

## 24.1 问题

界面工作线程原先这样收数据：

```cpp
sessionConfig.ioTimeoutMs = 250;            // 把"接收超时"当成"没有数据"
...
if (!session.receiveMessage(type, body)) {
    if (isTimeoutError(session.lastError())) continue;   // 按错误文本猜是不是超时
    ...终止会话...
}
```

两个后果（都是这次实测量化出来的）：

1. **日志噪声**：每次超时都由 `Network` / `Session` 打一行 ERROR
   （`recv() 超时，已接收 0/4 字节`）。空闲几秒钟，客户端日志就涨到 **352 行**；
2. **消息延迟**：接收间隔 = 轮询间隔，对端消息最多晚 **250 ms** 才显示。

另外第 2 点还有个隐藏代价：`ioTimeoutMs` 同时被当成"数据阶段的读超时"，
为了界面流畅被迫设成 250 ms，一旦对端发包中途卡住，读操作会在 250 ms 就失败。

## 24.2 设计：分两层解决，不改协议语义

| 层 | 新增接口 | 作用 |
| --- | --- | --- |
| `Network` | `enum class WaitResult { kReadable, kTimeout, kError }`<br>`WaitResult waitReadable(int timeoutMs)` | 用 `select()` 探测"有没有数据可读"。**没有数据不算错误**：不打印日志、不动 `lastResult()/lastError()`；`timeoutMs == 0` 就是纯非阻塞探测 |
| `SecureSession` | `enum class ReceiveStatus { kMessage, kNothing, kClosed }`<br>`ReceiveStatus tryReceiveMessage(MessageType&, Bytes&, int waitMs = 0)` | 先 `waitReadable(waitMs)`：可读才走原来的 `receiveMessage()`（完整性、防重放、解密**只有这一处实现**）；没数据返回 `kNothing`，会话结束/出错返回 `kClosed` |

界面工作线程随之简化：

```cpp
constexpr int kIdleWaitMs = 100;     // 没有数据时，最多隔多久回头看一眼命令队列
constexpr int kIoTimeoutMs = 5000;   // 已确认可读之后，读满一个完整包的兜底超时
...
const auto status = session.tryReceiveMessage(type, body, kIdleWaitMs);
if (status == SecureSession::ReceiveStatus::kNothing) { continue; }
if (status == SecureSession::ReceiveStatus::kClosed)  { ...终止...; break; }
```

要点：

* **消息延迟不再由轮询间隔决定**——`select()` 在对端发出数据的那一刻就被唤醒；
  那个 100 ms 只影响"点击发送到命令被执行"的最坏延迟（原来这个值是 250 ms）；
* `ioTimeoutMs` 现在可以恢复成一个**正常的读超时（5 s）**，用于"包读了一半对端卡死"的兜底；
* 删除界面里那段"按错误文本猜超时"的 `isTimeoutError()` hack
  （`docs/ui.md` §8 里的已知妥协随之作废）；
* **协议、密码学、状态机、包格式一律未改**：`receiveMessage()` 保留原样，
  新接口只是它前面加了一道"有没有数据"的探测。

## 24.3 代码改动（4 个文件 + 2 个测试）

| 文件 | 改动 |
| --- | --- |
| `include/network/network.h` / `src/network/network.cpp` | 新增 `WaitResult` 与 `waitReadable()`（`select()`；Windows 下第一个参数填 0；POSIX 下 `+1`；`EINTR` 重试） |
| `include/security/session.h` / `src/security/session.cpp` | 新增 `ReceiveStatus` 与 `tryReceiveMessage()` |
| `apps/ui/session_worker.cpp` | 5.2 段改用 `tryReceiveMessage()`；删除 `isTimeoutError()`；`kPollTimeoutMs(250)` → `kIdleWaitMs(100)` + `kIoTimeoutMs(5000)` |
| `tests/unit/test_network.cpp` | 新用例：无数据 → `kTimeout`（且 `lastResult()` 仍为 OK、无错误文本）；有数据 → `kReadable`；对端关闭 → 仍报可读但 `receiveFrame()` 得到 `PEER_CLOSED`；未连接 → `kError` |
| `tests/integration/test_secure_roundtrip.cpp` | 新用例：`kNothing`（等待 60 ms 后返回、`lastError()` 为空、会话仍建立）→ `kMessage`（3000 ms 预算内 <1000 ms 返回，证明"数据一到就醒"）→ `kClosed`（对端关闭后 100 次探测内返回，且 `lastError()` 非空） |

## 24.4 实测结果（2026-10-01）

**Windows（MSYS2 MinGW-w64，g++ 16.2.0）**

```text
编译：0 error，0 warning
ctest：100% tests passed out of 16
test_network.exe            → ALL TESTS PASSED: 11/11（含新增 waitReadable 用例）
test_secure_roundtrip.exe   → ALL TESTS PASSED:  3/3（含新增 tryReceiveMessage 用例）
```

**界面同一场景前后对比**（两个 `st_ui` 实例：握手 + 短消息 + 64 KB 文件 + WHOAMI，跑完后再空转 5 秒）

| 指标 | 改前（250 ms 超时轮询） | 改后（`tryReceiveMessage`） |
| --- | --- | --- |
| 客户端日志行数 | 352 行 | **11 行** |
| 其中 "超时" 行 | 300+ 行 | **0 行** |
| 服务端日志行数 | 353 行 | **15 行** |
| 其中 "超时" 行 | 300+ 行 | **0 行** |
| 文件传输 | 65536 字节、CRC32 通过 | 65536 字节、CRC32 通过（不受影响） |
| 访问控制 | ALLOW / DENY 正常 | ALLOW / DENY 正常（不受影响） |

**Linux 回归（Ubuntu 20.04，g++ 9.4.0）**

```text
编译：0 error，0 warning
ctest：100% tests passed, 0 tests failed out of 16
Alice/Bob 演示：4 条测试消息全部成功
文件/图像传输：4/4 逐字节一致
```

## 24.5 仍然保留的取舍

1. 界面仍是"单线程 + 命令队列"结构：100 ms 的空闲等待意味着**命令执行最坏延迟 100 ms**
   （体积上比原来的 250 ms 更好；如果要做成真正的"事件驱动"，
   可以再加一个自管道/eventfd 唤醒 `select()`，但那属于额外复杂度，当前演示场景不需要）；
2. `waitReadable()` 只探测**连接 socket**：它不处理"监听 socket 上有没有新连接"，
   服务端仍然是 `acceptOneClient()` 一次性接受一个客户端（与命令行版一致）；
3. 对端关闭时 `select()` 也一样报"可读"，这是 TCP 的语义；
   调用方必须像界面那样把 `kClosed` 当作会话结束，而不是"有数据"。

---

# 25. 第十轮：Windows 打包分发与 Wireshark 窃听证据（2026-10-01）

## 25.1 为什么要打包

前面几轮跑程序都要先进 MSYS2 的 MinGW64 shell（或者手动把
`D:\AppGallery\dev-tools\msys64\mingw64\bin` 加进 `PATH`），否则会报
`0xC0000135`（找不到 DLL）。演示时不可能每次都开 MSYS2，所以需要一个
**双击就能运行**的目录。

新增脚本 **`scripts/package_windows.sh`**（在 MSYS2 MinGW64 shell 里运行）：

```bash
bash scripts/package_windows.sh            # → dist/securityTransfer/
bash scripts/package_windows.sh /d/demo    # 或指定输出目录
```

它依次做六件事：

1. `cmake --build build-win`（Release）；
2. 复制 `alice.exe` / `bob.exe` / `st_ui.exe`；
3. `windeployqt-qt5.exe` 部署 Qt5 DLL 与插件；
4. **依赖传递闭包**：反复扫描 dist 里所有 PE 文件的导入表，
   凡是 `D:\AppGallery\dev-tools\msys64\mingw64\bin` 里有的 DLL 就复制进来，
   直到不再出现新依赖；
5. 复制 `configs/`（**只带 `keys.conf.example`，不带真实密钥**）与 `experiment_data/`；
6. 生成 `run_bob.bat` / `run_alice.bat` / `run_ui.bat`（CRLF 换行）。

### 打包过程中踩到的三个坑（都写进了脚本注释）

| 坑 | 现象 | 处理 |
| --- | --- | --- |
| `windeployqt` 的临时目录 | 报 `Unable to query qmake: Error creating stdout temporary file` | 脚本把 `TMPDIR/TEMP/TMP` 指向 `build-win/package-tmp` |
| `windeployqt` 缺可选依赖就提前退出 | `libGLESv2.dll does not exist` 后返回非零码，`set -e` 直接中断 | 不因它中断；**但**它退出前没来得及复制插件，所以脚本加了 3.1 步校验并补齐 `platforms/qwindows.dll`（少了它 Qt 程序根本起不来） |
| Qt5 DLL 自己还缺 MinGW 运行时 | 只补 `libstdc++/libgcc/winpthread` 仍然 `0xC0000135`，因为 `Qt5Core` 还依赖 `icu*`、`zlib1`、`harfbuzz`、`pcre2`、`double-conversion`、`zstd`、`png16`、`md4c`… | 改成"依赖传递闭包"自动补齐，并加 4.1 步校验（MSYS2 里有、dist 里没有 = 真的缺） |

### 实测结果

```text
输出目录：dist/securityTransfer（75 MB，30 个 DLL + 3 个 exe + 插件目录 + 配置 + 数据）
4.1 依赖校验：所有非系统依赖都已打包

干净 PATH 测试（PATH 只留 C:\Windows\System32;C:\Windows，完全不依赖 MSYS2）：
  st_ui.exe --help          → 正常打印中文用法（说明 Qt 平台插件加载成功）
  bob.exe + alice.exe       → 完整握手 + 4 条消息 + 64 KB 文件，sha256 一致
```

> 注意：发布包**故意不带** `configs/keys.conf`（里面有 K_master）。
> 使用者需要把它复制成 `keys.conf` 并填好；`run_*.bat` 会先 `cd` 到包目录，
> 这样程序按 `configs/keys.conf` 就能找到密钥文件。

## 25.2 Wireshark 窃听证据（Windows + tshark）

### 为什么不在本机 loopback 上抓

更贴近课程描述的"经 Internet 传输"：让 **Bob 跑在 Ubuntu 621 虚拟机**里，
**Alice 跑在 Windows 主机**上，用 tshark 抓 **VMnet8**（主机 `192.168.111.1` ↔
虚拟机 `192.168.111.139`）这条真实链路的包。

### 新增工具

**`scripts/capture_eve_windows.py`**（Python，管理员运行，抓包需要 Npcap 权限）：

```powershell
python scripts/capture_eve_windows.py --file experiment_data/test_file_64KB.bin
python scripts/capture_eve_windows.py --local      # Bob 跑本机
python scripts/capture_eve_windows.py --analyze-only <已有的 pcapng>
```

它自己完成：自动选网卡（找 VMnet8）→ 用 vmrun 在虚拟机里后台启动 Bob →
`tshark -i <网卡> -f "tcp port 9850" -a duration:25 -w *.pcapng` 抓包 →
本机运行 Alice（4 条测试消息 + 1 个 64 KB 文件）→ 停止抓包 →
**按 `[4 字节长度][Packet]` 重组 TCP 流并逐包解出协议字段** →
在原始抓包字节里检索明文与密钥 → 写报告。

### 抓包结果（`experiment_data/captures/eve_9850_20261001_202422.pcapng`）

```text
75 帧 / 63 个带 TCP 载荷的段 / 解出 20 个 SecureTransfer 数据包
其中：加密业务数据包 13 个（DATA×4、FILE_START、FILE_CHUNK(65536)、FILE_END、CLOSE、以及 Bob 的确认）
      握手包 7 个（HELLO / HELLO_ACK / AUTH / KEY_REQUEST / KEY_EXCHANGE / KEY_CONFIRM / KEY_CONFIRM_ACK）
```

解出来的前 12 个包（节选）：

| # | 方向 | 类型 | SessionId | Sequence | Nonce（前 8 字节） | 密文长度 | 密文前 8 字节 | CMAC 前 8 字节 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | C→S | HELLO | ef199c594cf2d7c8 | 0 | 2adb67f64058a953 | 7 | `0005616c696365` | `0000000000000000` |
| 2 | C→S | AUTH | ef199c594cf2d7c8 | 0 | 2adb67f64058a953 | 0 | — | `678ad9c0b3bf9d5a` |
| 4 | C→S | KEY_CONFIRM | ef199c594cf2d7c8 | 0 | 2adb67f64058a953 | 0 | — | `73924a8441905349` |
| 5 | C→S | DATA | ef199c594cf2d7c8 | 1 | 9d63b294d2c2539a | 10 | `320969a169cbaff2f189` | `4cb47b5eea0fd92c` |
| 7 | C→S | DATA | ef199c594cf2d7c8 | 3 | 9d63b294d2c2539a | 75 | `75998111cfab0b1a5cad1f3524abad73` | `95c27357bb7c38ec` |
| 10 | C→S | FILE_CHUNK | ef199c594cf2d7c8 | 6 | 9d63b294d2c2539a | 65536 | `c37995a53ee578ad7a36b04d8d44b196` | `85573c62a5381b1c` |
| 11 | C→S | FILE_END | ef199c594cf2d7c8 | 7 | 9d63b294d2c2539a | 12 | `06592a5d3218c97c03a6914c` | `4a4535a06d6d59fd` |

**明文 / 密钥检索（在整个抓包文件的原始字节里）**

| 检索目标 | 命中次数 | 期望 |
| --- | --- | --- |
| `Hello Bob!` | 0 | 0 ✅ |
| `A secure message between Alice and Bob.` | 0 | 0 ✅ |
| `Transfer #1024` | 0 | 0 ✅ |
| `你好，Bob`（UTF-8） | 0 | 0 ✅ |
| 文件 `test_file_64KB.bin` 的前 64 字节 | 0 | 0 ✅ |
| `K_master`（`0f1e…e1f0`） | 0 | 0 ✅ |
| `K_session`（`000102…0f`） | 0 | 0 ✅ |

**一个需要如实说明的细节**：HELLO 的 Body 是
`00 05 61 6c 69 63 65` = TLV `"alice"`，也就是**握手阶段的身份标识是明文**
（此时还没有 K_session，身份要参与转录串与 CMAC，与 TLS 握手的身份信息同理）。
业务数据从 DATA 开始一律是密文——上表已用"明文检索 0 命中"证明。

结论：**Eve 能看到 TCP 包、Ciphertext、Nonce、Sequence、CMAC；看不到业务明文、
K_session、K_master**——与 `project_q1.md` §9.1 的预期完全一致。

完整报告（由脚本自动生成）与抓包文件都已入库：
`experiment_data/captures/eve_9850_20261001_202422.{pcapng,txt}`，
说明文档见 `docs/eavesdrop.md`。

## 25.3 仍然保留的取舍

1. `dist/` 里的 DLL 有 75 MB，**不入库**（重新跑一次脚本只要十几秒）；
2. 打包脚本目前只处理 MinGW/Qt5 这套工具链；如果以后要换 MSVC，
   需要额外复制 VC 运行时（`vcredist`）；
3. 抓包脚本默认连虚拟机里的 Bob（需要 VMware 与 vmrun）；
   没有虚拟机时用 `--local` 也能复现，只是抓的是本机回环。

---

# 26. 第十一轮：修复界面使用中的五个问题（2026-10-06）

用户在实际使用图形界面后反馈了 5 个问题，本轮逐一定位、修复并补了回归测试。

## 26.1 问题 → 根因 → 修法

| # | 现象 | 根因 | 修法 |
| --- | --- | --- | --- |
| 1 | 非最大化时"选项框文字只显示一半" | 默认窗口 1180×760 在小屏幕/被缩放桌面上会被压缩；布局在空间不足时把按钮压到 28 px（自身需要 34 px）；左列没有滚动区 | 默认尺寸改 1120×700、最小 960×640；每个输入控件的**最小高度 = 自身 `sizeHint().height()`**；左列放进 `QScrollArea`；历史/日志区垂直 `QSizePolicy::Ignored`，不再用内容撑大布局 |
| 2 | 只能传英文路径，中文路径发不出去 | Windows 上 `std::ifstream/ofstream/_mkdir` 的窄字符接口按 **ANSI(GBK)** 解释路径，而内部统一 UTF-8 | 新增 `openInputFile/openOutputFile`（Windows 先转宽字符）、`ensureDirectory` 改 `_wmkdir` 并跳过盘符、命令行参数经 `GetCommandLineW` 转 UTF-8 |
| 3 | 点"断开"后停在"正在结束会话…"，只能重启程序 | ① 服务端线程永久阻塞在 `accept()`，断开无效；② 主动断开时工作线程不发 `sessionStopped`，界面按钮永远不复位 | 新增 `Network::waitAcceptable()` 与 `SecureSession::acceptOneClient(waitMs)`（超时可重试、监听保持有效）；界面工作线程按 200 ms 分片等待并检查停止标志；退出循环时统一补发 `sessionStopped` |
| 4 | 日志里出现 `WSA error ...(乱码)` | `std::system_category().message()` 返回本地代码页（GBK）文本，被当 UTF-8 打印 | Windows 分支改用 `FormatMessageW` + 转 UTF-8，现在显示为 `WSA error 10061 (由于目标计算机积极拒绝，无法连接。)` |
| 5 | 是否支持两台主机通信 | 不是缺陷，是使用说明缺失 | 在 `docs/ui.md` §11.5 写清两台主机的用法（角色选择、对端地址、K_master 一致、防火墙放行），并指向既有实测记录 |

## 26.2 代码改动清单

| 文件 | 改动 |
| --- | --- |
| `include/common/text_encoding.h`（新）<br>`src/common/text_encoding.cpp`（新） | UTF-8 ↔ UTF-16 转换；`utf8CommandLine()`（Windows 用 `GetCommandLineW + CommandLineToArgvW`） |
| `include/common/path_utils.h` | 新增 `widePathForFileApi` / `openInputFile` / `openOutputFile`；`ensureDirectory` 支持中文路径与盘符 |
| `src/application/file_transfer.cpp`、`src/security/access_control.cpp`、`src/security/keystore.cpp`、`apps/alice/main.cpp` | 所有文件读写改用上面两个 helper |
| `apps/alice/main.cpp`、`apps/bob/main.cpp` | 命令行参数统一转 UTF-8 |
| `include/network/network.h` / `src/network/network.cpp` | 新增 `waitAcceptable()`；`describeError()` 的 Windows 分支改为 `FormatMessageW` + UTF-8 |
| `include/security/session.h` / `src/security/session.cpp` | `acceptOneClient(int clientWaitMs = -1)` + `lastAcceptTimedOut()`；重复调用时不再重复 `listen()` |
| `apps/ui/session_worker.cpp` | 服务端分片等待客户端（可被"断开"打断）；退出时统一补发 `sessionStopped` |
| `apps/ui/main_window.cpp/.h`、`apps/ui/main.cpp` | 布局加固（默认/最小尺寸、最小高度、左列滚动、文本区不撑布局）；新增 `--geometry WxH` 与 `--print-geometry` 诊断开关 |
| `tests/integration/test_file_transfer.cpp` | 新增「中文文件名与中文接收目录也能传输」 |
| `tests/integration/test_secure_roundtrip.cpp` | 新增「`acceptOneClient(超时)` 可被打断，且监听保持有效」 |
| `tests/unit/test_network.cpp` | 新增「连接失败的错误信息是合法 UTF-8」 |

## 26.3 实测结果

**布局**（用新增的 `--print-geometry` 让 Qt 自己报尺寸）：

```text
默认 1120x700：所有按钮/输入控件实际高度 >= 自身 sizeHint（按钮 34px、输入框 28px）
最小 960x640：同样满足——只有两个可滚动文本区低于 sizeHint（有意为之）
```

**功能回归**：

```text
Windows（MinGW-w64）：0 错误 0 警告，ctest 16/16
  test_network 12/12（含新用例）test_secure_roundtrip 4/4（含新用例）test_file_transfer 2/2（含新用例）
Linux（Ubuntu 20.04 / g++ 9.4）：0 错误 0 警告，ctest 16/16，Alice/Bob 演示 + 4 个文件/图像逐字节一致
界面端到端：两个 st_ui 实例，中文目录 + 中文文件名传输，接收文件 sha256 与源文件一致
错误文本：connect() 失败: WSA error 10061 (由于目标计算机积极拒绝，无法连接。)
```

## 26.4 保留的说明

1. `acceptOneClient(waitMs)` 的"超时"与"失败"必须分开看：超时（`lastAcceptTimedOut()`）
   说明监听还活着、可以继续等；失败才需要放弃并报错。命令行 Bob 仍用默认的"永久等待"，
   行为与旧版完全一致。
2. 中文路径的修复是**双向**的：不仅要能打开中文路径的文件，还要能创建中文目录、
   把中文文件名放进传输元数据（TLV 里本来就是 UTF-8 字节）——三处都验证过。
3. 界面布局的"根因"是小屏幕上窗口被压缩，因此**最小尺寸**是这次修复的关键；
   如果将来要在更小的屏幕上用，可以再调小 `setMinimumSize()`，或者把右列也改成可滚动。

## 26.5 补充修复：左列内容被静默裁切（同日）

用户在实机反馈"文字框正常，但最左侧那一栏的文字显示不出来"。用 `--print-geometry`
一测就清楚了：

```text
leftScroll  viewport=424 x 674   innerWidget=538 x 735   hScroll=0   innerMinWidth=538
```

左列内容的**最小宽度 538 px > 滚动区可视宽度 424 px**（最小窗口时只有 347 px），
而我上一版把横向滚动条设成了 `ScrollBarAlwaysOff` → 多出来的部分被**静默裁掉**。

修法：① `QFormLayout::WrapLongRows` 让长标签换行，左列最小宽度 538 → 338 px；
② 横向滚动条改回 `AsNeeded`（宁可滚动，也不静默裁切）；③ 左列最大宽度 450 → 560 px。

修复后实测：`innerWidget` 宽度 **等于** `viewport` 宽度（507/507、347/347、411/411），
左列不再有内容被裁；Windows 与 Linux 回归均为 0 错误 0 警告、`ctest` 16/16。

---

# 27. 第十二轮：CI 自动测试 + 服务端常驻化与抗拒绝服务（2026-10-06）

这一轮针对上一节"项目最大改进点"的两条：**验证自动化**与**服务端健壮性**。

## 27.1 起因：一个实测出来的真实拒绝服务面

上一轮结束时做过一次实验（`docs/review` 口述结论）：只用一个"连上就断开"的空连接，
就能让命令行 Bob **直接退出**：

```text
=== 场景 A：坏客户端连上就断开（不发任何数据）===
    坏连接后 Bob 还在运行吗: 否（已退出！）
Bob 输出：[ERROR] [Bob] 握手失败: 握手 HELLO 接收失败: recv() 返回 0 ...
```

根因是 `apps/bob/main.cpp` 为**单次演示**写的结构：只 `accept()` 一次，握手失败就
`return EXIT_FAILURE`。对课程演示够用，但作为"工具"是不能用的。

## 27.2 CI：每次提交都自动跑测试

原来只有 `.github/workflows/windows-ui.yml`（编译 + 打包，不跑测试）。
新增 **`.github/workflows/tests.yml`**：

| 任务 | 内容 |
| --- | --- |
| `linux-tests`（ubuntu-latest） | 安装 g++/cmake/ninja → 构建 → `ctest` → **端到端演示**（起 Bob、跑 Alice、发 4 条消息 + 64 KB 文件、`cmp` 逐字节比对） |
| `windows-tests`（windows-latest + MSYS2） | 安装 gcc/cmake/ninja → 构建 → `ctest` |

两条任务都**不装 Qt5 / OpenSSL**（`st_ui` 与性能对比工具会被 CMake 自动跳过），所以很快；
界面打包仍由 `windows-ui.yml` 负责。触发条件：push 到 main（源码/测试/CMake 变更）、PR、手动。

## 27.3 服务端常驻化 + 抗拒绝服务

### 改动一览

| 层 | 改动 |
| --- | --- |
| `Network` | 新增 `closeConnection()`（只关连接、保留监听）；新增 `setReadDeadlineMs()`（**整包读取期限**）；`applyTimeout` 记录当前配置超时；`listen()` 的 backlog 由 **1 → 8** |
| `SecureSession` | 新增 `closeConnection()`（会话状态复位、保留监听）；新增 `SessionConfig::handshakeDeadlineMs`（默认 15 s，**整次握手总时限**）；握手失败时只关连接、不再关监听（`state_` 回到 `kDisconnected`）；握手期间把剩余时限下发给 `Network`，数据阶段取消 |
| `apps/bob` | 主循环改成**常驻服务**：分片等待客户端（200 ms，可响应 Ctrl+C）→ 处理会话 → `closeConnection()` → 继续等；新增 `--once`、`--max-sessions N`、`--help`；`SIGINT/SIGTERM` 优雅退出；失败限流（"真正占用过服务端的失败"才暂停 200 ms） |
| 脚本 | `verify_in_vm.sh` / `capture_eve.sh` / `lan_test.sh`（netns）/ `ui_demo.sh` / `capture_eve_windows.py` 里"起 Bob 后等它退出"的地方统一加 `--once`；`lan_test.sh --server` 与 `run_bob.bat` 保持常驻 |

### 为什么需要"整包读取期限"

`SO_RCVTIMEO` 只限制"两次 recv 之间没有数据"的等待。攻击者只要**每个字节间隔都比超时短**
（例如每 3 秒发 1 字节），`readExact()` 里的循环就一直有数据可读，**握手总时限也拦不住**，
服务端会被无限拖住。所以 `SecureSession` 在握手阶段把"剩余总时限"通过
`Network::setReadDeadlineMs()` 下发，`readExact()` 每轮 recv 前把超时收紧到剩余期限，
期限一到就返回 `TIMEOUT`。

## 27.4 新增测试

| 测试 | 断言 |
| --- | --- |
| `closeConnection() 后同一 SecureSession 可继续服务下一个客户端` | 第一次会话正常结束 → `closeConnection()` → 第二个客户端仍能完成握手与收发（监听没被关掉） |
| `慢速握手会被整包读取期限掐断` | 假客户端先发合法包头、再每 150 ms 只发 1 字节 → 服务端在 **< 3 s** 内失败（而单次 recv 超时设的是 8 s），错误信息含"期限/超时" |

## 27.5 实测结果（Windows，2026-10-06）

```text
构建：0 错误 0 警告；ctest：16/16 通过（test_secure_roundtrip 现在 6 个用例）

抗 DoS 实测（常驻 Bob）：
  连发 20 个"连上就断"的空连接 → 全部被接受，Bob 仍然存活 ✅
  紧接着连续 3 次正常会话         → 全部成功（退出码 0）✅
  Bob 日志末尾：handshake(ok/fail)=3/20，服务继续监听 ✅

--once 兼容性：只服务一个客户端后退出，退出码 0 ✅（脚本/测试仍按老方式工作）
```

对照组（改动前）：单个空连接就让 Bob 退出 ❌。

## 27.6 保留的取舍

1. 服务端是**顺序服务**（一次一个会话）：简单、可预测；`backlog=8` 用来排队等待的客户端。
   要真正并发可以再引入"每连接一个线程"，但会牵动 `AccessController`（审计日志）等共享状态的加锁，
   属于更大的改动，本轮不做。
2. 限流是"软"的：只对**占用过服务端**的失败暂停 200 ms。
   连上就断的洪泛本身几乎不耗时，直接继续服务；真正的资源占用已被"握手总时限 + 整包读取期限"锁死。
3. `handshakeDeadlineMs` 默认 15 s：足够正常握手（本地实测 < 50 ms），也不会让慢速攻击者占用太久。

---

# 28. 第十三轮：性能对比扩展到 Mbed TLS 与 Botan（2026-10-07）

## 28.1 目标

课程要求 5 是"与库文件**或别人的代码实现**做全面对比"。上一轮只有 OpenSSL 一个库，
本轮按用户决策补齐：

* **B 方案**：同时加入 **Mbed TLS**（嵌入式/小体积代表）与 **Botan**（现代 C++ 代表）；
* **纯软件对照（方案 b）**：不只对比"默认配置"，还要给出"纯软件对纯软件"的数据；
* **汇总表**：把多次运行合并成一张倍率总表；
* **只做 Windows**：环境是 MSYS2/MinGW-w64（不做 Ubuntu 侧）。

## 28.2 工具重构：从"两个实现"变成"多后端"

原先 `tools/crypto_benchmark.cpp` 是单文件、只认识 OpenSSL。现在拆成：

| 文件 | 作用 |
| --- | --- |
| `tools/bench_backend.h` | 后端接口：一个 `Backend` = 名字 + 加速说明 + `aesCtr()` + `cmac()` |
| `tools/bench_backend_self.cpp` | 自实现（第一部分成果） |
| `tools/bench_backend_openssl.cpp` | OpenSSL（`EVP_aes_128_ctr` + `CMAC_CTX`） |
| `tools/bench_backend_mbedtls.cpp` | Mbed TLS（`mbedtls_aes_crypt_ctr` + `mbedtls_cipher_cmac`） |
| `tools/bench_backend_botan.cpp` | Botan（`AES-128/CTR-BE` + `CMAC(AES-128)`；需 C++20） |
| `tools/crypto_benchmark.cpp` | driver：计时、正确性交叉验证、分后端表、**汇总表**、CSV 导出 |
| `tools/bench_merge.py` | 把多次运行的 CSV 合并成汇总表（Markdown） |
| `scripts/run_benchmarks.sh` | 一键：跑默认组 + 纯软件组 + 生成汇总表 |

要求 4 仍然守住：这些库只被"对比工具"链接，系统本体一行都没碰。

## 28.3 纯软件对照（方案 b）怎么做出来的

三个库关闭硬件加速的方式不同（这也是本轮最有信息量的部分）：

| 库 | 硬件支持的形式 | 关闭方式 |
| --- | --- | --- |
| OpenSSL | 运行时按 CPUID 选择 | 环境变量 `OPENSSL_ia32cap=~0x200000200000000`（同一份二进制即可） |
| Mbed TLS | 编译期宏 `MBEDTLS_AESNI_C` | 用自定义配置头（注释掉该宏）重新编译 `library/*.c` → `libmbedcrypto_noaesni.a` |
| Botan | 构建时启用的模块 `aes_ni` / `aes_vaes` | 源码构建：`--minimized-build --enable-modules=aes,cmac,ctr,modes --disable-modules=aes_ni,aes_vaes --cc=gcc --build-targets=static` |

两个自建库放在 `D:\AppGallery\dev-tools\libs\{mbedtls-noaesni,botan-noaesni}`；
CMake 通过 `-DST_BENCH_SOFT_ROOT=...` 生成第二个可执行文件 `crypto_benchmark_soft.exe`，
与默认的 `crypto_benchmark.exe` **同一份源码**，只有链接的库不同 → 口径一致。

## 28.4 实测结果（Windows / i5-1340P / MinGW-w64 g++ 16.2）

**正确性交叉验证（比性能之前先做）**：自实现、OpenSSL 3.6.5、Mbed TLS 3.6.7、Botan 3.13.0
四方的 AES-CTR 密文与 CMAC **逐字节一致** ✅ —— 说明 CTR 端序（Botan 用 `CTR-BE`）与
CMAC 参数都对上了，性能数字可比。

**AES-128-CTR 1 MB（吞吐率 MB/s，括号为相对自实现倍率）**：

```text
自实现          135.1
OpenSSL 硬件   5926.3（43.9x）    OpenSSL 软件    648.4（4.8x）
Mbed TLS 硬件  1212.1（9.0x）     Mbed TLS 软件   400.4（3.0x）
Botan 硬件     4784.3（35.4x）    Botan 软件      153.3（1.13x）
```

**CMAC 1 MB**：

```text
自实现          140.8
OpenSSL 硬件   2040.8（14.5x）    OpenSSL 软件    403.9（2.9x）
Mbed TLS 硬件  1120.3（8.0x）     Mbed TLS 软件   330.6（2.4x）
Botan 硬件      971.1（6.9x）     Botan 软件       71.1（0.52x）
```

## 28.5 结论（写进报告的三条）

1. **数量级差距来自硬件加速**：同一个库关掉 AES-NI 后，OpenSSL 从 ~5900 掉到 ~650 MB/s
   （≈9 倍），Mbed TLS 从 ~1200 掉到 ~400（≈3 倍）。
2. **"是库"不等于"快"**：都用 AES-NI 时，OpenSSL/Botan 能到 3900~5900 MB/s，
   而 Mbed TLS 只有 ~1200 —— 因为它按"一次一块"调用 AES-NI，没有做多块并行/流水线。
   这条对比最有说服力：**瓶颈在实现方式，不在"是不是第三方库"**。
3. **我们的实现处在"合格的通用软件实现"水平**：纯软件对纯软件时，
   比 OpenSSL 慢 4.8~5.0 倍、比 Mbed TLS 慢 2.9~3.0 倍，但**与 Botan 的通用软件路径持平**
   （AES-CTR 1.11~1.14x；CMAC 上我们比它快约 2 倍）。差距来自查表/多块并行/汇编等工程优化。

## 28.6 产物与复现

* 原始数据（已入库）：`experiment_data/benchmarks/{bench_hw.log,bench_hw.csv,bench_sw.log,bench_sw.csv,summary.md}`
* 报告章节：`docs/performance.md` §9（环境、方法、汇总表、纯软件怎么来的、复现命令）
* 一条命令复现：`bash scripts/run_benchmarks.sh [--max-mb N]`

## 28.7 保留的取舍

1. **Botan 在 Windows 是 3.13，要求 C++20**：只给对比工具这一个 target 开了 C++20，其余代码仍是 C++17；
2. 纯软件版的 Mbed TLS/Botan 是**我们自己构建**的（`-O3`），发行包的具体编译参数未知，
   报告中已标注构建方式；比较"库的软件路径"时两者优化级别一致（都是 -O3）；
3. 本轮只做 Windows（用户决策）；Linux 侧仍保留第 8 节的历史数据，口径与本节一致。

---

# 29. 第十四轮：图形界面改版（2026-10-09）

## 29.1 起因

界面在"能用"之后暴露出两个层次的问题：

1. **观感**：课本式参数面板——所有参数（含密钥路径、审计日志路径）摊在主界面，
   没有信息层级，不像一个真实桌面软件；
2. **"安全过程"不可见**：握手是黑盒（只有一行"已建立"），Eve 攻击演示只知道自己发了包，
   看不到"对端倒在哪一关"。

因此本轮按 `docs/SecureTransfer_UI改造草图.html` 做整体改版。**计划与决策记录**
（含 6 处事实修正与 3 条强制约束）原在 `docs/ui_redesign_plan.md`，
2026-10-12 已归档合并进 [`ui.md`](ui.md) §12（决策记录）与 §12.2（强制约束）。

## 29.2 内核改动（纯增量，2 处）

两处都**不改数据包格式、不改线上字节、不改分层方向、不影响既有测试断言**：

| 改动 | 位置 | 作用 |
| --- | --- | --- |
| `enum class RejectGate` + 访问器 | `include/security/session.h`、`src/security/session.cpp` | 记录"最近一次被拒绝倒在哪一关"（①帧 ②格式 ③SessionId ④方向 ⑤类型 ⑥重放 ⑦CMAC ⑧状态机）；纯进程内信息，不上网、不参与 MAC |
| `SessionConfig::onHandshakeStep` | 同上 | 握手每推进一步回调一次（step 1..7）；步骤中文名由界面侧映射，内核不发文案 |

11 处拒绝点各自紧跟一行 `lastRejectGate_ = ...`；`recvPacket()` / `receiveMessage()`
入口先置 `kNone`（保证"成功接收 → 读到的一定是 kNone"，不会读到陈旧值）。

**新增测试** `tests/unit/test_reject_gate.cpp`（4 条断言）：
篡改 → `kMac`；重放 → `kReplay`；改 SessionId → `kSessionId`；
连续两次不同拒绝 → 第二次读到的是第二个关卡。
`ctest` 由 16 个增加到 **17 个，全部通过**。

## 29.3 攻击回执 ATTACK-REPORT

原来"攻击端"看不到对端判定（对端拒绝后直接断连）。现在受害端在终止会话前**回一条回执**：

```text
Alice(攻击端)                         Bob(受害端)
  │ 篡改包 / 重放包 ─────────────────▶ │ CMAC 失败 / 判定重放（state 仍为 ESTABLISHED）
  │ ◀──── ATTACK-REPORT: ⑦ CMAC … ────┤ ★ 终止前回执 + 写 attack_log.txt
  │ 界面：动作 → 关卡 → 结果          │
```

* 回执是普通 `DATA` 报文，走既有安全通道，**不新增任何协议消息类型**；
* `"ATTACK-REPORT"` 已加入 `include/common/demo_reply.h` 白名单
  （否则会重演第六轮那个 3.4 万条消息的自动回复死循环）；
* 回执发送失败**只记 DEBUG**，不弹窗、不刷 ERROR；
* 攻击留档写到**独立文件** `experiment_data/attack_log.txt`，
  不混进访问控制审计（语义不同）。

实测（命令行 `bob.exe` 作受害端 + `alice.exe --attack tamper|replay` 作攻击端，
端口 9911 / 9912 各跑一轮）：篡改 → 对端判定 `⑦ CMAC 完整性校验失败`；
重放 → `⑥ 序号重放（防重放拦截）`；Alice 打印"对端判定: ATTACK-REPORT…"，
Bob 打印"已向对端回执…"，`attack_log.txt` 追加 2 行，双方退出码 0，**无死循环**。
（图形界面的等价演示见 `docs/ui.md` §12；`tests/test_tamper.cpp`、`tests/test_replay.cpp`
另外覆盖了协议层行为。）

## 29.4 界面改动

| 区域 | 改版后 | 关键点 |
| --- | --- | --- |
| 标题条 | 左 "SecureTransfer" / 右 状态灯 + 状态文字 | 状态灯按"未连接/连接中/已建立/已结束"换色 |
| 工具条 | [连接][断开] │ [发送文件][发送图像][查询身份][审计日志] … [高级设置…] | 常用动作一屏可达 |
| 左栏（可滚动） | 会话状态 / **握手 7 步进度** / 连接设置 | 小窗口下滚动而不是压扁控件 |
| 中栏 | 短消息（气泡）/ 文件图像传输 / **Eve 攻击面板** | 攻击面板做成"动作 → 拦截关卡 → 结果"三段式 |
| 右栏 | **统计 2×2 数字块**（收包/发包/拒绝/吞吐）/ 运行日志 | 日志分级着色 + 级别/关键字过滤 + 导出 |
| 状态栏 | 端口 ｜ AES-128-CTR + CMAC ｜ 会话时长 ｜ 就绪 | 会话时长由 `QTimer` 每秒刷新 |

**主题**：`apps/ui/app_theme.h` 内嵌 QSS（浅色扁平，取值全部来自草图），
语义色集中一处，界面代码不再散落硬编码色值。
不引入 `.qrc`/`Qt5::Svg`，图标一律用 `QStyle::standardIcon()` → 打包零额外依赖。

**必须遵守的一条**（否则"文字只显示一半"会复发）：
QSS 会改变控件的 `sizeHint`，而防回归机制是"最小高度 = sizeHint 高度"，
所以 **QSS 必须在创建任何控件之前应用** —— `apps/ui/main.cpp` 里
`QApplication` 构造之后、`MainWindow` 构造之前调用。

## 29.5 顺带核对的一个历史缺陷（乱码）——结论：无需再改

本轮开工时怀疑"日志里的中文系统错误信息会乱码"（用户曾反馈的问题 4）仍然存在，
于是先在 UI 边界加了一层"UTF-8 优先、失败退回 `fromLocal8Bit`"的解码兜底。

随后核对 `src/network/network.cpp` 发现：**该缺陷已于 2026-10-06 修好**——
`describeError()` 的 Windows 分支改用 `FormatMessageW` 取宽字符再转 UTF-8
（见 `docs/ui.md` §11.4），实测控制台输出为
`connect() 失败: WSA error 10061 (由于目标计算机积极拒绝，无法连接。)`，不再乱码。

因此**回退了那层多余的兜底代码**（最小修改原则：不引入"修不了任何东西"的防御代码）。
记录在这里，是为了避免下一轮重复排查同一个问题。

## 29.6 实测结果（Windows / MSYS2 MinGW-w64 / Qt 5.15.19）

| 项 | 结果 |
| --- | --- |
| 编译 | 0 error / 0 warning（`-Wall -Wextra`） |
| `ctest`（Windows / MinGW-w64） | **17 / 17 通过** |
| Linux 回归（Ubuntu 20.04 虚拟机 / g++ 9.4 / **Qt 5.12.8**） | 配置识别到 Qt 并启用 `st_ui`；编译 **0 error / 0 warning**，`st_ui` 成功链接；`ctest` **17 / 17 通过** |
| 布局回归 | `--print-geometry`（默认 1180×720 与最小 1040×660）：所有控件 `height ≥ sizeHint`，左栏 `hScroll=0`、内容宽 227 ≥ 最小需求 160 → **无横向裁切** |
| 双窗口演示 | 图形界面作为服务端 + 作为客户端各自完成完整会话（短消息 + 1 MB 文件 + 图像 + WHOAMI），双方 ESTABLISHED |
| 截图 | `docs/screenshots/ui_redesign_server.png`、`ui_redesign_client.png`（2186×1466，`PrintWindow` 抓取） |

## 29.7 与草图的偏差（有意为之，需要知道）

1. **连接参数的位置**：计划 §5.3 曾写"角色/对端地址/端口放进工具条"，
   但草图的工具条只放动作按钮、把连接设置放在左栏卡片里。
   实机是 **200% 缩放、逻辑分辨率仅 1080×720**，把三个参数塞进工具条会让工具条
   超过窗口宽度 → 按钮被压扁（正是本轮要消灭的问题）。
   因此**按草图**：参数留在左栏"连接设置"卡片，工具条只放动作按钮。
   主界面与高级设置的**字段划分不变**（对端身份与 4 个路径项仍在高级设置里）。
2. **日志分级**：计划 §5.5 设想由 worker 新增结构化 `logEntry(level, text)` 信号；
   实际实现改为 **UI 侧集中解析前缀**（`classifyLogLevel()` 一个函数）。
   行为等价、改动面更小；将来若要升级为结构化信号，只需替换这一个函数。
3. **消息气泡**：草图画了左右气泡，实现为 `QTextEdit` 富文本
   （本端蓝底右对齐、对端灰底左对齐）。未做头像与时间戳。

## 29.8 仍然保留的取舍

1. **拒绝即终止会话**（第二轮起的行为，未改）：一次攻击后需要重新建链才能再次演示；
2. **图像缩略图预览不做**（用户决策 O3）；
3. `QTextEdit` 气泡是"高亮文本"而非带内边距的圆角气泡——Qt 富文本对 CSS 子集支持有限；
4. 协议文档 §6.3 已按本轮实现改写（见 `docs/protocol.md`），
   其中"静默丢弃"的描述与实现不符，属历史遗留的措辞问题。

## 29.9 本轮的经验（值得写进复盘）

1. **QSS 与 sizeHint 的顺序**：Qt 里"先应用样式再建控件"不是风格问题，而是正确性问题；
2. **跨编码边界的文本**：Win32 系统错误消息是本地编码，任何"核心层→Qt"的字符串都要过一道
   编码判定，否则中文系统上必然乱码；
3. **"看不出来"的功能没人用**：把握手 7 步与攻击拦截关卡画出来之后，
   安全机制才真正"可演示"——这正是课程要求里"使安全操作对用户透明"的落点。

---

# 30. 第十五轮：真实链路中间人（MITM）与 Eve 面板升级（2026-10-10）

## 30.1 为什么要做

在此之前，项目里所有的"攻击演示"（`alice --attack`、界面上的篡改/重放按钮）
本质都是**通信端点自己构造攻击包、用自己的连接发出去**
（`SecureSession::sendRawWireForTesting`）。安全结论没错——对端确实拒了——
但它证明的是"收包方会校验"，而不是"链路上的第三方攻不进来"。
答辩时很容易被问一句："这是你自己改自己的发送路径吧？"

本轮把攻击者换成**独立进程**：它坐在两端之间，两端都只把它当普通对端。

```text
Alice ──connect──▶ [ eve 中继 :9400 ] ──connect──▶ Bob :9000
                     （没有任何密钥）
```

## 30.2 实现

| 文件 | 作用 |
| --- | --- |
| `include/attack/mitm_relay.h`、`src/attack/mitm_relay.cpp` | 中继核心：裸 socket 双工转发 + 篡改/丢弃/延迟/重放注入；帧解析复用 `Frame`/`Packet` |
| `apps/eve/main.cpp` | 命令行外壳：参数解析、stdin 命令（`tamper/drop/delay/replay/status/quit`）、结构化 stdout |
| `apps/ui/mitm_controller.{h,cpp}` | 界面侧用 `QProcess` 拉起中继、下发命令、解析 stdout、原始日志落盘 |
| `tests/integration/test_mitm.cpp` | 同进程内起 Bob + 中继 + Alice 的集成测试（4 条用例） |

**不变量**：不改协议、不改字节格式、不新增消息类型；中继不实现任何密码学逻辑，
也不能解密或冒充——它只会"转发"和"破坏"，而破坏必然被协议检测到。

## 30.3 实测（Windows / MSYS2 MinGW-w64）

| 轮次 | 中继动作 | 受害端（Bob）的反应 | 命中关卡 |
| --- | --- | --- | --- |
| 1 | 篡改第一条业务数据 | `CMAC verification failed - Message rejected` | **⑦ CMAC** |
| 2 | 把刚转发的数据包再发一遍 | `Replay Attack Detected: 序号 1 不大于已接收的最大序号 1` | **⑥ 防重放** |
| 3 | 丢掉第一条业务数据 | `recv() 超时，已接收 0/4 字节` → 会话终止 | 拦不住（可用性） |

累计：`reject(format/replay/mac/state)=0/1/1/0`，`handshake(ok/fail)=3/0`。
其中**纯中继**（不做任何破坏）时会话完全正常建立、文件 CRC32 校验通过——
这说明协议不依赖链路可信，中间人在链路上并不等于能攻破会话。

## 30.4 必须写进报告的 limitation

**丢弃 / 延迟这类可用性攻击，密码学防不住**：接收方只能靠超时判失败、重新建链。
我们选择如实写出来（`docs/eve_mitm.md` §5），而不是假装防住了。

## 30.5 本轮踩到的两个真实坑

1. **Windows 端口占用**：Windows 允许 `0.0.0.0:P` 与别人的 `127.0.0.1:P` 同时绑定，
   而发往 127.0.0.1 的连接会被更具体的绑定抢走。本机 `9430` 被另一个服务占着，
   于是中继"显示 LISTEN 成功、却一个连接都收不到"，客户端连上后收到的
   竟是那个服务的 HTTP 响应。现在中继在绑定前会先探测 `127.0.0.1:P` 是否已有活监听，
   冲突直接报错，不再出现"看起来成功"的失败。
2. **中继进程不退出**：图形界面用管道喂命令，主线程若阻塞在读 stdin 上，
   就永远发现不了"连接已断"，进程赖着不走、端口不释放，下一次演示撞上"端口被占用"。
   现在 stdin 由独立线程读取，主线程只盯连接状态。

## 30.6 界面侧（U1–U5、U7）

| 项 | 内容 |
| --- | --- |
| U1 | **八关流水线**：①帧 ②格式 ③SessionId ④方向 ⑤类型 ⑥重放 ⑦CMAC ⑧状态机，命中即高亮 |
| U2 | **数据包检查器**：逐包显示 Eve 能看到的字段（密文/Nonce/Sequence/CMAC…）+ 能看到/看不到清单 |
| U3 | **攻击历史表 + CSV 导出**（带 BOM，Excel 不乱码） |
| U4 | **一键重新建立会话**（中间人模式下自动换一个新的中继进程） |
| U5 | **来源/方式/目标下拉**：中间人支持篡改/重放/丢弃/延迟并可指定第 N 个包；端点视角只支持篡改/重放 |
| U7 | **一键攻击剧本**：篡改 → 重放 → 丢弃，自动重启中继、重连、发探针、归档（命令行 `--scenario`） |

中栏改为**可拖拽的垂直分栏**，Eve 面板内容多时可自己拖大。
命令行等价物：

```bash
./bob.exe 9930 --quiet --out-dir experiment_data/received &
./st_ui.exe --scenario --relay-listen 9400 --relay-target 9930
```

## 30.7 测试与产物

* `ctest` 由 17 个增加到 **18 个**（新增 `test_mitm`，4 条用例：纯中继 / 篡改 /
  丢弃 / 重放）；
* **两个平台各跑一遍**：Windows（MinGW-w64 / Qt 5.15.19）18/18、0 告警；
  Ubuntu 20.04（g++ 9.4 / Qt 5.12.8）18/18、0 告警。Linux 侧首次构建暴露出三个
  只有该平台才会犯的错，已修：缺 `<fcntl.h>`；`send()` 对已断开连接触发 `SIGPIPE`
  把测试进程直接打死（现统一带 `MSG_NOSIGNAL`）；`eve` 目标没链接 `Threads::Threads`
  （`undefined reference to pthread_create`）——这正是"每轮都要跑一次 Linux 构建"
  这条回归红线的价值；
* 证据文件：`experiment_data/relay_log.txt`（中继原始输出）、
  `experiment_data/attack_log.txt`（受害端留档）、界面「攻击历史」导出的 CSV、
  截图 `docs/screenshots/ui_mitm_attack.png`；
* 发布包新增 `eve.exe`（`scripts/package_windows.sh` 与 CI 自动带上）。

## 30.8 保留的取舍

1. 中继一次只服务一条连接（演示够用；长期驻留需改成 accept 循环）；
2. "第 N 个包"只对中间人模式有效；
3. 延迟固定 800 ms；
4. 端点的 篡改/重放 演示**保留**（它证明的是"收包方会校验"，
   与中间人证明的"第三方攻不进来"是两件事，报告里分开陈述）。

---

# 31. 第十六轮：按使用反馈修界面（2026-10-12）

## 31.1 一条原则：先把问题量出来，再改

这一轮的起点是三个"用起来不对劲"的反馈。为了让它们可验证、可回归，先给
`--print-geometry` 加了一段**逐页签布局自检**：

* 逐个把页签切到前台再量（隐藏页签里控件的 `width` 是陈旧值，直接检查会漏报）；
* 打印每个页签/主窗口的"实际尺寸 vs `minimumSizeHint`"；
* 检查三类"文字承载控件"：单行 `QLabel`/按钮（`width < sizeHint`）、
  **自动换行的 `QLabel`（`height < heightForWidth(width)`）**、`QComboBox`
  （统一设了 `AdjustToContents`，`sizeHint` 即当前项所需宽度）。

第二条是这次新增的关键判据：Qt 把换行标签的最小高度算成"一行"，
所以布局可以合法地把它压成一行高，**第二行直接看不见**——
这正是"文字显示不全"的另一种形态，原先的检查完全覆盖不到。

## 31.2 问题一：文字压缩、显示不全

**实测（修复前）**：

| 对象 | 实际 | 最小需求 | 结论 |
| --- | --- | --- | --- |
| 主窗口 | 1082 × 684 | 1011 × **791** | 高度缺 ~107px |
| 页签「中间人链路」 | 516 × 176 | 397 × **282** | 缺 106px，检查器/日志被裁 |
| 「方式」下拉 | 宽 58 | 需要 60 | 末字被裁 |
| 攻击者视角提示行 | 高 28 | 需要 42 | 第二行被裁 |

**根因有两层**：① 本机 200% 缩放，逻辑桌面只有约 1080×720，窗口最高约 705px，
而布局最小需求是 791px —— 怎样都放不下；② `setMinimumSize(1040, 660)` 写死的最小值
小于布局真实最小需求，等于允许"窗口比内容还小"，把矛盾藏了起来。

**修法（三条一起）**：

1. 页签内容统一包进 `QScrollArea(setWidgetResizable(true))`：放不下就滚动，
   而不是把控件压到最小高度以下 → 页签最小需求 282 → 57，主窗口布局最小高度 791 → **566**；
2. 降低文本框最小高度：检查器 72→48、中继日志 52→36、历史表 96→64；提示行并成一行；
3. 下拉框统一 `AdjustToContents`，长文案缩短（"中间人（Eve 中继）"→"中间人"），
   完整解释移入 tooltip。

**修后自检**（默认 1180×720 与最小 1040×660 两种尺寸）：主窗口与三个页签全部
`[OK] 没有文字被压缩`。

## 31.3 问题二：攻击目标太死板

原来是写死的 `下一个 / 第5 / 第6 / 第7 / 第8 / 第10 个包`。现在改成**"打哪一类包"**：

| 界面选项 | 中继命令 |
| --- | --- |
| 下一个包 | `tamper --dir c2s` |
| 下一条短消息 | `tamper --type DATA --dir c2s` |
| 下一个文件块 | `tamper --type FILE_CHUNK --dir c2s` |
| 最近一条短消息（捕获-篡改/重发） | `tamper --last --type DATA --dir c2s` |
| 指定第 N 个包 | `tamper --index 7 --dir c2s` |

实现：中继把"打哪个包"抽象成 `MitmTarget{index, type, lastOfType}`——
按类型匹配在转发路径上判断（握手包不会被误伤）；`lastOfType` 则走"立即注入"，
由控制线程拿缓存里的"最近一条该类原始包"（每个方向 × 每种类型各留一份）改完再发。
缓存为空时不静默失败，而是回 `ERR target=last-DATA：还没有已转发的该类包…`。
丢弃/延迟与"最近一条"组合会被明确拒绝（那个包早转发过去了）。

## 31.4 问题三：Eve 端只显示"攻击已 ok"

这是**设计要的性质**，不是缺陷：判定发生在受害端进程内部，受害端的处置/回执是发给
**合法对端**的、走加密通道，攻击者只能看到密文；连接随后被关闭这件事她能观察到，
但看不出原因。若攻击者能拿到"接受/拒绝"的反馈，就相当于得到 oracle，
可以据此二分猜测 —— 所以"攻击者拿不到判定"本身就是安全属性。

但**措辞确实有毛病**：`result=ok` 会被读成"攻击成功"。本轮改为：

* `result=injected`（已注入），并在末尾注明"对端是否接受由受害端掌握"；
* 攻击页签常驻一行提示（完整解释在 tooltip）；
* 攻击历史"结果"列写"已注入（判定未知）"；
* 连接结束时补一行可观察事实：

```text
OBSERVE attacker_view=injected_only injected=1 closed_after_last_inject_ms=1 \
        note=连接在注入之后被关闭（是否因为被拦下，Eve 无从得知；判定只发生在受害端）
```

三轮实测的时间差很有说服力：篡改那轮连接在注入后 **1 ms** 被关闭（说明对端立刻
发现并终止），丢弃那轮是 **9611 ms**（正好是对端 IO 超时）。攻击者能看出"出事了"，
但看不出"为什么"。

## 31.5 回归

* `ctest` **18/18**（`test_mitm` 由 4 条用例增加到 **5 条**，新增覆盖"按类型 / 最近一条"选包）；
  Windows（MinGW-w64 / Qt 5.15.19）与 Ubuntu 20.04（g++ 9.4 / Qt 5.12.8）**各跑一遍都是
  18/18、0 编译告警**；
* 布局自检：默认与最小窗口两种尺寸下，主窗口与三个页签均无文字被压缩；
* 端到端三窗口演示重跑：篡改 → **⑦ CMAC**、重放 → **⑥ 防重放**、丢弃 → 超时，
  与修复前结论一致；中继日志新增 `target=` 与 `OBSERVE` 行；
* 截图更新：`docs/screenshots/ui_mitm_attack.png`。
* Linux 回归还抓出一条**过严的断言**：`test_mitm` 里"中继至少转发 9 个包"依赖
  "服务端那条 ACK 一定来得及被转发"，而这取决于谁先关连接（Windows/Linux 时序不同）。
  已放宽成确定性的 8 个（握手 7 + 业务 1）—— 这是"每轮都在 Linux 上跑一遍"的又一次回报。

## 31.6 追问修复：选"第 N 个包"点下去没反应

同学实际点了一次："目标选第 N 个包、填好序号、点篡改 → 没有任何反应，会话还是正常的"。

**根因**（不是随机故障，是语义没交代清楚）：`--index N` 是"该方向从连接建立起算的第 N 个包"，
**包含 4 个握手包**；于是"填 5 但不发消息"就一直没有第 5 个包出现，"填 1~4"则永远不会触发，
而早期版本对这两种情况**一句提示都没有**。

**修法**：

1. `--index` 改为"**在匹配类型之内**数第几个"：写 `--type DATA --index 2` 就是"第 2 条短消息"，
   不受握手包干扰（不写 `--type` 时仍是绝对序号，保持兼容）。界面上新增选项
   **「第 N 条短消息」**，"指定第 N 个包"标注"（含握手）"。
2. 界面加**实时计数**：目标行下方常驻"已转发 3 条短消息，下一条是第 4 条"；
   中继页签加"链路已转发：C2S 12 个（其中短消息 3 条）｜ S2C 8 个 → 下一个 C2S 是第 13 个"；
   切到"第 N …"时序号框自动填"下一个"。
3. **过期序号当场拦**：界面直接给出"第 2 个包已经过去了…请改用「下一个包」，或把序号改成 13"；
   中继也会回一行 `ERR target=index:2 … 它永远不会触发`，并且 ERR 会显示在攻击面板上。
4. "排队等待中"不再含糊：结果显示"已排队：等目标包经过中继时生效 —— 现在发一条消息就会触发"。

`test_mitm` 增加到 **7 条用例**（新增"序号按类型计数""过期序号必须立刻报错"），
Windows 与 Ubuntu 两个平台各 **18/18、0 告警**。
