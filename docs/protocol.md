# 协议说明（数据包格式与握手流程）

本文档描述第二部分实现的**线上协议**。所有结论都对应代码中的具体位置，便于评审时逐条对照。

---

## 1. 分层与放置方式

```text
TCP 字节流
└── Frame（第一阶段成果）: [ length(4) ][ payload(N) ]
                              └── payload 里装的就是本协议的数据包：
                                  [ Packet 头(41) ][ Body(N') ][ MacTag(16) ]
```

`Network::sendFrame()` / `receiveFrame()` 已经解决了 TCP 的粘包 / 拆包、partial send / recv、
长度上限与错误处理，因此协议头直接放在 `Frame::payload` 内部，
**网络层代码一行都没有改动**（第一阶段 27 个用例仍是回归基线）。

## 2. 数据包格式

偏移以数据包第一个字节（Magic 的第一个字节）为 0，所有多字节整数都是**网络字节序（大端）**。

| 偏移 | 长度 | 字段           | 说明                                                             |
| ---- | ---- | -------------- | ---------------------------------------------------------------- |
| 0    | 2    | `Magic`      | 固定`0x53 0x54`（"ST"），用来快速过滤非本协议的字节流          |
| 2    | 1    | `Version`    | 当前`0x01`，版本不匹配直接拒绝                                 |
| 3    | 1    | `Type`       | 消息类型，见 §3                                                 |
| 4    | 1    | `Direction`  | `0x01` = Alice→Bob，`0x02` = Bob→Alice                     |
| 5    | 8    | `SessionId`  | 会话标识（课程建议格式为 8 字节）                                |
| 13   | 8    | `Sequence`   | 该方向的包序号；握手包为 0，数据包从 1 开始严格递增              |
| 21   | 16   | `Nonce`      | 对数据包是CTR 初始计数器块<br />对握手包是放置本端 Nonce，防重放 |
| 37   | 4    | `PayloadLen` | Body 字节数，确定消息边界                                        |
| 41   | N    | `Body`       | 握手包 = 明文；数据包 = 密文                                     |
| 41+N | 16   | `MacTag`     | 认证标签                                                         |

* **包头 41 字节，总开销 57 字节**；`Frame` 负载上限 1 MiB，因此单个数据包的 Body 最大
  `1048576 - 57 = 1048519` 字节（`Packet::kMaxBodySize`）。
* 包头不是 16 的倍数是有意的：只有 `Body` 需要按 AES 分组处理，头部只是被 MAC 覆盖的字节串，不需要对齐。

### 2.1 MAC 覆盖范围

```text
数据包： MAC 输入 = Packet[2 .. 41+N)   // Version 起，到 Body 结束
                                   （不含 Magic，也不含 MacTag 自身）

握手包： MAC 输入 = 显式转录串（§5），因为要覆盖双方 ID、两个 Nonce 等语义字段
```

`PayloadLen` 参与 MAC ⇒ 无法截断或拼接 Body 而不被发现；
`Direction` 参与 MAC ⇒ 无法把对端发来的合法包原样反射回去；
`SessionId` 参与 MAC ⇒ 上个会话的数据包无法在本会话重放。

### 2.2 与课程建议格式的差异

| 课程建议（`project_q1.md` §5）                                                 | 本实现                   | 原因                              |
| --------------------------------------------------------------------------------- | ------------------------ | --------------------------------- |
| Magic 2 / Version 1 / Type 1 / SessionId 8 / Sequence 8 / Nonce 16 / PayloadLen 4 | 完全一致                 | 按课程要求，SessionId 采用 8 字节 |
| 无 Direction                                                                      | 增加 1 字节`Direction` | 防反射攻击                        |

## 3. 消息类型

| 值         | 类型                     | 方向 | Body                           | MAC 密钥                              |
| ---------- | ------------------------ | ---- | ------------------------------ | ------------------------------------- |
| 0x01       | `HELLO`                | C→S | `TLV(Alice_ID)`              | 无（对端此刻无法验证身份）            |
| 0x02       | `HELLO_ACK`            | S→C | `TLV(Bob_ID)`                | `K_master`（转录串 + "S2C"）        |
| 0x03       | `AUTH`                 | C→S | 空                             | `K_master`（转录串 + "C2S"）        |
| 0x04       | `KEY_REQUEST`          | C→S | 空                             | `K_master`（`ST-KREQ-v1`）        |
| 0x05       | `KEY_EXCHANGE`         | S→C | `wrapped(K_session)` 16 字节 | `K_master`（`ST-KEYEX-v1`）       |
| 0x06       | `KEY_CONFIRM`          | C→S | 空                             | `K_session`（`ST-KC-v1`）         |
| 0x07       | `KEY_CONFIRM_ACK`      | S→C | 空                             | `K_session`（`ST-KCA-v1`）        |
| 0x08       | `DATA`                 | 双向 | 密文                           | `K_mac`（CMAC，RFC 4493）           |
| 0x09–0x0B | `FILE_START/CHUNK/END` | 双向 | 密文                           | `K_mac`（第三部分使用）             |
| 0x0C       | `IMAGE`                | 双向 | 密文                           | `K_mac`（第三部分使用）             |
| 0x0D       | `ERROR`                | 双向 | 错误码 + 说明                  | 无（仅演示提示）                      |
| 0x0E       | `CLOSE`                | 双向 | 空                             | `K_mac`（和普通数据一样加密 + MAC） |

所有"携带业务数据"的类型（`DATA` / `FILE_*` / `IMAGE` / `CLOSE`）使用**完全相同**的
加密 + MAC + 防重放流程，只是 `Type` 不同。

> 加密算法为第一部分自实现的 AES-128-CTR，完整性算法为第一部分自实现的
> CMAC（RFC 4493），两者均已通过标准向量验证（见 `tests/unit/test_aes_cmac.cpp`）。
> 协议层通过 `CryptoProvider` / `MacEngine` 调用它们，不直接依赖具体实现。

## 4. 会话密钥与子密钥

```text
课程规定的会话密钥：
    K_session = 000102030405060708090A0B0C0D0E0F       （固定测试值）

包裹方式（Bob → Alice）：
    wrapNonce  = NonceA XOR NonceB                    （两个随机数之异或，公开）
    keystream  = AES-CTR(K_master, wrapNonce, 0^16)   （取 16 字节密钥流）
    wrapped    = K_session XOR keystream              （网络上传输的就是这 16 字节）

派生数据阶段的子密钥（用途分离）：
    K_enc = MAC(K_session, L("ST-DATA-ENC"))
    K_mac = MAC(K_session, L("ST-DATA-MAC"))
```

* `wrapNonce` 每个会话都不同（两个 Nonce 都是本次新生成的随机数），因此 `K_master` 下的密钥流不会复用；
* Eve 抓到 `wrapped` 与 `wrapNonce` 也无法恢复 `K_session`（不知道 `K_master`）；
* 课程要求的是"**安全地分发**会话密钥"，所以这里是**真的传输**，而不是本地推导。

## 5. 握手流程

```text
Alice（客户端）                                            Bob（服务端）
──────────────                                            ──────────────
① 生成 NonceA(16 随机)、SessionId(8 随机)
   HELLO  Body=TLV("alice")  Nonce=NonceA      ─────────▶  记录 SessionId / Alice_ID / NonceA
② 生成 NonceB(16 随机)
   ◀─────────  HELLO_ACK  Body=TLV("bob")  Nonce=NonceB
        MacTag = MAC(K_master, T || L("S2C"))

   验证通过 ⇒ 认证 Bob 成功（T 中含 NonceA ⇒ 消息是新鲜的）
③ AUTH  MacTag = MAC(K_master, T || L("C2S"))  ─────────▶  验证通过 ⇒ 认证 Alice 成功
④ KEY_REQUEST  MacTag = MAC(K_master, KREQ 串) ─────────▶  验证通过
⑤ ◀─────────  KEY_EXCHANGE  Body = wrapped(16)
        MacTag = MAC(K_master, KEYEX 串 || wrapNonce || wrapped)
   验证 + 解包 ⇒ Alice 得到 K_session
⑥ KEY_CONFIRM  MacTag = MAC(K_session, KC 串) ─────────▶  验证通过 ⇒ 双方 K_session 一致
⑦ ◀─────────  KEY_CONFIRM_ACK  MacTag = MAC(K_session, KCA 串)
   验证通过 ⇒ 双方进入 ESTABLISHED
```

其中公共转录串为

```text
T = L("ST-AUTH-v1") || L(SessionId) || L(Alice_ID) || L(Bob_ID) || L(NonceA) || L(NonceB)
L(x) = uint16_be(len(x)) || x
```

### 5.1 转录串的三个安全性质

1. **域分离**：固定前缀 `ST-AUTH-v1` / `ST-KREQ-v1` / `ST-KEYEX-v1` / `ST-KC-v1` …
   保证同一把密钥下不同用途的 MAC 不会互相混用；
2. **无歧义**：所有字段用 TLV 长度前缀编码，`("ab","c")` 与 `("a","bc")` 的字节串不同；
3. **防反射**：`L("C2S")` / `L("S2C")` 方向标签使对方的 MAC 无法在自己这一侧复用。

（对应测试：`tests/unit/test_transcript.cpp`）

## 6. 数据阶段的加密、完整性与防重放

### 6.1 Nonce：为什么必须结构化

`aes_ctr_xor()` 把 `nonce` 当作初始计数器块，并把**整个 128 位计数器大端自增**，
所以一条长消息会占用连续多个计数器值。

如果简单地令 `Nonce = prefix(8) || 消息序号(8)`：第 1 条 1 MiB 的消息会用到
`prefix||1` … `prefix||65537`，其中包含第 65537 条消息要用的起始值 ⇒ **密钥流复用**。

因此本实现把计数区隔离在低 32 位：

```text
Nonce(16) = RandomPrefix(8, 会话建立时生成一次) || 0x00000000(4) || 消息计数(4, 大端)
```

* 第 m 条消息占用的区间是 `[P||0||m, P||0||m+blocks)`，`blocks ≤ 65536`（1 MiB 上限）；
* 因为 `blocks < 2^32`，不同 m 的区间一定不相交；
* 每个方向使用独立前缀，不同会话的前缀也不同 ⇒ 密钥流不会复用。

（对应测试：`secure_roundtrip: 同一会话内 Nonce 不重复`，发送 20 条相同明文，Nonce 与密文两两不同。）

### 6.2 收发流程

```text
发送：seq = ++sendSeq
      nonce = Prefix || 0 || seq
      body  = AES-CTR(K_enc, nonce, 明文)          // 先加密
      mac   = MAC(K_mac, 头部 || body)             // 再对头部+密文算 MAC（Encrypt-then-MAC）
      发送 [头部 || body || mac]

接收：① 格式校验（Magic / Version / PayloadLen 与实际长度）
      ② SessionId 校验（不属于本会话 ⇒ 拒绝）
      ③ Direction 校验（方向不符 ⇒ 拒绝，疑似反射攻击）
      ④ 防重放：seq <= 已接收最大序号 ⇒ 拒绝（此时不修改水位）
      ⑤ 完整性：重新计算 MAC 并常数时间比较，不一致 ⇒ 拒绝，不交付上层
      ⑥ 通过后才推进水位、解密、交给上层
```

**为什么先判断重放、后提交水位**：如果检查序号时直接推进水位（即序列号+1，完成序列号更新），攻击者只要伪造一个序号很大的包（MAC 必然失败），就能把水位推到很大，导致之后所有合法包被误判为重放——这是一个拒绝服务漏洞。
因此 `ReplayGuard` 拆成 `wouldAccept()`（只判断对错）与 `commit()`（MAC 通过后才推进）。【Dos攻击】

（对应测试：`tests/unit/test_replay_guard.cpp` 的 `wouldAccept 不改变状态`）

### 6.3 失败处理策略

> **2026-10-09 修订**：本节原先写"MAC / 重放只拒绝该包、格式非法静默丢弃"，
> 与实现不符。实际实现是 **拒绝即终止本次会话**（`fail()` 只记录 `lastError_`，
> 由上层据此关闭连接）。本次按实现改写，并补上"拒绝关卡"`RejectGate`——
> 它只存在于进程内，不上网、不参与 MAC、不改变任何字节格式。

| 情况                             | 拒绝关卡 `RejectGate` | 行为                     | 可见输出                                              |
| -------------------------------- | --------------------- | ------------------------ | ----------------------------------------------------- |
| 认证失败（`K_master` 不一致）    | —                     | 关闭连接（握手失败）     | `Authentication Failed：对端未能通过 K_master 认证` |
| 篡改（CMAC 校验失败）            | ⑦ `kMac`              | 拒绝该包并**终止会话**   | `CMAC verification failed - Message rejected`       |
| 序号重放                         | ⑥ `kReplay`           | 拒绝该包并**终止会话**   | `Replay Attack Detected - Packet rejected`          |
| 数据包格式非法（Magic / 版本 / 长度） | ② `kFormat`       | 拒绝并**终止会话**       | `数据包格式非法: …`                                  |
| SessionId 不属于本会话           | ③ `kSessionId`        | 拒绝并**终止会话**       | `SessionId 不属于当前会话`                            |
| 方向不符（疑似反射）             | ④ `kDirection`        | 拒绝并**终止会话**       | `数据包方向不正确（疑似反射攻击）`                     |
| 消息类型不允许                   | ⑤ `kType`             | 拒绝并**终止会话**       | `协议违规: …`                                        |
| 状态机不允许（未建立就收发）     | ⑧ `kState`            | 拒绝并**终止会话**       | `协议违规: …`                                        |
| TCP 帧层读取失败                 | ① `kFrame`            | 关闭连接                 | `… 接收失败: …`                                      |
| 握手超时 / 超总时限              | ⑧ `kState` / ① `kFrame` | 关闭连接               | `Handshake timeout` / `握手总时长超过 … ms`          |

**拒绝关卡（`RejectGate`）**：`SecureSession::lastRejectGate()` 记录"最近一次被拒绝
倒在哪一道校验"，供第三部分 Eve 攻击面板与测试报告精确定位拦截点。
每次 `recvPacket()` / `receiveMessage()` 入口先置 `kNone`，
因此"成功接收"读到的一定是 `kNone`，不会读到上一次的陈旧值。

**攻击回执（`ATTACK-REPORT`）**：若拒绝属于"攻击类关卡"
（② ③ ④ ⑤ ⑥ ⑦，即 `attack::isAttackReject()` 为真）且会话已经建立，
受害端会在关闭连接**之前**用普通 `DATA` 报文回一条

```text
ATTACK-REPORT: <关卡中文名> | seq=<接收序号> | <失败原因>
```

使攻击端界面能显示"倒在哪一关"。它不需要新的消息类型、不改变任何既有字段，
攻击端把它当普通消息显示即可。回执是**尽力而为**：对端已关闭时发送失败只记
DEBUG 日志，不影响本端流程，也不触发自动回复（已在 `shouldAutoReply()` 白名单中）。

## 7. 状态机

```text
DISCONNECTED ──connect()/accept()──▶ TCP_CONNECTED
                                          │ HELLO 发出/收到
                                          ▼
                                    AUTHENTICATING ──认证失败──▶ FAILED
                                          │ 双向认证通过
                                          ▼
                                    KEY_EXCHANGE ──解包/确认失败──▶ FAILED
                                          │ KEY_CONFIRM(_ACK) 通过
                                          ▼
                                    ESTABLISHED ──CLOSE / 出错──▶ CLOSED
```

只有在 `ESTABLISHED` 状态才允许 `sendMessage()` / `receiveMessage()`，
其它状态调用会立即失败并计入 `stats().rejectedState`。

## 8. 文件与图像传输（应用层，复用同一套安全机制）

文件与图像不需要新的密码学机制：它们都通过 §6 的安全数据通道发送，
**自动**获得 AES-128-CTR 加密、CMAC 完整性、Sequence 防重放与方向校验。
应用层只增加"分块 / 重组 / 整文件校验"。

```text
分块传输（普通文件、大图像）
    FILE_START  正文 = 元数据{kind, mode=分块, 文件名, 总字节数, CRC32}
    FILE_CHUNK  正文 = 这一块的原始字节（64 KiB；顺序由 Sequence 保证）
    FILE_END    正文 = {总字节数, CRC32}

单包传输（不超过约 1 MiB 的小图像）
    IMAGE       正文 = 元数据{kind=图像, mode=单包, 文件名, 总字节数, CRC32, 数据长度} + 数据
```

* `kind`：`0 = 普通文件`、`1 = 图像`（装饰性字段，便于对端分类显示）；
* 文件名只允许基本名（禁止 `/`、`\`、`..`、控制字符），避免目录穿越；
* 块大小 64 KiB 在 `Packet::kMaxBodySize`（1048519 字节）以内，留足余量；
* 接收端在 `FILE_END` 时校验**总字节数**与**整文件 CRC32**：
  CRC32 是非密码学的差错检测，用于确认"重组结果正确"；
  防篡改由每块的 CMAC 负责，两者不可互相替代。

详细的正文格式、实验数据与实测结果见 [`file_transfer.md`](file_transfer.md)。

## 9. 访问控制与应用层命令

访问控制作用在 §8 之上的"操作"粒度上（详见 [`access_control.md`](access_control.md)）：

```text
DATA / FILE_* / IMAGE  →  映射为受保护操作  →  按对端身份的角色的权限判定  →  允许 / 拒绝
     DATA      → send_message
     FILE_*    → send_file
     IMAGE     → send_image
     （无对应操作：CLOSE / ERROR 不做访问控制）
```

* 身份取自**握手阶段认证过的对端标识**，不是消息里自称的名字；
* 被拒绝时只拒绝该操作并回一条 `ACCESS DENIED: ...`，**会话保持可用**；
  被拒绝的传输的后续数据块会被丢弃，**不会落盘**；
* 两个内置应用层命令（同样走加密数据通道，无法被伪造）：

  | 命令（`DATA` 正文以 `CMD ` 开头） | 作用 | 需要的权限 |
  | --- | --- | --- |
  | `CMD WHOAMI` | 返回本端角色与权限清单 | `send_message` |
  | `CMD VIEW_LOG` | 返回最近若干条审计记录与允许/拒绝计数 | `view_log`（仅管理员） |
