# SecureTransfer 项目梳理（自述版）

> **内容为作者原稿，本文仅做排版与层级整理，不改动技术表述。**
> 文末「附录：待核对清单」为整理者标注，非原文，可自行删除。
>
> 定位说明：本文偏「**我怎么理解这个项目**」，按"从 0 开始做一遍"的顺序复述；
> 与 `docs/project_overview.md`（自动生成、偏"代码事实"）互为参照，不是替代关系。

---

## 1. 从 0 开始：为什么是 AES-128-CTR + CMAC

### 1.1 机密性 —— AES-128-CTR

**AES 本体**

- 分组密码，**每组 16 字节**，**10 轮迭代**；
- 每轮 4 个变换：**S 盒**（字节替换）→ **行移位** → **列混合** → **与轮密钥异或**。

**CTR 模式**

- 思路：用 `nonce`（计数器）作输入送给 AES，产生**密钥流**；
  明文 **异或** 密钥流 = 密文。
- 三个好处：
  1. **加解密是同一个运算** —— 接口层名字做了区分，实际是同一个算法；
  2. **可并行**；
  3. **不需要填充**，明文长度可为任意值 —— 因为**明文根本不参与 AES**，
     只有 nonce 进 AES，出来的密钥流再和明文异或。

**为什么不用 GCM**

- 因为 CTR 和 CMAC 分工合作：把**机密性**和**完整性**逐一实现，环节更加清晰。

### 1.2 完整性 —— CMAC（RFC 4493）

**组合方式**

- AES-128-CTR 提供 `ciphertext`，CMAC 提供 `tag`；
- 所以传输的消息 = **ciphertext + tag**；
- 接收端**先校验 tag，再解密 ciphertext** —— 这就是完整性（防止篡改）。

**防篡改"组合拳"**

| 手段 | 作用 |
| --- | --- |
| 先 encrypt 后 CMAC，先 CMAC 后 decrypt | Encrypt-then-MAC 顺序 |
| 密钥分离 `encKey` / `macKey` | 加密与完整性各用各的密钥 |
| MAC 覆盖范围 | `PayloadLen` 防截断拼接；`Sequence` 防重放；`Direction` 防冒充；`SessionId` 防跨会话 |
| 常数时间比较 | 不能利用"失败时间长短"去定位 tag |

**CBC-MAC 的两处加固**

- 先做子密钥推导（从全 0 开始）；
- 处理**最后一个分组块**：正常就多异或 `K1`，长度不足就补齐 16 字节再多异或 `K2`；
- 补齐**不是补全 0，而是 `1000…0`** —— 防止补 `00` 产生编码歧义（不知道是填充还是信息本身）；
- 多异或这一下既是"加一把锁"，也是**区分**。

**子密钥推导**

```text
L  = AES_k(0^128)        // 128 bit 全 0 送入 AES，得到 L
K1 = dbl(L)              // 一次 dbl
K2 = dbl(dbl(L))         // 两次 dbl
```

### 1.3 算法语言的选择

- 目前落在两处：**密码算法实现** + **Qt 的 UI 界面设计**。

### 1.4 性能测试：怎么测、结果如何

- 对照对象：**OpenSSL**（一个包含众多密码算法的软件库）；
- 关键手法：**关闭 AES-NI**（专门加速 AES 的硬件）；
- 原则：**先正确，再比较**；
- 数据规模的挑选；
- 要分清**真实差距**和**软件层的差距**；
- 扩展对照：增加 **Botan** 和 **mbed TLS**。

---

## 2. 网络层怎么设计

### 2.1 TCP 字节流：粘包拆包

`receiveFrame` 的处理顺序：

1. 先 `readExact` 得到 **4 字节 length**；
2. **校验 length**，非恶意分配内存；
3. 再 `readExact` 读完 **payload**。

结构上：

```text
payload = packet（内含 ciphertext）
```

### 2.2 连接中的超时与异常处理

**两种超时策略**

| 策略 | 说明 |
| --- | --- |
| **A · 单次超时 5s** | 每一次 `recv` 都**重新计时** |
| **B · 总期限** | 只记一个"截止时刻"，**不重置**（防止对方一直踩着 A 发没用的消息） |

**术语表**

| 名称 | 含义 |
| --- | --- |
| `SO_RCVTIMEO` | Socket Option, Receive TimeOut —— 接收的等待上限（套接字选项） |
| `SO_SNDTIMEO` | Socket Option, Send TimeOut —— 发送的等待上限（套接字选项） |
| `applyTimeout()` | "把这个上限真的设到套接字上" —— 因为设超时是一次系统调用，函数名就是"去应用它" |
| `setReadDeadlineMs()` | set read deadline —— 给这次读定一个"截止时刻"（毫秒）；deadline 就是"死线" |
| `waitReadable()` | wait readable —— 先问一句：现在有数据可读吗 |
| `waitAcceptable()` | wait acceptable —— 先问一句：现在有新连接可以接收吗 |

**三个参数**

| 参数 | 值 | 覆盖范围 |
| --- | --- | --- |
| `handshakeTimeoutMs` | 5 s | 单次接收（握手期） |
| `handshakeDeadlineMs` | 15 s | 整个握手的**总预算** |
| `ioTimeoutMs` | 10 s | 单次接收（数据期） |

### 2.3 一次连接：TCP 三次握手 + 安全层七步握手

**TCP 连接**：3 次握手（先 `listen` 后 `connect`）。

**安全层握手七步**

| 步 | 方向 | 内容 |
| --- | --- | --- |
| 1 | Alice → Bob | `HELLO`：Alice_ID + NonceA　**【注意 DoS 面】** |
| 2 | Bob → Alice | `HELLO_ACK` + MAC<sub>K_master</sub>(Bob_ID + NonceB) |
| 3 | Alice → Bob | `AUTH`：MAC<sub>K_master</sub> |
| 4 | Alice → Bob | `KEY_REQUEST`：MAC<sub>K_master</sub> |
| 5 | Bob → Alice | `KEY_EXCHANGE`：MAC<sub>K_master</sub>(K_session) |
| 6 | Alice → Bob | `KEY_CONFIRM`：MAC<sub>K_session</sub> |
| 7 | Bob → Alice | `KEY_CONFIRM_ACK`：MAC<sub>K_session</sub> |

之后：

- `deriveSessionKeys()` 派生出 `encKey` / `macKey`；
- 若超时则断连，但**服务端保持监听**。

### 2.4 第 ⑤ 步 KEY_EXCHANGE：会话密钥怎么"包"出去

```text
wrapNonce = NonceA 异或 NonceB
          // 用两个随机数之异或，避免每次一模一样

keystream = AES-CTR(K_master, wrapNonce, 16 个 0x00)
          // 16 个 0 字节：方便，且加密算法刚好处理 16 字节，与 K_session 等长

wrapped[i] = sessionKey[i] 异或 keystream[i]
          // 掩码

MAC = CMAC(K_master, 转录串 ‖ wrapped)
```

### 2.5 数据传输通道

**帧结构**

```text
TCP 字节流
  └─ Frame[ Length | Packet ]

Packet = 41 字节头[ Magic | Version | Type | Direction | Sequence | Nonce ]
       + Body[ AES-CTR ]
       + MAC
```

处理职责划分：

- **Frame** 定边界；
- **packet** 解字段；
- 验 MAC；
- 解密 Body。

**`sendMessage()` 九步**

1. `state == kEstablished`？
2. `isDataBearing(type)`？（是否真正携带业务，还是控制类包）
3. `Length <= kMaxBodySize`？
4. `sequence = sendSequence_ + 1`
5. `nonce = 随机前缀(8) ‖ 0^4 ‖ 计数器(4)`
   —— 8 字节随机前缀（每会话、每方向都不同）+ 4 字节全零隔离带 + 4 字节计数器；**零区的作用是隔开计数溢出区**
6. `body = AES-CTR(encKey_, nonce, 明文)`
7. `mac = CMAC(macKey_, encode())`
8. 套 Frame
9. `writeAll()`

**`receiveMessage()` 九步**

| # | 关卡 | 目的 |
| --- | --- | --- |
| 1 | Frame 层：`readExact` 两次（Length + Payload），边界与长度合法性 | 分帧安全 |
| 2 | Packet 层：Magic / Version / 结构体长度 | 格式合法 |
| 3 | `SessionId` 是不是当前会话 | 防跨会话串包 |
| 4 | `Direction` 对不对 | 防反射攻击（把对方的包原样打回去冒充自己） |
| 5 | 是不是 `isDataBearing` 类型 | 类型合法 |
| 6 | 防重放 `wouldAccept()` ← **便宜** | 先做便宜的 |
| 7 | 验 MAC `verifyCmac()` ← **贵** | 后做贵的 |
| 8 | 全部通过后才 `commit()`，推进重放窗口 | 先判断后提交 |
| 9 | 解密 Body，得到明文 | 交付上层 |

### 2.6 不同 type 的数据

**短消息**

- 直接走加密通道。

**文件**

```text
FILE_START  元数据：版本 / kind / mode / 文件名 / 总字节数 / CRC32
FILE_CHUNK  64 KiB（循环发送）
FILE_END    总字节数 + CRC32
```

**图像**

- 小的：直接元数据 + 数据，**一个包发完**；
- 大的：`[IMAGE | FILE_CHUNK | FILE_END]`；
- 文件与图像走的是**同一个** `FileSender::send()`。

**接收端五重校验**

1. `receivedBytes_ == meta_.totalBytes` —— 长度校验；
2. `FILE_END` 声明的字节数 == 实收 —— 结束包与过程不一致；
3. `FILE_END` 的 CRC32 == 起始包声明 —— 结束包被改；
4. 逐块累积的 CRC32 == 起始包声明 —— 中间某块内容错；
5. 重新读一次磁盘文件算 CRC32 —— 我自己存的时候是否出错。

---

## 3. Eve 的攻击

**本质：不知道 `K_master`。**

| 攻击 | Eve 做什么 | 防线 | 为什么挡得住 |
| --- | --- | --- | --- |
| **窃听** | 抓包读内容 | AES-128-CTR | 网上只有密文 |
| **篡改** | 改密文里的字节 | CMAC 完整性校验 | tag 对不上 |
| **假冒** | 冒充 Alice 连 Bob | `K_master` 身份认证 | 没密钥连不进来 |
| **重放** | 把旧包再发一次 | 序号窗口 + SessionId | 见过的序号不再收 / 会话 ID 不对 |

**两种"拒绝"要分清**

| 情形 | 后果 | 检查点 |
| --- | --- | --- |
| **篡改 / 重放** | **导致断连（保守策略）** | 重放检查、MAC 检查 |
| **访问控制拒绝（越权请求）** | **只是拒绝操作，连接照常** | 角色 → 权限判定 |

**两个为攻击演示准备的接口**

| 接口 | 等价于 Eve 的什么能力 |
| --- | --- |
| `lastSentWireForTesting()` | Eve 的**抓包**能力 |
| `sendRawWireForTesting()` | Eve 的**注入**能力 |

---

## 4. Linux → Windows 的迁移

### 4.1 工具链

| 组件 | 说明 |
| --- | --- |
| **MSYS2** | Windows 上的一套"开发工具仓库 + Unix 风格环境"；包含 Ninja、Qt 和 MinGW |
| **MinGW-w64** | 让 GCC 能够编译 Windows 原生程序的工具链 |
| **g++** | 16.2.0（编译器） |
| **Ninja** | 构建：哪些文件需要编译？怎么编译？先编译谁？最后怎么链接？ |
| **Qt** | 5.15.19（MSYS2 仓库包）—— UI |
| **CMake** | `CMakeLists.txt`，生成构建规则提供给 Ninja |

### 4.2 需要适配的地方

| 方面 | Linux | Windows |
| --- | --- | --- |
| **网络层** | socket 是内核直接提供的，拿来就用 | 必须先 `WSAStartup` 把网络子系统加载起来 |
| **编码** | —— | 程序内部统一用 UTF-8，先转成宽字符再传，走 Unicode 接口，系统按 UTF-16 正确匹配 |
| **运行依赖** | —— | **DLL**（动态链接库）需要随程序一起分发 |

---

## 5. UI 设计

> 本节为提纲，待补。

- 用户需要什么：`SecureTransfer.exe` + 它运行时需要的 DLL + 其他必要资源；
- 我用了哪些工具；
- UI 可以完成什么功能；
- 怎么将代码和前端串起来的。

---

## 6. 扩展

> 本节为提纲，待补：**做了哪些扩展，为什么做这些扩展**。
>
> 可考虑从这些线索切入（整理者提示，非原文）：
> 性能对比工具（含 Botan / mbed TLS 后端）、Eve 攻击演示、访问控制（角色 / 权限 / 审计）、
> 窃听抓包脚本、GIS/CI 自动出包与免环境分发、`--auto` 脚本化界面。

---

## 附录：答辩前的措辞提醒（2026-10-12 复核过）

以下都是**答辩时可能被追问**的点，已对照代码与课程原文复核：

| # | 位置 | 文中写的 | 建议核对 |
| --- | --- | --- | --- |
| 1 | §2.2 超时策略 | 参数表写 `handshakeDeadlineMs = 15 s` | ✅ 已一致：代码就是 `handshakeDeadlineMs = 15000`（15 s），文中不再出现"30 s" |
| 2 | §1.1 "为什么不用 GCM" | 理由 = CTR 与 CMAC 分工更清晰 | **课程本身指定了 AES-128-CTR + CMAC**，主因是"按要求做"，分工清晰是补充理由。若答成"我们权衡后选了 CTR"，容易被问"为什么不用更强的 AEAD" |
| 3 | §1.1 AES 每轮变换 | "10 轮迭代，每轮 4 个变换" | 准确说法：AES-128 共 10 轮，但**最后一轮不含列混合**（只有 S 盒 + 行移位 + 轮密钥异或）。前 9 轮才是 4 个变换 |
| 4 | §1.2 "先做子密钥推导" | 措辞为"密钥扩展" | 这里的 `L/K1/K2` 推导是 **CMAC 的子密钥派生**，与 AES 的**密钥扩展**（11 组轮密钥）是两回事，建议区分用词 |
