# 安全的信息传输套件

> **问题描述**
>
> Alice和Bob是一对好朋友，他们远隔千山万水，无法面对面地交流，只能通过Internet进行信息交互，如果数据传输的环境很安全，Alice和Bob就会很顺利地收到对方的消息，可是网络上有一个人Eve，他经常会做一些窃取Alice与Bob通信内容的事情，也会拦截并篡改他们之间的通信内容，甚至会假冒Alice或Bob给对方发送信息，这就使得Alice和Bob常常因此而饱受困扰，必须有合适的方法或工具让他们之间能够安全地进行信息交互。请你为他们设计一个工具套件，以便能够在非安全的互联网环境下进行安全的信息交互。
>
> **实现提示**
>
> 密码算法是保护信息机密性、完整性、可用性的重要方法，可以防止Eve假冒Alice或者Bob的身份，可以防止Eve窃取Alice和Bob之间的通信内容，然而，为了使密码算法保护Alice和Bob之间的信息交互，我们还需要设计必要的安全协议，比如如何获得对称加密的密钥，甚至也可以使用分组密码达到完整性校验的目的，这些也是大家需要考虑的问题。

## 实验要求

1. 在Alice和Bob之间**安全地进行会话密钥分发**，分发的密钥为key：0x 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F。（10分）
2. 用分发的密钥key和**AES加密**算法，实现Alice和Bob之间的**加密数据传输**，构造不少于4条测试数据消息进行正确性测试。（10分）
3. 对Alice和Bob之间发送的消息进行完整性保护和校验，防止消息篡改，**使用标准数据进行算法正确性测试**。（10分）
4. 以上3项功能可以使用成熟的国际通用密码算法或者国密算法，但必须是**自己编写代码实现**，不能直接用库文件和别人的源码。（10分）
5. 将自己的密码算法实现与库文件或别人的代码实现进行全面的**性能对比**。（10分）
6. Alice和Bob之间的信息交互可以在同一台主机上或不同主机间测试，但**信息必须经过网络传输**（可以本地发送，本地接收）。（10分）
7. 针对某个已有应用添加必要的安全保护功能，**完整地设计并实现一套安全协议，包含加密、认证、密钥交换和访问控制等功能**，使Alice和Bob交互信息时，上述安全操作尽量对用户透明。（10分）
8. 有**良好的人机交互界面、合适的应用需求分析、合理的应用设计**将获得加分。（10分）
9. 能够**支持多种信息（短消息、文件、图像等）安全传输**。（10分）
10. 除上述要求功能外还可考虑**扩充功能**。（10分）

## 步骤

### 1. 搭建 TCP 网络连接

首先建立 Alice 和 Bob 之间的基本网络通信环境。TCP（Transmission Control Protocol，传输控制协议）负责提供可靠的网络数据传输，但**TCP 本身不提供加密、身份认证或完整性保护**，因此不能直接认为 TCP 通信是安全的。

**通信模型**

```tex
Alice(Client)
      │
      │ TCP
      ↓
Bob(Server)
```

1. Alice 和 Bob 通过 TCP 建立连接。连接建立后，**不直接发送明文业务消息**，而是先进入身份认证和会话建立流程。

2. 开发和测试阶段可以先在同一台主机上运行 Alice 和 Bob：

   ```text
   Alice / Bob
        ↓
   127.0.0.1:8888
   ```

   其中 `127.0.0.1` 表示本机地址，`8888` 为通信端口。

3. 完成单机测试后，可以扩展到局域网中的两台主机，例如：

   ```text
   Alice：192.168.x.x
   Bob：  192.168.x.x
   ```

   此时数据仍然必须经过实际网络传输，以满足实验要求。

4. TCP 连接成功只能说明 Alice 和 Bob 之间具备基本的数据传输能力，**不能说明通信已经安全**。后续还需要通过认证、密钥交换、加密和完整性保护抵御 Eve 的攻击。

------

### 2. 身份认证

身份认证（Authentication）用于回答：

> **“通信对方到底是不是它声称的 Alice 或 Bob？”**

不能仅仅通过发送字符串 `"I am Alice"` 来判断身份，否则 Eve 可以直接冒充 Alice。因此需要利用 Alice 和 Bob 预先共享的秘密信息完成认证。

#### 2.1 预先配置长期认证密钥 `K_master`

首次部署系统时，为 Alice 和 Bob 安全地配置一个长期认证密钥：

```text
K_master
```

`K_master` 是 Alice 和 Bob 在建立网络通信之前就已经知道的共享秘密，用于证明双方的身份以及保护会话建立过程。

这个密钥**不能通过当前的不安全网络直接传输**，否则 Eve 可以在密钥传输过程中窃取它。

实验中可以采用“带外方式（Out-of-Band）”进行预配置，例如：

- 管理员在线下配置；
- 通过安全存储设备写入；
- 程序首次部署时写入配置文件。

最终保证：

```text
Alice：
K_master = XXXXXXXX

Bob：
K_master = XXXXXXXX

Eve：
不知道 K_master
```

`K_master` 是长期使用的认证密钥，而后续的 `K_session` 是某一次通信会话使用的临时会话密钥，两者用途不同。

#### 2.2 使用 Challenge-Response 进行认证

为了防止 Eve 直接冒充 Alice 或 Bob，可以使用 Challenge-Response（挑战—响应）方式进行身份认证。

首先 Alice 向 Bob 发送：

```text
ALICE:
    HELLO
    Alice_ID
    Nonce_A
```

其中：

- `Alice_ID`：Alice 的身份标识；
- `Nonce_A`：一次性随机数（Nonce），用于保证本次认证数据具有新鲜性，防止旧消息被重新利用。

Bob 收到后生成自己的随机数 `Nonce_B`，并返回：

```text
BOB:
    HELLO_ACK
    Bob_ID
    Nonce_B
    MAC(K_master,
        Alice_ID || Bob_ID ||
        Nonce_A || Nonce_B)
```

其中 `||` 表示字符串或数据的拼接。

Alice 收到 Bob 的消息后，也使用自己的 `K_master` 对相关数据进行验证，并返回：

```text
ALICE:
    AUTH
    MAC(K_master,
        Alice_ID || Bob_ID ||
        Nonce_A || Nonce_B)
```

Bob 验证成功后，认为 Alice 通过身份认证。

#### 2.3 MAC 的作用

MAC（Message Authentication Code，消息认证码）是一种利用秘密密钥生成的校验值，其基本形式可以表示为：

```text
MAC = F(secret_key, message)
```

例如：

```text
message = "Hello Bob"
K = SecretKey

             ┌─────────────┐
message ────>│             │
K ──────────>│     MAC     │
             └──────┬──────┘
                    ↓
                 83A91F...
```

接收方使用相同的秘密密钥重新计算 MAC，并与收到的 MAC 进行比较。

如果两者一致，说明：

1. 消息内容在传输过程中没有被修改；
2. 发送方掌握相应的共享秘密。

因此，MAC 可以提供**消息完整性保护**，并提供基于共享秘密的消息来源认证。

例如 Eve 修改了通信内容：

```text
原消息：
Transfer 100

Eve修改：
Transfer 900
```

由于 Eve 不知道 `K_master`，无法为修改后的内容生成正确的 MAC，Bob 在验证时会发现：

```text
MAC verification failed
```

从而拒绝该消息。

#### 2.4 Nonce 的作用

Nonce 可以理解为“一次性使用的随机数”。

认证过程中使用：

```text
Nonce_A
Nonce_B
```

并将它们加入 MAC 的计算：

```text
MAC(K_master,
    Alice_ID
    || Bob_ID
    || Nonce_A
    || Nonce_B)
```

这样可以保证本次认证与当前会话绑定。

它主要用于防止**重放攻击（Replay Attack）**：

```text
Alice → Bob：
合法认证消息

        ↓ Eve截获

一段时间后：

Eve → Bob：
重新发送之前截获的认证消息
```

由于新的会话会产生新的 Nonce，旧的认证消息无法通过当前会话的验证。

------

### 3. 安全分发 Session Key

身份认证成功后，需要建立本次通信所使用的会话密钥：

```text
K_session
```

Session Key（会话密钥）是一次安全通信会话中使用的临时密钥，主要用于后续的数据加密和完整性保护。与长期保存的 `K_master` 不同，Session Key 可以在不同会话之间重新建立。

本实验要求分发的 Session Key 固定为：

```text
K_session =
00 01 02 03 04 05 06 07
08 09 0A 0B 0C 0D 0E 0F
```

即：

```text
000102030405060708090A0B0C0D0E0F
```

这里的固定密钥是**课程实验指定的测试密钥**，实际安全系统通常应当为每次会话生成随机的 Session Key。

#### 3.1 KEY_EXCHANGE

设计 `KEY_EXCHANGE` 阶段，使 Alice 和 Bob 安全地获得本次会话的 Session Key。

基本流程：

```text
Alice                                Bob
  │                                    │
  │──── KEY_REQUEST ──────────────────>│
  │                                    │
  │<─── encrypted(K_session) ─────────│
  │                                    │
  │──── KEY_CONFIRM ──────────────────>│
  │                                    │
```

其中：

```text
encrypted(K_session)
```

表示对 Session Key 进行保护后再通过网络传输，而不是直接发送：

```text
000102030405060708090A0B0C0D0E0F
```

否则 Eve 可以直接从网络中获得 Session Key。

`KEY_EXCHANGE` 的作用主要包括两个方面：

1. **安全地使通信双方获得本次会话所使用的 Session Key；**
2. **通过后续确认步骤验证双方确实获得了同一个 Session Key。**

#### 3.2 KEY_CONFIRM

Alice 获得 Session Key 后，可以利用该密钥生成一个确认消息：

```text
CMAC(K_session,
     "KEY_CONFIRM"
     || Session_ID
     || Nonce_A
     || Nonce_B)
```

发送给 Bob。

Bob 使用自己获得的 Session Key 重新计算并验证。

验证成功说明：

```text
Alice拥有K_session
        +
Bob拥有K_session
        +
双方处于同一个会话
```

此时可以认为安全会话建立成功。

------

### 4. AES 加密通信

Session Key 建立后，Alice 和 Bob 使用它对实际业务数据进行加密传输。

本实验采用：

```text
AES-128-CTR + CMAC
```

其中：

- **AES-128-CTR**：负责保证数据的机密性，防止 Eve 直接看到通信内容；
- **CMAC**：负责保证数据的完整性，并验证消息是否被篡改。

整体流程为：

```text
                         ┌─────────────┐
plaintext ──────────────>│ AES-128-CTR │
                         └──────┬──────┘
                                ↓
                           ciphertext
                                │
                                ▼
                    ┌────────────────────┐
                    │       CMAC         │
                    │                    │
                    │ Sequence           │
                    │ + Nonce            │
                    │ + ciphertext       │
                    └─────────┬──────────┘
                              ↓
                           MAC Tag
```

最终通过网络发送：

```text
Nonce
+
Sequence
+
Ciphertext
+
CMAC
```

#### 4.1 AES-128

AES（Advanced Encryption Standard，高级加密标准）是一种对称分组密码。

AES-128 中：

- 密钥长度为 128 bit，即 16 byte；
- 加密和解密使用同一个密钥。

本实验指定的：

```text
000102030405060708090A0B0C0D0E0F
```

正好是 128 bit 的密钥。

AES 负责解决：

> **“Eve 即使截获网络数据，也不能直接得到原始明文。”**

#### 4.2 CTR 模式

CTR（Counter Mode，计数器模式）是一种 AES 工作模式，可以将 AES 分组密码用于处理任意长度的数据。

其基本思想是：

```text
Nonce + Counter
       │
       ▼
     AES(K)
       │
       ▼
   Keystream
       │
       │ XOR
       ▼
Plaintext ───────> Ciphertext
```

对于不同的数据块使用不同的计数器值：

```text
S0 = AES(K, Nonce || Counter0)
S1 = AES(K, Nonce || Counter1)
S2 = AES(K, Nonce || Counter2)
```

然后：

```text
C0 = P0 XOR S0
C1 = P1 XOR S1
C2 = P2 XOR S2
```

解密时同样使用对应的密钥流：

```text
P0 = C0 XOR S0
P1 = C1 XOR S1
P2 = C2 XOR S2
```

因此 CTR 模式可以处理长度不同的消息和文件。

需要特别注意：

> **同一个 Session Key 下，Nonce 不能重复使用。**

因此每条消息都应具有唯一的 Nonce。

#### 4.3 CMAC 完整性保护

CMAC（Cipher-based Message Authentication Code，基于密码的消息认证码）可以利用 AES 构造消息认证码。

对于每条消息，可以计算：

```text
CMAC(
    K_mac,
    Sequence
    || Nonce
    || Ciphertext
)
```

如果接收方计算出的 CMAC 与发送方提供的 CMAC 不一致，则说明：

```text
消息可能被篡改
```

接收方应直接拒绝该消息，而不是继续处理。

因此：

```text
AES-128-CTR
    ↓
保护机密性

CMAC
    ↓
保护完整性
```

两者组合后，可以同时应对 Eve 的窃听和篡改。

#### 4.4 完成至少 4 条数据测试

构造不少于 4 条测试消息，对加密、传输、解密和完整性校验进行正确性测试。

测试数据可以按照长度逐渐增加，例如：

```text
测试1：短文本
"Hello Bob!"

测试2：普通英文文本
"A secure message between Alice and Bob."

测试3：较长文本
包含较长字符串、数字和特殊字符。

测试4：中文或更长数据
"你好，Bob，这是一次安全通信测试。"
```

测试过程中记录：

```text
明文
↓
Ciphertext
↓
CMAC
↓
Bob解密结果
↓
完整性验证结果
```

最终确认 Bob 得到的明文与 Alice 发送的原始数据一致。

------

### 5. 设计统一消息格式

为了让短消息、文件和图像都能够使用同一套安全协议，需要设计统一的数据包格式。

建议：

```text
┌──────────────────────────────┐
│ Magic        2 bytes         │
├──────────────────────────────┤
│ Version      1 byte          │
├──────────────────────────────┤
│ Type         1 byte          │
├──────────────────────────────┤
│ Session ID   8 bytes         │
├──────────────────────────────┤
│ Sequence     8 bytes         │
├──────────────────────────────┤
│ Nonce        16 bytes        │
├──────────────────────────────┤
│ Payload Len  4 bytes         │
├──────────────────────────────┤
│ Ciphertext   N bytes         │
├──────────────────────────────┤
│ CMAC         16 bytes        │
└──────────────────────────────┘
```

各字段作用如下：

- **Magic**：用于判断数据包是否属于本协议；
- **Version**：协议版本，便于以后升级；
- **Type**：表示当前数据包的类型；
- **Session ID**：标识当前通信会话；
- **Sequence**：数据包序号，用于检测重复数据包和重放攻击；
- **Nonce**：CTR 模式使用的一次性随机数；
- **Payload Len**：表示有效数据长度；
- **Ciphertext**：经过 AES-CTR 加密后的数据；
- **CMAC**：用于完整性验证。

`Type` 可以进一步定义为：

```text
0x01  HELLO
0x02  AUTH
0x03  KEY_EXCHANGE
0x04  TEXT
0x05  FILE_START
0x06  FILE_DATA
0x07  FILE_END
0x08  IMAGE
0x09  ERROR
```

这样可以使用同一个通信协议处理不同类型的信息。

------

### 6. 访问控制

访问控制（Access Control）用于解决：

> **“用户通过身份认证后，可以执行哪些操作？”**

它与身份认证不同：

```text
Authentication：
你是谁？

Access Control / Authorization：
你可以做什么？
```

例如：

```text
普通用户：
    发送消息       ✓
    发送文件       ✓
    查看自己的文件  ✓
    删除其他用户文件 ✗

管理员：
    发送消息       ✓
    发送文件       ✓
    查看日志       ✓
    管理用户       ✓
```

基本流程：

```text
身份认证
   ↓
确定用户身份
   ↓
确定用户角色 Role
   ↓
检查操作权限 Permission
   ↓
允许 / 拒绝
```

这样可以满足安全协议中对访问控制功能的要求。

------

### 7. 建议的 Git 项目结构

为了方便小组成员并行开发，项目可以按照功能划分目录：

```text
SecureTransfer/
│
├── crypto/
│   ├── aes/
│   │   ├── aes.h
│   │   ├── aes.cpp
│   │   ├── key_schedule.cpp
│   │   ├── sub_bytes.cpp
│   │   ├── shift_rows.cpp
│   │   ├── mix_columns.cpp
│   │   └── add_round_key.cpp
│   │
│   ├── cmac/
│   │   ├── cmac.h
│   │   └── cmac.cpp
│   │
│   └── crypto_utils/
│
├── protocol/
│   ├── packet.h
│   ├── packet.cpp
│   ├── handshake.h
│   ├── handshake.cpp
│   └── session.cpp
│
├── network/
│   ├── tcp_client.cpp
│   ├── tcp_server.cpp
│   └── socket_manager.cpp
│
├── application/
│   ├── message.cpp
│   ├── file_transfer.cpp
│   └── image_transfer.cpp
│
├── ui/
│   ├── alice/
│   └── bob/
│
├── benchmark/
│   └── aes_benchmark.cpp
│
├── tests/
│   ├── test_aes.cpp
│   ├── test_cmac.cpp
│   ├── test_protocol.cpp
│   └── test_transfer.cpp
│
└── docs/
    ├── protocol.md
    ├── architecture.md
    └── test_report.md
```

建议按照以下三个主要模块进行小组分工：

```text
第一部分：密码与安全机制
    AES
    AES-CTR
    CMAC
    标准测试
    性能测试

第二部分：安全通信协议与网络
    TCP
    数据包格式
    身份认证
    Session Key 分发
    会话管理
    防重放

第三部分：应用与测试展示
    UI
    短消息
    文件
    图像
    访问控制
    Eve 攻击演示
```

三个部分通过统一接口连接，避免不同成员直接修改其他成员的底层代码。

------

### 8. 加入用户界面（UI）

在核心通信功能完成后加入图形用户界面，使用户不需要直接操作密码算法和网络协议。

界面至少应能够完成：

```text
启动程序
    ↓
连接 Bob
    ↓
身份认证
    ↓
建立安全会话
    ↓
发送 / 接收消息
    ↓
发送 / 接收文件
    ↓
显示传输状态
```

密码运算、密钥交换、MAC 验证等安全操作尽量在后台自动完成，使安全机制对普通用户透明。

------

### 9. Eve 攻击演示与安全性验证

仅仅能够正常完成 Alice 和 Bob 之间的数据传输，**不能证明系统能够抵御 Eve 的攻击**。

因此需要设计专门的攻击测试，对系统的安全机制进行验证。

#### 9.1 窃听攻击

Eve 通过抓包工具观察 Alice 和 Bob 的网络通信。

预期结果：

```text
Eve 可以看到：
TCP数据包
Ciphertext
Nonce
Sequence
CMAC

Eve 不应该直接看到：
原始明文
Session Key
K_master
```

用于验证 AES 加密是否提供了机密性保护。

#### 9.2 篡改攻击

Eve 修改通信数据中的某些字节：

```text
原始 Ciphertext
      ↓
Eve 修改
      ↓
Bob收到修改后的数据
```

Bob 重新计算 CMAC：

```text
收到的 CMAC
      ≠
重新计算的 CMAC
```

则：

```text
CMAC verification failed
Message rejected
```

用于验证完整性保护。

#### 9.3 身份伪造攻击

Eve 尝试发送：

```text
"I am Alice"
```

但由于 Eve 不知道 `K_master`，无法生成正确的认证信息。

预期：

```text
Authentication Failed
Connection rejected
```

用于验证身份认证机制。

#### 9.4 重放攻击

Eve 截获一次合法的数据包，然后在之后重新发送。

系统通过：

```text
Nonce
+
Sequence Number
+
Session ID
```

判断数据包是否属于当前有效会话。

如果发现已经处理过的旧序号或无效会话数据：

```text
Replay Attack Detected
Packet rejected
```

用于验证系统对重放攻击的防护能力。

------

### 10. 性能对比测试

最后对自己实现的密码算法与成熟密码库中的实现进行性能对比。

至少测试不同规模的数据，例如：

```text
1 KB
64 KB
1 MB
10 MB
100 MB
```

分别记录：

```text
加密时间
解密时间
吞吐率
```

可以形成如下测试表：

| 数据大小 | 自己实现 AES | 库实现 AES | 自己实现吞吐率 | 库实现吞吐率 |
| -------- | ------------ | ---------- | -------------- | ------------ |
| 1 KB     |              |            |                |              |
| 64 KB    |              |            |                |              |
| 1 MB     |              |            |                |              |
| 10 MB    |              |            |                |              |
| 100 MB   |              |            |                |              |

通过测试结果分析不同实现之间的性能差异，并结合算法实现方式、代码优化、底层硬件加速等因素进行解释。

# # 
