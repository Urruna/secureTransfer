# 文件与图像安全传输（课程要求 9）

> 课程要求 9：**能够支持多种信息（短消息、文件、图像等）安全传输。**
> 短消息已由 `DATA` 消息支持；本文说明文件与图像的实现方式、实验数据与实测结果。

---

## 1. 结论摘要

| 能力 | 实现方式 | 实测结果 |
| --- | --- | --- |
| 文件传输 | `FILE_START` → `FILE_CHUNK`×N → `FILE_END`，块大小 64 KiB | 64 KB / 1 MB 文件逐字节一致 |
| 小图像 | 单个 `IMAGE` 消息（元数据 + 数据同一包） | 147 KB PNG 逐字节一致 |
| 大图像 | 仍用 `IMAGE` 作为起始包（kind = 图像），其余分块 | 2.2 MB PNG 逐字节一致 |
| 安全性 | 每一块都走 `SecureSession::sendMessage`，**自动**获得加密 + CMAC + 防重放 | `reject(...)=0/0/0/0` |
| 端到端校验 | 发送端给出总字节数与整文件 CRC32，接收端重组后比对 | 4/4 文件校验通过，sha256 与源文件相同 |

**一句话**：应用层只新增了"分块 / 重组 / CRC32 校验"，密码学保护完全复用第二部分的安全通道，
因此文件、图像、短消息用的是**同一套安全机制**。

## 2. 传输流程

### 2.1 分块传输（文件、大图像）

```text
发送端                                           接收端
  │ FILE_START  元数据{kind,文件名,总大小,CRC32}  │  创建文件，记录期望值
  │ FILE_CHUNK  第 1 块（64 KiB）                 │  写入 + 累积 CRC
  │ FILE_CHUNK  第 2 块                           │
  │ ...                                           │
  │ FILE_END    总字节数 + CRC32                   │  比对字节数与 CRC32 → 通过 / 失败
```

* 每一块都是一个独立的安全数据包：类型 `FILE_CHUNK`，正文就是这一块的原始字节；
* 块的**顺序**由协议头里的 `Sequence` 保证（严格递增、收到重复或旧序号直接拒绝），
  所以应用层不需要自己在块里带偏移量；
* 块大小 64 KiB：协议单包正文上限约 1 MiB（`Packet::kMaxBodySize = 1048519`），留足余量，
  也让上层方便显示进度。

### 2.2 单包传输（小图像）

```text
发送端  │ IMAGE  元数据{mode=单包,文件名,总大小,CRC32,数据长度} + 数据 │  接收端
```

图像不超过单包上限时，元数据与数据放在**同一个** `IMAGE` 消息里，
一次性传输、无分块开销；超过上限时自动退化为分块（起始包仍是 `IMAGE`，`kind = 图像`）。

## 3. 正文格式

全部使用大端序；`L(x)` 表示"2 字节长度前缀 + 内容"（TLV，见 `common/byte_buffer.h`）。

```text
FILE_START / IMAGE（起始包）
    [u8  版本 = 1]
    [u8  kind      0 = 普通文件, 1 = 图像]
    [u8  mode      0 = 单包（后面紧跟数据）, 1 = 分块]
    [L   文件名（UTF-8，只允许基本名，禁止路径分隔符）]
    [u64 文件总字节数]
    [u32 整文件 CRC32]
    [u32 单包数据长度]        // mode = 0 时有效
    ...（mode = 0 时：紧跟数据字节）

FILE_CHUNK
    就是这一块的原始字节（偏移由到达顺序决定）

FILE_END
    [u64 已发送/已接收总字节数]
    [u32 整文件 CRC32]
```

**安全设计**：文件名会做安全校验（禁止 `/`、`\`、`..`、控制字符），防止接收端被诱导
写到任意路径（目录穿越）。

## 4. 安全性与校验的分工（报告里要写清楚）

| 机制 | 防什么 | 说明 |
| --- | --- | --- |
| AES-128-CTR（每块） | 窃听 | 文件内容不会以明文出现在网络上 |
| CMAC（每块，Encrypt-then-MAC） | 篡改、伪造 | 任何一块被改动都会被拒绝，文件不会"悄悄损坏" |
| Sequence + SessionId | 重放、跨会话混入 | 重复或过期的块直接拒绝 |
| 总字节数 + 整文件 CRC32 | 漏块 / 多块 / 落盘错误 | **非密码学**的差错检测，用于端到端一致性确认 |

> 注意：CRC32 不是密码学哈希，不能抵抗刻意构造的碰撞，**不能替代 CMAC**；
> 它只是"重组结果对不对"的快速自检。

## 5. 实验数据

全部放在 `experiment_data/`（**主机与虚拟机各一份完全相同的副本**）：

| 文件 | 大小 | 说明 |
| --- | --- | --- |
| `text_messages.txt` | 521 B | 4 条文本测试消息的明文备份 |
| `test_file_1KB.bin` | 1 KB | 小文件 |
| `test_file_64KB.bin` | 64 KB | 恰好 1 个分块 |
| `test_file_1MB.bin` | 1 MB | 16 个分块 |
| `test_image_256x256.png` | 147 KB | 小图像 → 单包 `IMAGE` |
| `test_image_1024x768.png` | 2.2 MB | 大图像 → 分块（起始包 `IMAGE`） |
| `received/` | — | Bob 侧接收落盘目录（主机上也保留了一份从虚拟机取回的结果） |

数据为自制测试数据：`.bin` 是确定性伪随机字节，PNG 由标准库 `zlib` 手工构造
（渐变 + 棋盘格，大图叠加噪声以超过单包上限），不含任何隐私内容。

## 6. 实测结果（Ubuntu 20.04 虚拟机，真实 TCP 回环）

命令：

```bash
cd /home/securityTransfer/build
./bob 9210 --out-dir ../experiment_data/received &
./alice 127.0.0.1 9210 --file test_file_64KB.bin --file test_file_1MB.bin \
    --image test_image_256x256.png --image test_image_1024x768.png
```

发送端输出（节选）：

```text
  文件名      : test_file_64KB.bin
  大小        : 65536 字节
  传输方式    : 分块（FILE_START/CHUNK/END，块大小 65536 字节）
  分块数量    : 1
  整文件 CRC32: 0x1f50c2e7
  发送耗时    : 2.058 ms（含加密与网络）
  应用层吞吐  : 30.36 MB/s
  对端确认    : FILE OK test_file_64KB.bin (65536 字节, CRC32=0x1f50c2e7)
...
  文件名      : test_image_256x256.png
  传输方式    : 单包（IMAGE，元数据+数据同一包）
  应用层吞吐  : 31.54 MB/s
...
  文件名      : test_image_1024x768.png
  传输方式    : 分块（FILE_START/CHUNK/END，块大小 65536 字节）
  分块数量    : 34
  应用层吞吐  : 42.26 MB/s
统计: sent=67 recv=11 bytes=3487487/1067 reject(format/replay/mac/state)=0/0/0/0
```

| 数据 | 大小 | 路径 | 分块数 | 发送耗时 | 应用层吞吐 | 接收端校验 |
| --- | --- | --- | --- | --- | --- | --- |
| test_file_64KB.bin | 65,536 B | 分块 | 1 | 2.06 ms | 30.4 MB/s | 通过 |
| test_file_1MB.bin | 1,048,576 B | 分块 | 16 | 27.31 ms | 36.6 MB/s | 通过 |
| test_image_256x256.png | 147,133 B | 单包 `IMAGE` | 0 | 4.45 ms | 31.5 MB/s | 通过 |
| test_image_1024x768.png | 2,221,729 B | 分块（kind=图像） | 34 | 50.14 ms | 42.3 MB/s | 通过 |

逐字节核对（接收端落盘文件 vs 源文件）：

```text
[一致] test_file_64KB.bin  (65536 字节)
[一致] test_file_1MB.bin  (1048576 字节)
[一致] test_image_256x256.png  (147133 字节)
[一致] test_image_1024x768.png  (2221729 字节)

sha256 前 16 位：
test_file_64KB.bin      源=5eb4ca70d0ee472b  收=5eb4ca70d0ee472b
test_file_1MB.bin       源=d824bde2acff5ab2  收=d824bde2acff5ab2
test_image_256x256.png   源=f8ea510fbcb5e006  收=f8ea510fbcb5e006
test_image_1024x768.png  源=baa39e9c9864962e  收=baa39e9c9864962e
```

**应用层吞吐 30~42 MB/s** 与"纯加密吞吐 ≈110 MB/s"的差距来自：
每次 `sendMessage` 的固定开销、磁盘读写、每块一次 CMAC、以及 64 KiB 小块带来的调用次数。
（如需更高吞吐，可把块大小调大到 256 KiB 或 512 KiB，仍远低于单包上限。）

## 7. 代码位置与接口

| 文件 | 作用 |
| --- | --- |
| `include/application/crc32.h` | 自实现 CRC32（IEEE 802.3），流式接口 |
| `include/application/transfer_meta.h`、`src/application/transfer_meta.cpp` | 元数据编解码、文件名安全校验、类型推断 |
| `include/application/file_transfer.h`、`src/application/file_transfer.cpp` | `FileSender`（发送）与 `TransferReceiver`（接收） |
| `apps/alice/main.cpp` | `--file` / `--image` / `--data-dir` 参数 |
| `apps/bob/main.cpp` | `--out-dir` 参数、接收落盘、回 ACK |
| `tests/unit/test_transfer_meta.cpp` | CRC32 / 元数据 / 接收器的单元测试（含篡改必须失败） |
| `tests/integration/test_file_transfer.cpp` | 三条路径的端到端测试（文件 / 小图像 / 大图像） |

最小用法：

```cpp
// 发送
transfer::SendResult r = transfer::FileSender::send(session, "experiment_data/test_file_1MB.bin",
                                                    transfer::Kind::kFile);

// 接收（放在收消息的循环里）
transfer::TransferReceiver receiver("experiment_data/received");
if (receiver.handle(type, body, &error)) { /* 这条消息属于文件传输 */ }
```

## 8. 当前限制（写在报告里更稳妥）

1. 发送端会把整个文件读进内存后再分块（实验数据规模下没问题；超大文件应改为流式读取）；
2. 没有断点续传：传输中断需要重新发送整个文件；
3. 接收端同名文件会被覆盖（`std::ios::trunc`）；
4. 应用层吞吐受块大小影响（见 §6 的说明）；
5. 没有做"多文件并发传输"（当前一次只允许一个传输在进行，收到新的起始包会被拒绝）。
