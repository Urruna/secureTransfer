# 测试报告（第一阶段：基础 TCP 通信）

> ⚠ **这是第一阶段（纯 TCP 网络层）的历史测试报告，不代表当前状态。**
> 当前完整测试结果（12 个测试程序、安全测试、性能对比、局域网双机）
> 请看 [`../test_report.md`](../test_report.md)、[`../performance.md`](../performance.md)、
> [`../lan_test.md`](../lan_test.md)。

## 1. 状态说明

**本阶段代码已在 Ubuntu 621 虚拟机中完成真实编译、测试与通信验证（2026-09-23）。**

执行环境：

| 项目 | 实测值 |
| --- | --- |
| 操作系统 | Ubuntu 20.04 (x86_64) |
| 内核 | `Linux ubuntu 5.15.0-140-generic #150~20.04.1-Ubuntu SMP` |
| 编译器 | `g++ (Ubuntu 9.4.0-1ubuntu1~20.04.3) 9.4.0` |
| 构建工具 | `cmake version 3.16.3` + make |
| CPU | 2 vCPU（虚拟机配置） |
| 项目路径 | `/home/SecureTransfer` |
| 构建方式 | `cmake .. && cmake --build .` |

结论：`ctest` 3 个测试程序、共 **27 个用例全部通过**；
Alice 与 Bob 两个独立进程通过真实 TCP loopback 完成 `Hello Bob` / `Hello Alice` 往返。
实际输出见第 4 节。

## 2. 如何执行测试

```bash
cd /home/SecureTransfer
mkdir -p build && cd build
cmake .. && cmake --build .
ctest --output-on-failure
```

或者使用一键脚本（编译 + 测试 + Alice/Bob 演示）：

```bash
bash scripts/verify_in_vm.sh
```

单独运行某个测试程序：

```bash
./tests/test_frame
./tests/test_network
./tests/test_tcp_roundtrip
```

## 3. 测试用例清单

### 3.1 `tests/unit/test_frame.cpp`（12 个用例）

| # | 用例 | 验证内容 |
| --- | --- | --- |
| 1 | 普通文本序列化后可以完整还原 | `"Hello Bob"` → `00 00 00 09 + payload`，反序列化后内容一致、`consumed` 正确 |
| 2 | length 字段使用大端序 | 258 字节 payload → `00 00 01 02` |
| 3 | 空 payload 可以正常收发 | `length = 0`，线上只有 4 字节 |
| 4 | 最大允许 payload（1 MB） | 边界值可以正常序列化 / 反序列化，内容逐字节一致 |
| 5 | 超过 1 MB 的 payload 非法 | `isValid() == false`，`serialize()` 返回空 |
| 6 | length 与 payload 不一致 | 构造 `length=5, payload=3` 的非法 Frame，不被序列化 |
| 7 | 数据不完整返回 `INCOMPLETE` | 少于 4 字节、以及"声明 100 字节只给 10 字节" |
| 8 | 长度超过 1 MB 返回 `LENGTH_TOO_LARGE` | `0x7FFFFFFF` 前缀不会导致内存分配 |
| 9 | 一个缓冲区多个 Frame | 连续解析两个 Frame，`consumed` 正确 |
| 10 | 含 `0x00` 的二进制数据 | 不会被当成字符串结尾截断 |
| 11 | UTF-8 中文内容 | `"你好，Bob，这是一次安全通信测试。"` 完整还原 |
| 12 | `encodeLength` / `decodeLength` 边界值 | `0 / 1 / 255 / 256 / 65535 / 0x01020304 / 0xFFFFFFFF` |

### 3.2 `tests/unit/test_network.cpp`（10 个用例）

| # | 用例 | 验证内容 |
| --- | --- | --- |
| 1 | 未建立连接时的接口调用 | `sendFrame` / `receiveFrame` / `accept` 都返回失败且 `NOT_CONNECTED` |
| 2 | 连接无人监听的端口 | 返回失败、`SOCKET_FAILURE`，不崩溃、不永久阻塞 |
| 3 | 非法参数 | host 为空、port 为 0 → `INVALID_ARGUMENT` |
| 4 | `listen(0)` 与真实往返 | 系统分配端口、`accept()` 成功、`ping` / `pong` 双向收发正确 |
| 5 | 非法 length 前缀 | 直接发送 `7F FF FF FF`，返回 `INVALID_FRAME`，不分配大内存 |
| 6 | payload 中途断开 | 声明 100 字节只发 10 字节后关闭 → `PEER_CLOSED` |
| 7 | 对端立即关闭 | `receiveFrame()` → `PEER_CLOSED` |
| 8 | 接收超时 | 300 ms 超时设置生效，`TIMEOUT` 且耗时远小于 5 s |
| 9 | 超大 / 非法 Frame 被拒 | 两次非法发送失败后，连接依然可用（字节流未被破坏） |
| 10 | 同一端口重复 `listen` | 第二次绑定失败（`SOCKET_FAILURE`） |

用例 5 / 6 / 7 使用 `tests/raw_client.h` 直接操作 socket，
构造 `Network` 类本身无法生成的异常字节流。

### 3.3 `tests/integration/test_tcp_roundtrip.cpp`（5 个用例）

服务端运行在独立线程中，客户端在主线程中，使用真实的 TCP loopback 连接。

| # | 用例 | 验证内容 |
| --- | --- | --- |
| 1 | 三条消息顺序往返 | `"Hello Bob"` / `"Secure Transfer"` / `"Test Message 3"` 逐条收发，内容与顺序都正确 |
| 2 | 连续 200 个小 Frame | 服务端连续快速发送 200 帧，客户端逐帧收全（粘包处理） |
| 3 | 1 MB 大 Frame | 1 MB 数据完整传输并逐字节校验（拆包处理） |
| 4 | 对端关闭连接 | 客户端得到 `PEER_CLOSED`，不会崩溃或死锁 |
| 5 | 服务端顺序服务两个客户端 | `accept()` 复用逻辑正确（先关闭旧连接） |

### 3.4 手工通信测试（课程要求的"真实通信"）

```text
终端 1: ./bob
终端 2: ./alice
```

通过标准：

* Bob 输出 `Bob listening on port 9000...`、`Client connected.`、
  `Received: Hello Bob`、`Sent: Hello Alice`；
* Alice 输出 `Connected to Bob.`、`Sent: Hello Bob`、`Received: Hello Alice`；
* 两个程序都正常退出（退出码 0），没有崩溃、没有卡死。

## 4. 实际执行结果

执行日期：2026-09-23　　执行环境：虚拟机 Ubuntu 621（见第 1 节）

### 4.1 编译

```text
=================== 1. 编译 ===================
cmake 配置成功
编译成功
[PASS] 生成可执行文件 alice
[PASS] 生成可执行文件 bob
```

编译过程 `-Wall -Wextra` 下无警告；生成 `build/alice`、`build/bob`、
`build/tests/test_frame`、`build/tests/test_network`、`build/tests/test_tcp_roundtrip`。

### 4.2 自动化测试（ctest）

```text
=================== 2. 自动化测试 ===================
Test project /home/SecureTransfer/build
    Start 1: test_frame
1/3 Test #1: test_frame .......................   Passed    0.02 sec
    Start 2: test_network
2/3 Test #2: test_network .....................   Passed    0.32 sec
    Start 3: test_tcp_roundtrip
3/3 Test #3: test_tcp_roundtrip ...............   Passed    0.03 sec

100% tests passed, 0 tests failed out of 3
Total Test time (real) =   0.36 sec
[PASS] ctest 全部通过
```

逐用例统计（直接运行三个测试程序得到的套件汇总）：

| 测试程序 | 用例数 | 结果 |
| --- | --- | --- |
| `tests/unit/test_frame.cpp` | 12 | **12/12 passed** |
| `tests/unit/test_network.cpp` | 10 | **10/10 passed** |
| `tests/integration/test_tcp_roundtrip.cpp` | 5 | **5/5 passed** |
| 合计 | **27** | **27/27 passed** |

其中 `test_network` 的实测错误日志确认了各条错误路径都被正确触发，例如：

```text
[ERROR] [Network] Failed to connect to 127.0.0.1:1 (connect() 失败: errno 111 (Connection refused))
[ERROR] [Network] receiveFrame() 失败：非法的 Frame 长度 2147483647，最大允许 1048576 字节
[ERROR] [Network] recv() 返回 0：对端关闭了连接 (已接收 10/100 字节)
[ERROR] [Network] recv() 超时，已接收 0/4 字节
[ERROR] [Network] bind() 失败，端口 46257 可能已被占用: errno 98 (Address already in use)
```

### 4.3 Alice / Bob 真实 TCP 通信

```text
=================== 3. Alice / Bob 真实通信 ===================
---------- Bob 输出 ----------
[INFO] [Network] TCP server listening on 0.0.0.0:9000 (backlog=1)
Bob listening on port 9000...
[INFO] [Network] accepted a client connection
Client connected.
Received: Hello Bob
Sent: Hello Alice
[INFO] [Network] connection closed
[INFO] [Bob] 一次通信测试完成，Bob 退出
---------- Alice 输出 ----------
[INFO] [Network] TCP connected to 127.0.0.1:9000
Connected to Bob.
Sent: Hello Bob
Received: Hello Alice
[INFO] [Network] connection closed
[INFO] [Alice] 一次通信测试完成，Alice 退出
------------------------------
[PASS] alice 正常退出
[PASS] bob 正常退出
[PASS] Bob 收到 "Hello Bob"
[PASS] Alice 收到 "Hello Alice"

全部验证通过：网络层已能在真实 TCP 上完成 Alice <-> Bob 通信。
注意：当前版本没有加密与认证，仅用于验证基础 TCP 通信。
```

两个进程的退出码均为 0，无崩溃、无卡死；数据确实经过 TCP（127.0.0.1:9000 的
`connect`/`accept`/`send`/`recv`），不是函数模拟。

## 5. 测试覆盖范围与局限

**已经覆盖：**

* Frame 的正常路径与边界（空、1 MB、超过 1 MB、长度不一致）；
* 反序列化的不完整数据与非法长度；
* 网络错误路径（连接失败、绑定失败、对端关闭、中途断开、超时、非法参数）；
* 粘包 / 拆包（连续 200 帧、1 MB 大帧）；
* 真实 TCP 往返与多客户端顺序接入。

**未覆盖（属于后续阶段）：**

* 安全性（加密、认证、完整性、防重放）——本阶段没有这些功能，无法测试；
* 恶意篡改导致的行为——当前没有 MAC，篡改不会被发现（这正是后续阶段要解决的）；
* 高并发 / 长时间稳定性 / 性能基准（100 MB 级吞吐、与 OpenSSL 对比）；
* 跨主机（局域网）通信——需要两台主机或两台虚拟机；命令见 `docs/development.md`。
