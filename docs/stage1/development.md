# 开发与运行指南

> ⚠ **这是第一阶段（纯 TCP 网络层）的历史文档存档，不代表当前状态。**
> 文中"暂未实现"的会话密钥分发、AES、CMAC、安全协议、性能对比等内容**现已全部完成**；
> 当前进展请看项目根目录的 `Part2_transfer.md` 与 [`../development.md`](../development.md)。

## 1. 环境准备（Ubuntu 621 虚拟机）

```bash
sudo apt update
sudo apt install -y build-essential cmake git
g++ --version      # 需要支持 C++17（g++ 7 及以上）
cmake --version    # 需要 3.10 及以上
```

本阶段不需要任何第三方库（不需要 OpenSSL、不需要 Qt、不需要网络库）。

## 2. 把项目放到 `/home/SecureTransfer`

课程要求项目路径为 `/home/SecureTransfer`。可以用下面的脚本复制：

```bash
cd <你解压/克隆得到的目录>/SecureTransfer
bash scripts/deploy_to_home.sh
```

脚本会把整个项目复制到 `/home/SecureTransfer`（`/home` 需要权限时会自动使用
`sudo`），并把目录所有者改为当前用户。也可以手工复制：

```bash
sudo cp -r SecureTransfer /home/SecureTransfer
sudo chown -R "$USER":"$USER" /home/SecureTransfer
```

## 3. 编译

```bash
cd /home/SecureTransfer
mkdir -p build
cd build

cmake ..
cmake --build .            # 等价于 make；也可以加 -j4 加速
```

编译产物：

```text
build/alice
build/bob
build/tests/test_frame
build/tests/test_network
build/tests/test_tcp_roundtrip
```

如需重新从头编译：

```bash
rm -rf build && mkdir build && cd build && cmake .. && cmake --build .
```

### 3.1 使用项目自带的 CMake 配置脚本（推荐）

`scripts/configure_cmake.sh` 会把"检查工具链 → 配置 → 编译 → 运行测试"串起来，
并明确打印 CMake / 编译器版本，便于排查环境问题：

```bash
cd /home/SecureTransfer

bash scripts/configure_cmake.sh                  # 只配置 build/ 目录
bash scripts/configure_cmake.sh --build          # 配置 + 编译
bash scripts/configure_cmake.sh --build --test   # 配置 + 编译 + ctest
bash scripts/configure_cmake.sh --clean --build  # 先清空 build/ 再配置编译

BUILD_TYPE=Debug bash scripts/configure_cmake.sh --build   # 指定构建类型
GENERATOR=Ninja bash scripts/configure_cmake.sh --build    # 指定 Ninja（需 ninja-build）
```

脚本要点：

* 采用**源码外构建**（所有产物都在 `build/` 内），不会污染源码树；
* 会检查 `cmake` 版本是否满足 `CMakeLists.txt` 要求的 3.10 及以上；
* 生成 `build/compile_commands.json`，便于 IDE / clangd 做跳转补全；
* 构建目录固定为项目内的 `build/`，`--clean` 只允许删除该目录。

### 3.2 本课程虚拟机实测环境

| 项目 | 版本 |
| --- | --- |
| 系统 | Ubuntu 20.04 (x86_64) |
| CMake / CTest / CPack | 3.16.3（`apt` 安装的 `cmake` + `cmake-data`） |
| 编译器 | g++ 9.4.0（`build-essential`） |
| make | GNU Make 4.2.1 |
| 其它（可选） | `cmake-curses-gui`（`ccmake`）、`ninja-build`（`ninja`） |

如果以后需要比 3.16 更新的 CMake，Ubuntu 20.04 的 apt 源里没有更新的版本，
可以用 `pip3 install --user cmake`、`sudo snap install cmake --classic`
或 Kitware 官方 apt 源，三者任选其一。

## 4. 运行 Alice 与 Bob

**终端 1（Bob，服务端，先启动）**

```bash
cd /home/SecureTransfer/build
./bob                 # 默认端口 9000
```

**终端 2（Alice，客户端）**

```bash
cd /home/SecureTransfer/build
./alice               # 默认 127.0.0.1:9000，发送 "Hello Bob"
```

参数说明：

```text
./bob   [port]
./alice [host] [port] [message]
```

预期结果：

```text
Bob 终端：                    Alice 终端：
Bob listening on port 9000... Connected to Bob.
Client connected.             Sent: Hello Bob
Received: Hello Bob           Received: Hello Alice
Sent: Hello Alice
```

如果不是本机测试，而是局域网内两台主机（仍然满足"信息经过网络传输"）：

```bash
# 在 Bob 所在主机
./bob 9000
# 在 Alice 所在主机（把 host 换成 Bob 的 IP）
./alice 192.168.x.x 9000 "Hello Bob"
```

注意：Bob 目前绑定 `INADDR_ANY (0.0.0.0)`，因此局域网内可以直接连接；
如果连不上，请检查防火墙（`sudo ufw allow 9000/tcp`）与网段是否互通。

## 5. 运行测试

```bash
cd /home/SecureTransfer/build
ctest --output-on-failure
```

也可以单独运行，便于看每一步的输出：

```bash
./tests/test_frame           # Frame 序列化 / 边界 / 非法输入（12 个用例）
./tests/test_network         # 错误处理 / 超时 / 非法长度 / 对端断开（10 个用例）
./tests/test_tcp_roundtrip   # 多消息往返 / 粘包 / 1 MB 大 Frame / 多客户端（5 个用例）
```

一键完成"编译 + 测试 + Alice/Bob 演示"的脚本：

```bash
bash scripts/verify_in_vm.sh
```

## 6. 日志级别

默认输出 `INFO` 及以上级别。需要更详细的网络调试信息时：

```bash
ST_LOG_LEVEL=DEBUG ./alice
ST_LOG_LEVEL=WARN  ./bob          # 只看警告与错误
```

**调试时也不要打印密钥**：后续加入 `K_master` / `K_session` 后，
任何密钥相关输出必须放在 `DEBUG` 级别且默认关闭。

## 7. 常见问题

| 现象 | 原因与处理 |
| --- | --- |
| `[ERROR] Failed to connect to 127.0.0.1:9000 (connect() 失败: errno 111 ...)` | Bob 还没启动，或端口写错 |
| `bind() 失败，端口 9000 可能已被占用: errno 98 (Address already in use)` | 端口被别的进程占用：`sudo ss -lntp \| grep 9000`，或换端口 |
| Bob 一直卡在 `accept()` | 正常现象：它在等 Alice 连接 |
| Alice 卡住不返回 | Bob 没回复；用 `setReceiveTimeoutMs()` 已设为 10 秒，会以 `TIMEOUT` 报错 |
| `ctest` 报某个用例失败 | 用 `ctest --output-on-failure` 或直接运行对应测试程序查看详细断言位置 |
| 局域网内连不上 | 检查 `ufw` 防火墙、IP 是否可达（`ping`）、Bob 是否绑定在 `0.0.0.0` |
| 编译时出现 `Warning: File '...' has modification time ... in the future`、`Clock skew detected`，或 Ninja 报 `manifest 'build.ninja' still dirty after 100 tries` | 从 Windows 拷贝进来的文件时间戳比虚拟机时间晚（时区/时钟差异），make/ninja 会一直认为文件"刚被修改"。执行 `find /home/SecureTransfer -exec touch {} +` 把时间戳改成当前时间，然后重新编译即可。 |

## 8. 后续如何接入 AES / CMAC（给下一位组员）

接入原则：**`Network` 与 `Frame` 的接口不需要修改**，
密码算法与协议逻辑加在网络层之上的新模块里。

建议的开发顺序：

1. **准备公共类型**：`include/common/types.h`
   （`using Byte = uint8_t; using Bytes = std::vector<Byte>;`
   以及 `Key128` / `Nonce` / `SessionId` / `MacTag`，长度各 16 字节）；
2. **定义可插拔接口**：`include/crypto/crypto_provider.h`

   ```cpp
   class CryptoProvider {
   public:
       virtual ~CryptoProvider() = default;
       virtual Bytes aesCtrEncrypt(const Key128&, const Nonce&, const Bytes&) = 0;
       virtual Bytes aesCtrDecrypt(const Key128&, const Nonce&, const Bytes&) = 0;
       virtual MacTag cmac(const Key128&, const Bytes&) = 0;
       virtual bool verifyCmac(const Key128&, const Bytes&, const MacTag&) = 0;
   };
   ```

3. **先写 Mock 实现**（`MockCryptoProvider`，仅用于把协议跑通，
   代码中必须标注 `WARNING: development-only mock implementation`），
   这样协议层可以先行开发和测试；
4. **AES-128 与 AES-CTR**（组员 A）：实现后先用标准测试向量验证
   （如 FIPS-197 附录、NIST SP 800-38A CTR 向量），再接入 `AesCryptoProvider`；
5. **CMAC**（组员 B）：实现后先用 RFC 4493 的标准向量验证，
   再在 `AesCryptoProvider` 中实现 `cmac()` / `verifyCmac()`；
6. **安全协议层**：在 `include/protocol/` 与 `src/security/` 中实现
   `HELLO → AUTH → KEY_EXCHANGE → KEY_CONFIRM → ESTABLISHED` 状态机；
   收发数据时：

   ```cpp
   // 发送：先加密，再对"头部 + 密文"计算 CMAC（Encrypt-then-MAC）
   Bytes cipher = crypto->aesCtrEncrypt(sessionKey, nonce, plaintext);
   MacTag tag  = crypto->cmac(sessionKey, headerBytes + cipher);
   Frame frame = /* 把 header + cipher + tag 组装进 payload */;
   network.sendFrame(frame);
   ```

7. **替换点**：真正实现替换 Mock 时，只改"创建哪个 `CryptoProvider` 实例"
   的那一处（例如工厂函数或配置），协议层与网络层代码不变。

## 9. 代码规范（本项目约定）

* C++17；类与函数使用大驼峰 / 小驼峰，成员变量以 `_` 结尾；
* 每个 `.h` 使用 include guard，避免循环依赖；
* 资源使用 RAII 管理（`Network` 析构自动 `close()`），不使用裸 `new/delete`；
* 函数尽量 `const` 正确；不引入全局可变状态（日志的最小级别除外）；
* 不使用魔法数字，长度、上限等用命名常量（如 `Frame::kMaxPayloadSize`）；
* 每个模块都要有测试；修改网络层后必须重新运行 `ctest`。
