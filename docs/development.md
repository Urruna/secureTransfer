# 开发与运行指南

## 1. 环境

| 项目 | 要求 |
| --- | --- |
| 系统 | Ubuntu 20.04（课程虚拟机 `Ubuntu6.21`） |
| 编译器 | g++ 9.4（支持 C++17） |
| 构建 | CMake ≥ 3.10（实测 3.16.3）+ make |
| 第三方依赖 | **无**（不需要 OpenSSL / Qt / 网络库） |
| 可选工具 | tcpdump（窃听演示）、openssl（独立交叉验证） |

本项目已实测通过的环境：

```text
Ubuntu 20.04.6 LTS / Linux 5.15.0-140-generic / x86_64
g++ (Ubuntu 9.4.0-1ubuntu1~20.04.3) 9.4.0
cmake version 3.16.3 / GNU Make 4.2.1
```

## 2. 部署到 `/home/securityTransfer`

```bash
cd <项目目录>
cp configs/keys.conf.example configs/keys.conf   # 首次使用时根据模板生成本地密钥文件
bash scripts/deploy_to_home.sh                   # 复制到 /home/securityTransfer 并 chown
chmod 600 /home/securityTransfer/configs/keys.conf
```

`/home` 属于 root，所以脚本内部会使用 `sudo`（会提示输入密码）。
`configs/keys.conf` 含 `K_master`，已被 `.gitignore` 排除，**不要提交**；
模板 `keys.conf.example` 使用课程实验测试值。

## 3. 编译与测试

```bash
cd /home/securityTransfer
mkdir -p build && cd build
cmake .. && cmake --build . -j4
ctest --output-on-failure
```

产物：

```text
build/alice  build/bob
build/cmac_benchmark
build/tests/test_frame                 build/tests/test_network
build/tests/test_tcp_roundtrip         build/tests/test_aes_cmac
build/tests/test_packet                build/tests/test_transcript
build/tests/test_replay_guard          build/tests/test_session_state
build/tests/test_secure_roundtrip      build/tests/test_tamper
build/tests/test_forge                 build/tests/test_replay
```

一键脚本（编译 + ctest + 演示 + 攻击测试）：

```bash
bash scripts/verify_in_vm.sh
bash scripts/verify_in_vm.sh --no-demo     # 只编译与测试
```

## 4. 运行演示

```bash
# 终端 1（Bob，服务端，先启动）
cd /home/securityTransfer/build && ./bob 9000

# 终端 2（Alice，客户端）
cd /home/securityTransfer/build && ./alice 127.0.0.1 9000
```

命令行参数：

```text
./bob    [port] [--key <配置文件>] [--mock] [--placeholder] [--quiet] [--out-dir <目录>]
                 [--id <本端身份>] [--peer <对端身份>] [--policy <策略>] [--access-log <日志>]
./alice  [host] [port] [--key <配置文件>] [--mock] [--placeholder] [--quiet]
                 [--file <路径>]... [--image <路径>]... [--data-dir <目录>]
                 [--id <身份>] [--policy <策略>] [--whoami] [--view-log]
```

* `--key`：指定密钥配置文件（默认按 `configs/keys.conf`、`../configs/keys.conf` 等候选路径查找）；
* `--mock`：使用 `MockCryptoProvider`（加密与 MAC 都是占位实现，仅用于联调）；
* `--placeholder`：仍用真实 AES-CTR，但把 MAC 换成占位实现，
  用于演示"密码算法与协议层解耦"（会打印警告）；
* `--quiet`：关闭握手每一步的日志（演示时更干净）。
* `--file <路径>` / `--image <路径>`（Alice）：在 4 条文本消息之后把文件 / 图像安全传给 Bob，
  可重复使用；相对路径会自动到 `--data-dir`（默认 `experiment_data/`）里查找；
* `--out-dir <目录>`（Bob）：接收到的文件 / 图像保存目录，默认 `experiment_data/received`。
* `--id <身份>`：覆盖本端身份（Alice 演示不同角色时用，例如 `--id mallory`）；
* `--peer <身份>`（Bob）：本次接受的**对端身份**，握手时会校验（防止冒充）；
* `--policy <文件>`：访问控制策略文件，默认 `configs/access_policy.conf`；
* `--access-log <文件>`（Bob）：审计日志，默认 `experiment_data/access_log.txt`；
* `--whoami` / `--view-log`（Alice）：查询自己的角色与权限 / 查看服务端审计日志（仅管理员）。

### 4.2 访问控制演示

```bash
# 场景 1：管理员（全部允许，并能查看审计日志）
cd /home/securityTransfer/build
./bob 9000 --peer alice --out-dir ../experiment_data/received --access-log ../experiment_data/access_log.txt &
./alice 127.0.0.1 9000 --id alice --whoami --view-log \
    --file test_file_64KB.bin --image test_image_256x256.png

# 场景 2：访客（只能发短消息；文件/图像/查看日志都会被拒绝，但不中断会话）
./bob 9001 --peer mallory --out-dir ../experiment_data/received --access-log ../experiment_data/access_log.txt &
./alice 127.0.0.1 9001 --id mallory --whoami --view-log \
    --file test_file_64KB.bin --image test_image_256x256.png
```

策略与权限矩阵见 `configs/access_policy.conf`，
判定流程、实测输出与局限说明见 [`access_control.md`](access_control.md)。

### 4.3 图形界面（Qt5，课程要求 8）

```bash
# 首次使用需要安装 Qt5 开发包（约 100 MB）
sudo apt install -y qtbase5-dev

# 编译（未安装 Qt 时该目标会自动跳过，不影响命令行程序与测试）
cd /home/securityTransfer/build && cmake .. && cmake --build . -j4

# 在虚拟机桌面里启动（图形界面需要桌面会话）
DISPLAY=:0 ./st_ui                    # 纯界面操作
DISPLAY=:0 ./st_ui --server --id bob --peer alice --auto   # 自动开始会话（演示/截图）
./st_ui --help                        # 查看全部命令行参数
```

界面支持：选择角色（客户端/服务端）与身份、显示握手与会话状态、发送短消息、
发送文件/图像（带进度条与 CRC32 校验结果）、查询角色权限、查看审计日志、
一键 Eve 攻击演示（篡改 / 重放）。

一键演示（两个场景 + 自动截图）：

```bash
bash scripts/ui_demo.sh
bash scripts/ui_demo.sh --no-shot      # 只跑演示不截图
```

说明与截图见 [`ui.md`](ui.md)、[`screenshots/`](screenshots/README.md)。

### 4.1 文件与图像传输演示

```bash
# 终端 1（接收端）
cd /home/securityTransfer/build && ./bob 9000 --out-dir ../experiment_data/received

# 终端 2（发送端）：文件 + 图像（小图走单包，大图自动分块）
cd /home/securityTransfer/build && ./alice 127.0.0.1 9000 \
    --file test_file_64KB.bin --file test_file_1MB.bin \
    --image test_image_256x256.png --image test_image_1024x768.png

# 逐字节核对接收结果（期望全部一致）
cd /home/securityTransfer/实验数据
for f in test_file_64KB.bin test_file_1MB.bin test_image_256x256.png test_image_1024x768.png; do
    cmp "$f" "received/$f" && echo "$f 一致"
done
```

实验数据的说明（每个文件的大小与用途）见 [`experiment_data/README.md`](../experiment_data/README.md)，
协议与实测数据见 [`file_transfer.md`](file_transfer.md)。

日志级别：

```bash
ST_LOG_LEVEL=DEBUG ./alice 127.0.0.1 9000     # 更详细
ST_LOG_LEVEL=WARN  ./bob 9000                 # 只看警告与错误
```

## 5. 密码算法的接入方式与替换方法（已完成接入）

第一部分交付了自实现的 `AES`（`aes.cpp`）与 `CMAC`（`cmac.cpp`），
二者通过下面这一层接缝接入协议：

```text
第一部分交付物                     第二部分（协议层）
──────────────                    ──────────────────
AES  (aes.cpp)     ──┐
CMAC (cmac.cpp)    ──┴─▶ CmacEngine (MacEngine)  ──▶ AesCryptoProvider (CryptoProvider)
                                                       │
                                                       ▼
                                              Packet / 握手 / SecureSession
```

* `include/crypto/cmac_engine.h` 是**唯一的粘合代码**（约 30 行，只做转发）；
* 第一部分的算法文件原样保留，**没有为了配合协议而修改任何一行**；
* 默认行为：`AesCryptoProvider provider;` → 真实 AES-CTR + 真实 CMAC；
* 若要替换算法实现（例如与库实现做对比），实现 `MacEngine` 接口后传入即可：

```cpp
class LibraryMacEngine : public MacEngine { /* 调用库实现 */ };
AesCryptoProvider provider(new LibraryMacEngine());   // 协议层代码零改动
```

标准向量回归测试在 `tests/unit/test_aes_cmac.cpp`：
FIPS-197 单分组、NIST SP 800-38A CTR、RFC 4493 的 4 条 CMAC 向量，
以及"默认使用真实 CMAC""显式切换占位实现"两条接缝测试。

## 6. 局域网 / 跨主机测试

```bash
# Bob 所在主机
./bob 9000

# Alice 所在主机（把 host 换成 Bob 的 IP）
./alice 192.168.x.x 9000
```

两台主机上的 `configs/keys.conf` 必须**完全一致**（同一个 `K_master`），
否则会看到 `Authentication Failed`——这本身就是认证机制生效的证据。

Bob 默认绑定 `0.0.0.0`，如果连不上请检查 `sudo ufw allow 9000/tcp` 与网段是否互通。

## 7. 窃听演示（需要 tcpdump 与 sudo）

```bash
bash scripts/capture_eve.sh 9101 "Hello Bob"
```

脚本会：启动抓包 → 跑一次 Alice/Bob → 停止抓包 → 检索明文关键字。
期望 `plaintext_hits = 0`（抓包里只有密文），而 Alice/Bob 的日志中该关键字出现次数 > 0。

也可以手工分析：

```bash
sudo tcpdump -U -i lo -X port 9101 -w /tmp/eve.pcap
strings /tmp/eve.pcap | grep -c "Hello Bob"      # 期望 0
```

## 8. 独立交叉验证（可选，证明"协议用对了算法"）

虚拟机自带 OpenSSL 1.1.1f，可用它独立验算我们自己的实现：

```bash
# AES-128-CTR：与我们的密文逐字节对比
printf 'Hello Bob!' | openssl enc -aes-128-ctr \
    -K 000102030405060708090a0b0c0d0e0f -iv <16 字节 nonce hex> | xxd -p

# CMAC：与第一部分的实现对比（iv 全 0）
printf '...' | openssl dgst -mac cmac -macopt cipher:aes-128-cbc \
    -macopt hexkey:000102030405060708090a0b0c0d0e0f
```

**注意**：OpenSSL 只用于交叉验证，不参与我们的实现（课程要求 4）。

## 9. 常见问题

| 现象 | 原因与处理 |
| --- | --- |
| `connect() 失败: errno 111 (Connection refused)` | Bob 还没启动，或端口写错 |
| `TCP server listening on 0.0.0.0:xxxxx` 端口与预期不同 | 启动时传了 `0`，由系统分配端口（测试用） |
| `Authentication Failed` | 两端 `configs/keys.conf` 的 `master_key` 不一致 |
| `CMAC verification failed` | 数据被篡改（正常的安全行为）；检查是否有中间环节改动字节 |
| `Replay Attack Detected` | 收到了重复的数据包（正常的安全行为） |
| 启动时提示密钥文件对 group/other 可读 | `chmod 600 configs/keys.conf` |
| `Clock skew detected` / make 报文件时间在未来 | 从 Windows 拷贝进来的文件时间戳问题：`find /home/securityTransfer -exec touch {} +` |
| 中文日志乱码 | 终端编码不是 UTF-8：`export LANG=C.UTF-8`；Windows 侧读取日志请按 UTF-8 解码 |
| `test_*` 偶发失败并提示端口相关错误 | 端口被占用；测试用例使用系统分配端口，一般不会发生 |

## 10. 代码规范（本项目约定）

* C++17；类名大驼峰，函数小驼峰，成员变量以 `_` 结尾；
* 每个头文件使用 include guard，避免循环依赖；
* 统一使用 `uint8_t` / `Bytes` 存放数据，**不使用 `char*` 存二进制**；
* 资源用 RAII 管理，不使用裸 `new/delete`（`AesCryptoProvider` 传入的 `MacEngine*` 由调用方持有）；
* 不使用魔法数字：长度、上限、标签等都用命名常量；
* 每个模块都要有测试；修改后必须重新运行 `ctest`（含第一阶段的 27 个回归用例）；
* 禁止把密钥写入日志（只允许写密钥指纹）。
