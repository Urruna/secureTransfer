# 第二部分实施方案：安全通信协议与网络

> 面向课程项目《安全的信息传输套件》（课程需求：`docs/project_q1.md`）的 **第二部分**：
> TCP、数据包格式、身份认证、Session Key 分发、会话管理、防重放。
>
> 本文档是**方案**（设计 + 步骤 + 验收标准），不是最终交付报告。
> 文中区分三类陈述：**【已验证】**（本次实际执行得到的事实）、**【已有材料】**（读取现有文件得到）、**【建议/待决策】**（设计选择，需你确认）。

---

> ## 【2026-09-26 更新】本方案已实施完成
>
> 代码已落地在 **`projects/securityTransfer/`**（71 个文件、约 9200 行），
> 并部署到虚拟机 `/home/securityTransfer`。实测结果：
>
> * 编译通过（`-Wall -Wextra` 无警告）；
> * `ctest` **12 个测试程序全部通过**（含第一阶段 27 个回归用例、AES 标准向量回归）；
> * Alice/Bob 端到端演示成功：完整握手 + 4 条测试消息 + 双向确认 + CLOSE，双方退出码 0；
> * 篡改 / 身份伪造 / 数据包重放 / 窃听四项安全测试**全部按预期被阻止 / 无泄漏**。
>
> 实施过程中对方案做了若干修订（SessionId 改为 8 字节、包头由 49 改为 41 字节、
> 防重放改为两阶段提交等）。**§16「实施结果与方案修订」记录了全部差异与实测数据**，
> 阅读时建议先看 §16；§5–§7 保留原始设计草案，便于对照"计划 vs 实际"。
>
> ---
>
> ## 【2026-09-26 第二次更新】第一部分 AES + CMAC 已交付并完成集成
>
> 第一部分把自实现的 **AES-128 + CMAC**（C++ 工程 `SecureTransfer`）交付过来后，已：
>
> * 把算法接入协议栈（`CmacEngine` 适配，**算法源码零修改**），
>   完整性保护由占位实现**升级为真实 CMAC**（RFC 4493）；
> * 补充标准向量回归测试：FIPS-197、NIST SP 800-38A、RFC 4493 全部通过；
> * 整理项目结构：课程需求 `project_q1.md`、组内 `team_interfaces_original.md`、本文件、
>   第一部分交付原件（`reference/part1-aes-cmac/`）全部并入
>   `projects/securityTransfer/`，`projects/` 下不再散落文件；
> * 重新在虚拟机中实测：**12 个测试程序全部通过**，端到端演示与四项攻击测试全部通过。
>
> 详细内容见 **§17「第二轮：资源整合与 CMAC 集成」**。
>
> ---
>
> ## 【2026-09-26 第三次更新】性能对比与局域网双机测试已完成
>
> * **要求 5（性能对比）**：新增 `tools/crypto_benchmark`，把自实现的 AES-CTR / CMAC
>   与 OpenSSL 在 1 KB / 64 KB / 1 MB / 10 MB / 100 MB 上对比，并额外做了
>   "禁用 AES-NI 的纯软件对比"与正确性交叉验证 → 详见 `docs/performance.md`；
> * **要求 6（网络传输）**：新增 `scripts/lan_test.sh`，在**两台独立主机**
>   （各自独立网卡/IP/路由/ARP）之间完成握手与数据传输，并用抓包证明
>   （含 TCP SYN/SYN-ACK、ARP 记录、明文零泄露）→ 详见 `docs/lan_test.md`；
> * 结论摘要：默认情况下 OpenSSL 快 4.7~82 倍，**关掉 AES-NI 后只快 2.7~3.6 倍**
>   —— 差距主要来自硬件加速，其次才是工程优化。
>
> 详细内容见 **§18「第三轮：与库实现的性能对比 + 局域网双机测试」**。
>
> ---
>
> ## 【2026-09-28 第四次更新】文件与图像安全传输已完成（课程要求 9）
>
> * 新增应用层 `include/application/` + `src/application/`：
>   **文件走 `FILE_START/CHUNK/END` 分块（64 KiB）**，**小图像走单包 `IMAGE`**，
>   **大图像自动分块**；每一块都复用第二部分的安全通道，
>   因此自动获得加密 + CMAC + 防重放，无需任何新的密码学代码；
> * 端到端校验：接收端重组后比对**总字节数**与**整文件 CRC32**（自实现），
>   实测 4 个文件全部逐字节一致（`cmp` 与 sha256 双重核对）；
> * 实验数据统一放在 **`experiment_data/`**（主机与虚拟机各保留一份完全相同的副本，
>   接收结果也各自留档）；
> * 新增 2 个测试程序（`test_transfer_meta`、`test_file_transfer`），
>   `ctest` 由 12 个增加到 **14 个，全部通过**。
>
> 详细内容见 **§19「第四轮：文件与图像安全传输」**，专项文档见 `docs/file_transfer.md`。
>
> ---
>
> ## 【2026-09-28 第五次更新】访问控制已完成（课程要求 7 的最后一块）
>
> * 新增 `src/security/access_control.cpp` + `configs/access_policy.conf`：
>   **身份 → 角色 → 权限** 三层模型，策略写在配置文件里，改策略不用改代码；
> * **服务端权威判定 + 默认拒绝**：未登记身份落到 `guest` 角色，角色未定义权限时无权限；
> * **拒绝操作但不中断会话**（与"篡改/重放导致断连"区分开），
>   被拒绝的传输后续数据块会被丢弃、**不落盘**；
> * **审计日志**记录每次允许/拒绝（时间、身份、角色、操作、结果），
>   管理员可用 `--view-log` 查看；`--whoami` 可查询自己的角色与权限；
> * 实测：管理员 alice 全部允许（含查看日志），访客 mallory 的 `send_file` /
>   `send_image` / `view_log` 全部被拒绝、短消息正常、会话不中断；
> * `ctest` 由 14 个增加到 **16 个测试程序，全部通过**。
>
> 详细内容见 **§20「第五轮：访问控制」**，专项文档见 `docs/access_control.md`。
>
> ---
>
> ## 【2026-09-28 第六次更新】图形界面已完成（课程要求 8）
>
> * 技术选型：**Qt 5.12 Widgets（C++）**，与安全内核同进程，直接调用
>   `SecureSession` / `FileSender` / `AccessController` ——
>   **界面不实现任何密码学逻辑**（满足要求 4）；
> * 界面功能：角色与身份配置、握手与会话状态、短消息、文件/图像传输
>   （进度条 + CRC32 校验结果）、访问控制查询（WHOAMI / 查看审计日志）、
>   **一键 Eve 攻击演示**（篡改 / 重放）、运行日志；
> * 线程模型：`SessionWorker` 独占安全会话（阻塞接收放在工作线程），
>   GUI 线程只负责画界面，通过加锁队列下发命令；
> * 实测：图形界面分别作为**服务端**与**客户端**完成完整会话
>   （4 条消息 + 1 MB 文件 + 图像 + 命令），截图存于 `docs/screenshots/`；
> * 本轮还**发现并修复了一个真实缺陷**：两端互相"自动回复"导致死循环
>   （实测产生 34,000+ 条消息、12.8 MB 审计日志），
>   现已用 `ACK:` 前缀约定修复（`include/common/demo_reply.h`）。
>
> 详细内容见 **§21「第六轮：图形界面」**，专项文档见 `docs/ui.md`。
>
> ---
>
> ## 【2026-10-01 第七次更新】路径英文化 + GitHub 首次备份 + 启动 Windows 迁移
>
> * **路径与文件名统一改为英文**（正文仍为中文）：`实验数据/` → `experiment_data/`、
>   `接收结果/` → `received/`、`文本消息.txt` → `text_messages.txt`、
>   `测试文件-*.bin` → `test_file_*.bin`、`测试图片-*.png` → `test_image_*.png`、
>   `接口.md` → `team_interfaces_original.md`、`使用说明.pdf` → `usage_notes.pdf`。
>   共改名 1 个目录 + 12 个文件，并同步替换了 20 个文件里的 69 处路径引用；
>   目的是**为迁移到 Windows 做准备**（Windows 默认 ANSI 是 GBK，
>   源码里的 UTF-8 中文路径容易打不开文件）。
>   改动后已重新干净部署并全量回归：**16 个测试全通过、6 步验证全 PASS**；
>   虚拟机内 `find` 确认**零非 ASCII 路径名**。
> * **GitHub 首次备份**：仓库 <https://github.com/Urruna/secureTransfer>（Private）。
>   由于当时 Windows 主机尚未安装 git，先在 Linux 虚拟机内建立仓库
>   （`git init` + 首次提交 + 标签 `v1.0-linux-verified`），再把 `.git` 取回主机，
>   并用"主机工作区 → 虚拟机原仓库 `git status`"的方式验证了**内容与提交完全一致**。
>   入选 132 个文件 / 4.92 MB；排除 `build/`、`reference/.../.vs`（579 MB）、
>   `Debug/`、`x64/`、`configs/keys.conf`（含 K_master）、`experiment_data/received/`、
>   `access_log.txt` 与各类二进制，共 585 MB 未入库。
>   随后主机安装了 **Git for Windows 2.47.1（D:\AppGallery\Git）**，
>   把提交署名改为 Urruna <1956274291@qq.com>，分支改名为 `main`，
>   推送到 GitHub 并打好标签。
> * **下一步**：按迁移路线 A 推进（M1 先在 Windows 编译无平台依赖的库与测试，
>   M2 移植网络层到 Winsock2，M3 处理 UTF-8→UTF-16 路径，M5 编译 Qt 界面）。
>   方案全文见 §22。

---

## 0. 摘要（先看这一节）

结论：**第二部分的骨架已经存在且能跑**，不需要从零开始。

| 能力 | 现在有什么 | 第二部分要做到 | 归属 |
| --- | --- | --- | --- |
| TCP 连接、分帧、粘包拆包 | 【已验证】`/home/SecureTransfer` 第一阶段代码，编译通过、`ctest` 3/3 套件通过 | 直接复用，**不改 STABLE API** | 第二部分（已完成） |
| 统一数据包格式 | 仅有 `Frame = length + payload`，无协议头 | 新增 41 字节 Packet 头（Magic/Version/Type/Direction/SessionId(8)/Sequence/Nonce/Length）+ 16 字节 CMAC | 第二部分 |
| 身份认证 | 无，任何人都能连上 Bob | `K_master` 预共享 + Challenge-Response（Nonce_A/Nonce_B + CMAC）双向认证 | 第二部分 |
| Session Key 分发 | 无 | `K_session = 000102...0F` 用 `K_master` 包裹后传输 + `KEY_CONFIRM` 双方确认 | 第二部分 |
| 会话管理 | 无 | 会话状态机 + SessionId + 握手超时 + 统计计数 | 第二部分 |
| 防重放 | 无 | Sequence 严格递增检查 + 每方向独立计数 + Nonce 结构保证不重复 | 第二部分 |
| AES / CMAC 算法 | 【已有材料】AES 在 Windows：`D:\圈圈\课程\算法设计与实验\AES\大作业`，C 语言实现，已有 FIPS-197 向量自测；**CMAC 尚未编写** | 只对接，不实现（属于第一部分） | 第一部分 |

第二部分的**工作量重心**在三处：

1. 定义并冻结**包格式与接口**（一旦第三部分开始写 UI，接口就不能再改）；
2. 实现**握手状态机**（HELLO → 认证 → 密钥分发 → 确认），这是最容易出错、也最容易被提问的部分；
3. 把**加密 + 完整性 + 防重放**正确地组合起来（Encrypt-then-MAC、Nonce 不重复、Sequence 拒绝重放），并用篡改/伪造/重放测试证明它真的有效。

---

## 1. 素材与现状盘点

### 1.1 已有材料

| 材料 | 位置 | 本次读取到的内容 |
| --- | --- | --- |
| 课程要求 | `docs/project_q1.md` | 10 项要求 + 步骤 1–10；第二部分 = TCP / 数据包格式 / 身份认证 / Session Key 分发 / 会话管理 / 防重放 |
| 组内接口约定 | `docs/team_interfaces_original.md` | `AES::encryptBlock`、`AES::encryptCTR`、`CMAC::generate/verify`、`Network::connect/listen/accept/sendFrame/receiveFrame/close`、`struct Frame` |
| AES 成果 | `D:\圈圈\课程\算法设计与实验\AES\大作业\` | `aes.h` / `aes.c` / `test.c`；导出 `aes_key_expand`、`aes_encrypt_block`、`aes_ctr_xor`；`test.c` 含 5 条自测（FIPS-197 单块向量 + 4 条 CTR 往返） |
| 第一阶段链路 | Ubuntu6.21 虚拟机 `/home/SecureTransfer`（源码 + `build/`）；备份 `/home/urruna/SecureTransfer.zip` | Frame / Network / Alice / Bob + 3 个测试程序 + 6 份 docs |

> 说明：上表记录的是**第一轮开始时的位置**。项目整理完成后，课程需求与组内约定
> 已移入本目录的 `docs/`（`docs/project_q1.md`、`docs/team_interfaces_original.md`），
> 第一阶段的代码与文档分别保留在本工程的 `include/network`、`src/network`、
> `tests/` 与 `docs/stage1/` 中；第一阶段代码在虚拟机里仍有一份原样副本
> `/home/SecureTransfer`（未改动，仅作备份）。

**`aes.h` 导出的接口（第二部分需要按这个对接）：**

```c
void aes_key_expand(const uint8_t key[16], uint8_t rk[176]);
void aes_encrypt_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]);
void aes_ctr_xor(const uint8_t rk[176], const uint8_t nonce[16], uint8_t* data, size_t len);
```

注意三点（对第二部分很关键）：

1. `aes_ctr_xor` 是**原地 XOR**，加密和解密是同一个函数（CTR 的特性）；
2. 它把 `nonce` 当作**初始计数器块**，内部按**大端整体自增 128 位**（`inc128_be`）——这直接决定了 Nonce 的结构设计（见 §7.1）；
3. 它是 C 语言接口（`aes.c` 按 C 编译），且 `aes.h` 与源文件里的中文注释是 **GBK 编码**，在 Ubuntu 下用 UTF-8 打开是乱码，C++ 里直接 `#include` 还会遇到 name mangling 问题（见 §10）。

### 1.2 第一阶段成果的实际状态【已验证】

本次在 Ubuntu6.21 虚拟机里重新执行：

```text
$ cd /home/SecureTransfer/build && cmake --build . && ctest --output-on-failure

[ 23%] Built target st_network
[ 38%] Built target bob
[ 53%] Built target alice
[ 69%] Built target test_tcp_roundtrip
[ 84%] Built target test_network
[100%] Built target test_frame

1/3 Test #1: test_frame .......................   Passed    0.01 sec
2/3 Test #2: test_network .....................   Passed    0.31 sec
3/3 Test #3: test_tcp_roundtrip ...............   Passed    0.03 sec
100% tests passed, 0 tests failed out of 3
```

即：**编译能过、27 个用例（12+10+5）当前全部通过**，这构成后续开发的**回归基线**。改任何东西之后，这 27 个用例必须继续全绿。

### 1.3 虚拟机环境【已验证】

| 项目 | 实测值 |
| --- | --- |
| 虚拟机 | VMware Workstation 17 里的 `Ubuntu6.21`（`D:\ctf\ubuntu\newtry6.21\Ubuntu6.21.vmx`），当前处于开机状态 |
| 系统 | Ubuntu 20.04.6 LTS (focal)，内核 `5.15.0-140-generic`，x86_64，2 vCPU / 4 GB |
| 网络 | NAT，guest IP `192.168.111.139`（宿主 `192.168.111.1`，NAT 网关 `192.168.111.2`） |
| 编译器 | g++ 9.4.0（C++17 可用） |
| 构建 | CMake 3.16.3 + GNU Make 4.2.1；git 2.25.1；python3 3.8.10 |
| 密码学库 | OpenSSL 1.1.1f，`/usr/include/openssl/evp.h` 存在（**libssl-dev 已装**） |
| 抓包工具 | `tcpdump`、`wireshark`、`nc`、`socat`、`xxd` 均已安装 |
| 项目路径 | `/home/SecureTransfer`（课程要求路径） |

两个直接结论：

* **没有依赖问题**：`libssl-dev` 已装，第一部分要做「与库的性能对比」、我们要做「协议层独立交叉验证」都不需要再装包；
* **虚拟机里没有 AES 代码**：`find /home -iname '*aes*'` 无结果。AES 成果目前在 Windows 主机上，需要导入（见 §10）。

### 1.4 能力缺口清单

| 缺口 | 影响的要求 | 本方案对应章节 |
| --- | --- | --- |
| 无协议头（无法表达 Type/SessionId/Sequence/Nonce） | 要求 7、要求 9 | §5 |
| 无认证，任何人都能连 Bob | 要求 7、Eve 伪造演示 | §6.3 |
| 无会话密钥分发 | **要求 1（10 分）** | §6.4 |
| 无加密数据通道 | **要求 2（10 分）** | §7 |
| 无完整性保护与篡改拒绝 | **要求 3（10 分）** | §7.3 |
| 无重放检测 | 要求 7、Eve 重放演示 | §7.2 |
| CMAC 算法本身缺失 | 要求 3（第一部分） | §10.3 |

---

## 2. 第二部分的目标与边界

### 2.1 要做（本方案的范围）

```text
第二部分交付物
├── D1  统一数据包格式（Packet）与编解码 + 单元测试
├── D2  握手协议状态机：HELLO → HELLO_ACK → AUTH → KEY_REQUEST
│                       → KEY_EXCHANGE → KEY_CONFIRM → KEY_CONFIRM_ACK → ESTABLISHED
├── D3  基于 K_master 的双向身份认证（Challenge-Response + CMAC）
├── D4  Session Key 安全分发与双方确认（K_session = 000102...0F）
├── D5  会话管理：SessionId、状态机、超时、统计计数
├── D6  数据阶段的机密性/完整性/防重放（Encrypt-then-MAC + Sequence）
├── D7  安全测试：篡改 / 伪造身份 / 重放 / 窃听（可复现的测试程序）
└── D8  对外接口 SecureSession（供第三部分 UI / 文件 / 图像直接调用）
```

### 2.2 不做（属于其他部分）

| 不做的事 | 归属 | 我们只负责什么 |
| --- | --- | --- |
| AES-128 单块 / CTR / CMAC 算法实现与标准向量 | 第一部分 | 定义并调用 `CryptoProvider` 接口 |
| 100 MB 级性能对比 benchmark | 第一部分 | 不涉及（可在协议层复用其 API） |
| Qt GUI、文件/图像传输、访问控制 | 第三部分 | 提供 `sendMessage(type, bytes)` 通用接口并预留 Type 值 |
| Eve 演示的展示脚本 | 第三部分 | 提供可复现的攻击注入测试与日志输出 |

> 【建议】访问控制（Role/Permission）虽然课程放在「安全协议」一节，但按 `project_q1.md` 第 7 节的分工属于第三部分。第二部分只在握手完成后把**认证出的身份**（`Alice_ID` / `Bob_ID`）交给上层，权限判断交给第三部分，避免重复实现。

### 2.3 与其他部分的接口契约（必须尽早确认）

```text
第一部分                        第二部分                        第三部分
─────────                       ─────────                       ─────────
AES / CMAC 实现        ──▶      Packet 编解码 / 握手状态机  ──▶   UI、文件、图像
CryptoProvider 接口             SecureSession 门面              访问控制、Eve 演示
                                Network（第一阶段成果）
```

* 我们**向上**承诺：`SecureSession`（§4.3）不变；
* 我们**向下**要求：`CryptoProvider`（§4.2）不变；
* 我们**不改**：`Network` / `Frame` 的 STABLE API（这是第一阶段已经验证过的资产）。

---

## 3. 总体设计

### 3.1 分层

```text
        ┌──────────────────────────────────────────────┐
        │  第三部分：UI / 短消息 / 文件 / 图像 / 访问控制  │
        └───────────────────┬──────────────────────────┘
                            │  sendMessage(type, bytes)
                            ▼
        ┌──────────────────────────────────────────────┐
        │  第二部分：SecureSession                      │
        │  ┌────────────────────────────────────────┐  │
        │  │ 握手状态机 Handshake（认证 + 密钥分发）  │  │
        │  ├────────────────────────────────────────┤  │
        │  │ 记录层 Record：加密 / CMAC / 防重放      │  │
        │  ├────────────────────────────────────────┤  │
        │  │ Packet 编解码（字节 ↔ 结构体）           │  │
        │  └────────────────────────────────────────┘  │
        └───────────────────┬──────────────────────────┘
                            │  调用 CryptoProvider（接口，不关心谁实现）
                            │  调用 Network::sendFrame / receiveFrame
                            ▼
        ┌───────────────────────────┐   ┌────────────────────────────┐
        │ 第一阶段：Network + Frame │   │ 第一部分：AES / CMAC 实现    │
        │ （不改动，直接复用）        │   │ （通过 CryptoProvider 接入） │
        └───────────────────────────┘   └────────────────────────────┘
```

### 3.2 六条设计原则

1. **安全逻辑全部放在 `Frame::payload` 内部。**
   第一阶段文档已经预留了这个扩展点：「Frame 的 payload 里放明文还是密文，对 `Network` 来说是一样的」。这样包格式怎么演进，都不需要动网络层，第一阶段的 27 个用例继续有效。

2. **Encrypt-then-MAC。**
   先 AES-CTR 加密得到 Body，再对「头部 + Body」算 CMAC。顺序不能反：先 MAC 后加密（MAC-then-Encrypt）会引入额外的安全性论证负担，Encrypt-then-MAC 可以直接拒绝任何被改动的包，且不需要先解密。

3. **长度字段必须进 MAC。**
   `Frame` 自己带的 4 字节长度是**网络层的**，不在 CMAC 覆盖范围内；所以 Packet 头里保留自己的 `PayloadLen` 并把它算进 CMAC，否则攻击者可以截断/拼接 Body 而不被发现。

4. **方向和身份必须进 MAC。**
   头部带 `Direction` 字节（0x01 = Alice→Bob，0x02 = Bob→Alice），且握手 MAC 输入带方向标签。否则存在**反射攻击**：把 Bob 发给 Alice 的消息原样发回给 Bob，MAC 依然成立。

5. **Nonce 不重复要在结构上保证，不靠「随机应该不会撞」。**
   见 §7.1——这是 CTR 模式的生死线（Nonce 复用 ⇒ 密钥流复用 ⇒ 明文可被异或恢复）。

6. **握手阶段不依赖加密，只依赖 MAC。**
   HELLO / AUTH 等消息的 Body 是明文（但被 CMAC 保护，防止篡改与伪造）；只有 Session Key 的包裹体是加密的。理由：加密需要 `K_session`，而 `K_session` 正是握手要分发的东西，不能循环依赖。

---

## 4. 冻结接口

### 4.1 `include/common/types.h`（第一部分、第二部分共用）

```cpp
#pragma once
#include <array>
#include <cstdint>
#include <vector>

using Byte  = uint8_t;                      // 统一用无符号：中文/高位字节不会出错
using Bytes = std::vector<Byte>;

using Key128    = std::array<Byte, 16>;     // AES-128 密钥
using Block128  = std::array<Byte, 16>;     // AES 分组
using Nonce     = std::array<Byte, 16>;     // CTR 初始计数器块
using MacTag    = std::array<Byte, 16>;     // CMAC 输出
using SessionId = std::array<Byte, 16>;     // 会话标识【待决策 D1，见 §13】

enum class Direction : Byte { kClientToServer = 0x01, kServerToClient = 0x02 };
```

> 【已有材料】`projects/team_interfaces_original.md` 与第一阶段 `docs/architecture.md` 把 `Bytes / Key128 / Nonce / MacTag` 定为 16 字节。
> **【已决策 D1】** `SessionId` 最初在本方案里按组内约定写成 16 字节，但 `project_q1.md` §5 的建议格式是 **8 字节**。
> 实施时按你的要求**采用课程规定的 8 字节**，因此包头由草案的 49 字节变为 41 字节（见 §16.3）。

### 4.2 `include/crypto/crypto_provider.h`（第一部分实现，第二部分调用）

这是**唯一的算法接缝**。第二部分只认这个接口，不关心背后是「自己写的 AES」还是别的实现。

```cpp
class CryptoProvider {
public:
    virtual ~CryptoProvider() = default;

    // CTR 加密与解密是同一个运算（对称性），保留两个名字只为可读性
    virtual Bytes aesCtrEncrypt(const Key128& key, const Nonce& nonce,
                                const Bytes& plaintext)  = 0;
    virtual Bytes aesCtrDecrypt(const Key128& key, const Nonce& nonce,
                                const Bytes& ciphertext) = 0;

    // CMAC over arbitrary length
    virtual MacTag cmac      (const Key128& key, const Bytes& data) = 0;
    virtual bool   verifyCmac(const Key128& key, const Bytes& data,
                              const MacTag& tag) = 0;   // 内部做常数时间比较
};
```

约束（写进接口注释，避免后面扯皮）：

* `verifyCmac` 必须用**常数时间比较**（不要用 `memcmp` 提前返回）；
* `aesCtrEncrypt/Decrypt` 必须支持**任意长度**（0 字节、1 字节、不是 16 的倍数、1 MB）；
* 不允许在内部打印密钥（只能 `DEBUG` 级别且默认关闭）。

同时提供一个**开发期 Mock**（第一阶段 `docs/development.md` 已建议）：

```cpp
// include/crypto/mock_crypto_provider.h
// WARNING: development-only mock implementation - 不可用于任何真实场景
class MockCryptoProvider : public CryptoProvider { /* 可逆的伪运算占位 */ };
```

价值：**第一部分的真 AES/CMAC 到位之前，第二部分就能把协议跑通并做完单元测试**，两块工作可以并行。

### 4.3 `include/security/session.h`（第二部分对外，第三部分调用）

```cpp
enum class SessionState {
    kDisconnected, kTcpConnected, kAuthenticating,
    kKeyExchange, kEstablished, kClosing, kFailed
};

struct SessionConfig {
    std::string localId;        // "alice" / "bob"
    std::string peerId;         // 期望的对端身份，用于认证校验
    std::string host;           // 客户端用，例如 "127.0.0.1"
    uint16_t    port = 9000;
    std::string masterKeyFile;  // K_master 的读取路径（见 §8）
    int         handshakeTimeoutMs = 5000;
    int         ioTimeoutMs        = 10000;
};

struct ProtocolStats {           // 给第三部分的「传输状态」界面用
    uint64_t sentPackets = 0, receivedPackets = 0;
    uint64_t rejectedReplay = 0, rejectedMac = 0, rejectedFormat = 0;
};

class SecureSession {
public:
    SecureSession(CryptoProvider& crypto, const SessionConfig& config);
    ~SecureSession();

    // 客户端：TCP connect + 完整握手；返回 true 时 state() == kEstablished
    bool connectToServer();

    // 服务端：listen + accept + 完整握手
    bool acceptOneClient();

    // 业务数据（短消息 / 文件分块 / 图像都用这一对接口）
    bool sendMessage(MessageType type, const Bytes& plaintext);
    bool receiveMessage(MessageType& type, Bytes& plaintext);

    void close();

    SessionState state() const;
    const SessionId& sessionId() const;
    const ProtocolStats& stats() const;
    const std::string& lastError() const;
};
```

这个门面一冻结，第三部分就可以并行开工（先用 Mock 跑 UI 流程，最后换真实现，只改一处工厂函数）。

---

## 5. 统一数据包格式（Packet）

> ⚠ **本节是原始设计草案**：其中包头按 16 字节 SessionId 计算（49 字节）。
> 实施时 SessionId 改为 8 字节，**实际包头为 41 字节、总开销 57 字节**，
> 其余字段与布局完全一致。以 §16.3 与 `projects/securityTransfer/docs/protocol.md` 为准。

### 5.1 放置方式：Packet 放在 `Frame::payload` 里

```text
TCP 字节流
└── Frame（第一阶段成果）:  [ length(4) ][ payload(N) ]
                                └── payload 里装的就是我们定义的 Packet：
                                    [ Packet 头(49) ][ Body(N') ][ CMAC(16) ]
```

理由：`Network::sendFrame()` / `receiveFrame()` 已经处理好了粘包/拆包、partial send/recv、长度上限、错误处理，且 27 个用例在测它。把协议头放进 payload，等于**白拿一层已被测试过的可靠传输**，同时完全不碰网络层代码。

### 5.2 字段定义

```text
偏移  长度  字段
 0     2    Magic        = 0x53 0x54 ("ST")
 2     1    Version      = 0x01
 3     1    Type         = MessageType
 4     1    Direction    = 0x01 (C→S) / 0x02 (S→C)
 5    16    SessionId
21     8    Sequence     uint64 大端
29    16    Nonce
45     4    PayloadLen   uint32 大端 = Body 字节数
49     N    Body         握手包=明文；数据包=密文
49+N  16    MacTag       CMAC
```

| 偏移 | 长度 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0 | 2 | `Magic` | 固定 `"ST"`。不匹配直接丢弃，用来快速过滤「不是本协议的字节流」 |
| 2 | 1 | `Version` | `0x01`；版本不匹配 → 拒绝（为以后升级留出口） |
| 3 | 1 | `Type` | 消息类型，见 §6.1 |
| 4 | 1 | `Direction` | `0x01` Alice→Bob，`0x02` Bob→Alice；进 MAC，防反射攻击 |
| 5 | 16 | `SessionId` | 本次会话标识；握手第一条由 Alice 随机生成，其后必须一致 |
| 21 | 8 | `Sequence` | 该方向的包序号，从 1 开始严格递增；握手包为 0 |
| 29 | 16 | `Nonce` | CTR 初始计数器块；数据包必须唯一（§7.1） |
| 45 | 4 | `PayloadLen` | Body 的字节数（不含头、不含 MAC）；**进 MAC**，防截断 |
| 49 | N | `Body` | 明文（握手包）或密文（数据包） |
| 49+N | 16 | `MacTag` | CMAC 输出 |

**包头固定 49 字节，一个包总长 = N + 65 字节。**

负载长度上限沿用 `Frame::kMaxPayloadSize = 1 MiB`，所以单个 Packet 的 Body 最大
`1048576 - 65 = 1048511` 字节。第三部分做文件传输时按 64 KiB 分块（留足余量，也便于显示进度）。

> 包头不是 16 的倍数，这是有意的：只有 `Body` 需要被 AES 按分组处理，头部只是被 CMAC 覆盖的字节串，不需要对齐。

### 5.3 MAC 覆盖范围

```text
数据包：  MAC 输入 = Packet[2 .. 49+N)      // Version 起、到 Body 结束
                                （不含 Magic 2 字节，不含 MacTag 自身 16 字节）

握手包：  MAC 输入 = 显式的握手转录串（§6.3），因为握手消息的语义字段
                     （双方 ID、两个 Nonce）比头部字段更多
```

### 5.4 与课程建议格式的差异（要在报告里说明）

| 课程 `project_q1.md` §5 建议 | 本方案 | 原因 |
| --- | --- | --- |
| Magic 2 / Version 1 / Type 1 / SessionID 8 / Sequence 8 / Nonce 16 / PayloadLen 4 | 相同，但 SessionID 用 16 字节（待决策 D1） | 对齐组内 `team_interfaces_original.md` 的统一类型 |
| 无 Direction 字段 | 增加 1 字节 `Direction` | 防反射攻击（把对端发来的合法包原样发回） |
| 无 Flags/Reserved | 也未使用 | 保持最小；将来需要时用 `Version` 升级 |

这些差异都属于**可以写进报告的设计论证**，不是偏离要求——课程给的格式是「建议」。

---

## 6. 握手协议（认证 + 密钥分发 + 会话建立）

### 6.1 消息类型

```cpp
enum class MessageType : uint8_t {
    kHello          = 0x01,  // C→S  Alice_ID
    kHelloAck       = 0x02,  // S→C  Bob_ID + MAC(K_master, 转录, "S2C")
    kAuth           = 0x03,  // C→S  MAC(K_master, 转录, "C2S")
    kKeyRequest     = 0x04,  // C→S  空 Body，MAC(K_master) 保护
    kKeyExchange    = 0x05,  // S→C  wrapped(K_session) + MAC(K_master)
    kKeyConfirm     = 0x06,  // C→S  MAC(K_session, "ST-KC-v1"||...)
    kKeyConfirmAck  = 0x07,  // S→C  MAC(K_session, "ST-KCA-v1"||...)
    kData           = 0x08,  // 双向  密文 + MAC(K_mac)
    kFileStart      = 0x09,  // 双向  （第三部分用，处理方式与 kData 完全相同）
    kFileChunk      = 0x0A,
    kFileEnd        = 0x0B,
    kImage          = 0x0C,
    kError          = 0x0D,  // 双向  1 字节错误码 + 可选说明（明文，仅用于演示提示）
    kClose          = 0x0E   // 双向  正常结束
};
```

**处理规则**：所有「带业务数据」的类型（`kData` / `kFileStart` / `kFileChunk` / `kFileEnd` / `kImage`）走**完全相同的加密 + MAC + 防重放流程**，只是 `Type` 不同。这样第三部分的文件、图像、短消息不需要各自写一套安全逻辑。

### 6.2 握手时序

```text
  Alice (客户端, 有 K_master)                                  Bob (服务端, 有 K_master)
  ───────────────────────────                                  ───────────────────────────
  TCP connect ─────────────────────────────────────────────▶  TCP accept

  ① 生成 Nonce_A(16 随机) + SessionId(16 随机)
     HELLO        Type=0x01 Dir=C→S Seq=0 Nonce=Nonce_A
     Body = L("alice")                                   ──▶  检查 Magic/Version/Type
                                                               记录 Alice_ID / Nonce_A / SessionId
  ② 生成 Nonce_B(16 随机)
     ◀──  HELLO_ACK  Type=0x02 Dir=S→C Seq=0 Nonce=Nonce_B
          Body = L("bob") + CMAC(K_master, T || L("S2C"))

  Alice 用 K_master 验证 tag_B ──▶ 认证 Bob 成功
  （同时确认 Nonce_A 被包含在 T 里 ⇒ 这是本次连接、不是旧消息）

  ③  AUTH         Type=0x03 Dir=C→S Seq=0
     Body = CMAC(K_master, T || L("C2S"))                ──▶  Bob 验证 tag_A
                                                               ⇒ 认证 Alice 成功（双向认证）
  ④  KEY_REQUEST  Type=0x04
     Body = CMAC(K_master, "ST-KREQ-v1"||...)            ──▶  Bob 生成 K_session

  ⑤  ◀── KEY_EXCHANGE Type=0x05 Seq=0
          Body = wrapped(16) + CMAC(K_master, "ST-KEYEX-v1"||...)

  Alice 验证并解包，得到 K_session

  ⑥  KEY_CONFIRM  Type=0x06
     Body = CMAC(K_session, "ST-KC-v1"||L(SessionId)||L(NonceA)||L(NonceB))
                                                         ──▶  Bob 验证成功
                                                              ⇒ 双方持有同一个 K_session
  ⑦  ◀── KEY_CONFIRM_ACK Type=0x07
          Body = CMAC(K_session, "ST-KCA-v1"||...)

  Alice 验证 ──▶ 双方进入 ESTABLISHED，初始化
                 seq_c2s = 0, seq_s2c = 0, 每方向一个随机 NoncePrefix(8)
```

对应课程 `project_q1.md` §3.1 的 `KEY_REQUEST → encrypted(K_session) → KEY_CONFIRM` 三个动作，我们额外加了 ①②③（身份认证）和 ⑦（服务端反向确认）。理由：只有 Alice 单向确认时，Bob 无法证明自己掌握的密钥与 Alice 一致；双向确认更完整，也更好演示。

### 6.3 认证转录串（Transcript）的精确定义

握手 MAC 的输入必须**无歧义**，否则会出现「不同字段拼起来字节相同」的边界攻击。因此所有字段用 **2 字节长度前缀 + 内容**（TLV）编码：

```text
L(x)  = uint16_be(x.size()) || x

T     = L("ST-AUTH-v1") || L(SessionId) || L(AliceID) || L(BobID) || L(NonceA) || L(NonceB)

tag_B = CMAC(K_master, T || L("S2C"))      // Bob 证明自己是 Bob（HELLO_ACK 携带）
tag_A = CMAC(K_master, T || L("C2S"))      // Alice 证明自己是 Alice（AUTH 携带）
```

* 固定前缀 `"ST-AUTH-v1"` 做**域分离**（domain separation），避免同一把 `K_master` 在不同用途下的 MAC 被混用；
* `"S2C"` / `"C2S"` 方向标签 ⇒ 防止把 Bob 的 tag 拿去冒充 Alice（反射）；
* 两个 Nonce 都在里面 ⇒ **新鲜的挑战-响应**：Bob 每次连接都生成新的 `Nonce_B`，Alice 必须对它做 MAC，旧的 AUTH 消息无法通过验证（防重放）。

### 6.4 Session Key 的安全分发（要求 1，10 分）

课程指定：

```text
K_session = 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
```

这是**固定值**，所以不能「用 KDF 推导出来假装分发了」，必须**真的把 16 字节传过去**，并且传输过程不能让 Eve 拿到。

**方案：用 K_master 做一次性键盘（CTR 包裹）**

```text
wrapNonce = NonceA XOR NonceB                        // 16 字节，公开值，不必保密
keystream = AES-CTR(K_master, wrapNonce, 0^16)       // 取 16 字节密钥流
wrapped   = K_session XOR keystream                  // 网络上传输的就是这 16 字节
```

理由：

* `wrapNonce` 由两个**本次会话新生成**的随机数异或得到 ⇒ 每个会话都不同 ⇒ `K_master` 下的 AES-CTR 密钥流不会复用；
* Eve 不知道 `K_master`，因此即使抓到 `wrapped` 与 `wrapNonce`，也无法恢复 `K_session`；
* 完全复用第一部分已有的 AES-CTR，不需要新算法。

【建议】把这一处封装成单一函数，方便将来替换成「真随机会话密钥」：

```cpp
// 课程实验：会话密钥是规定值，必须「分发」而不是「推导」
inline Key128 makeCourseSessionKey() { return kCourseFixedSessionKey; }
// 真实系统：随机生成 —— 只需替换这一行的实现，协议与测试都不用动
```

**KEY_CONFIRM 的意义**（课程 `project_q1.md` §3.2 明确要求）：

```text
KEY_CONFIRM = CMAC(K_session, L("ST-KC-v1") || L(SessionId) || L(NonceA) || L(NonceB))
```

Alice 能算出正确的 `KEY_CONFIRM`，说明**她确实拿到了 `K_session`**；Bob 能验证通过，说明**Bob 手里的 `K_session` 与 Alice 的一致**，且双方处于同一会话（Nonce 与 SessionId 都绑定了）。第 ⑦ 步的 `KEY_CONFIRM_ACK` 把这个结论对称地给回 Alice。

### 6.5 会话状态机

```text
                    connect()/accept()
   DISCONNECTED ──────────────────────▶ TCP_CONNECTED
                                            │
                       发送/收到 HELLO      │
                                            ▼
                                      AUTHENTICATING ──tag 验证失败──▶ FAILED
                                            │
                          双方认证通过       │
                                            ▼
                                      KEY_EXCHANGE ────解包/确认失败──▶ FAILED
                                            │
                      KEY_CONFIRM(_ACK) 通过 │
                                            ▼
                                      ESTABLISHED ──ERROR/CLOSE/超时──▶ CLOSING ─▶ CLOSED
```

规则：

* 状态机是**单线程同步**的（第一阶段 `Network` 本身就非线程安全，`docs/architecture.md` §5 已说明），不做异步/多线程，降低出错面；
* **只有在 `ESTABLISHED` 状态才允许** `sendMessage` / `receiveMessage`；其它状态调用直接返回 false 并记录 `lastError`；
* 任何状态收到不符合当前阶段的 Type（例如在 `AUTHENTICATING` 收到 `kData`）⇒ 视为协议违规，拒绝并关闭会话；
* 整个握手有超时（`handshakeTimeoutMs`，默认 5 秒），超时后关闭连接，避免程序卡死；
* 每个会话只允许一条 TCP 连接、一个 SessionId（演示够用；多客户端由第三部分决定是否需要，网络层已经支持为每个连接建独立 `Network` 对象）。

---

## 7. 数据阶段：机密性、完整性、防重放

### 7.1 Nonce 构造（CTR 模式的生死线）

**问题**：`aes_ctr_xor` 把 `nonce` 当成初始计数器，内部把整个 128 位**大端自增**（`inc128_be`），因此一条长消息会**占用连续多个计数器值**。

如果简单地令 `Nonce = prefix || msgSeq`（msgSeq 逐消息 +1），那么第 1 条消息（若有 1 MB）会用到计数器
`prefix||1` … `prefix||65537`，其中就包含第 65537 条消息要用的起始值 ⇒ **密钥流复用**。

**方案：把计数区隔离在低 32 位**

```text
Nonce(16) = Prefix(8, 会话建立时随机生成一次) || 0x00000000(4) || MsgCounter(4, 大端)
                                                                └── 该方向的消息序号
```

* 每个方向（C→S / S→C）有**独立**的 Prefix 和 MsgCounter；
* 第 m 条消息占用的计数器区间是 `[Prefix||0||m , Prefix||0||m + blocks)`，其中 `blocks = ceil(len/16) ≤ 65536`（1 MB 上限）；
* 因为 `blocks < 2^32`，不同 m 的区间**一定不相交**；又因为 `Prefix` 每会话随机、方向独立 ⇒ **不同消息、不同会话、不同方向的密钥流都不重复**；
* 剩余约束：单条消息 ≤ 2^32 个分组，单个会话消息数 < 2^32（对课程演示是天文数字）。

这个设计能直接和第一部分的 `aes_ctr_xor` 对接（把算好的 16 字节 `Nonce` 原样传进去即可），不需要改动 AES 代码。

### 7.2 Sequence 与防重放

```text
发送：seq = ++seqSend[direction]            // 从 1 开始
接收：if (seq <= lastSeq[收到的方向])        ⇒ 判定为重放，拒绝，rejectedReplay++
      else lastSeq = seq，继续校验 MAC
```

* 一个方向一个计数器（Alice 的发送序列与 Bob 的接收序列对应同一组数字）；
* 因为 TCP 保证有序，这里用**严格递增**即可覆盖重放与乱序；若将来要容忍乱序，可换成一个 64 位滑动窗口 bitmap（接口不变，属于可选扩展）；
* 判定顺序很关键：**先查重放（便宜），再验 MAC（贵）**；两种情况都必须拒绝并且**不把数据交给上层**；
* `SessionId` 也参与校验：不属于当前会话的包直接丢弃，避免「上一个会话的旧包」被当成合法数据。

### 7.3 接收处理流程（伪代码）

```cpp
bool SecureSession::receiveMessage(MessageType& type, Bytes& plaintext) {
    Frame frame;
    if (!network_.receiveFrame(frame)) return fail(network_.lastError());

    Packet pkt;
    if (!Packet::deserialize(frame.payload, pkt)) {          // ① 格式检查
        stats_.rejectedFormat++;  return false;              //    Magic/Version/长度/字段缺失
    }
    if (pkt.sessionId != sessionId_) {                       // ② 会话绑定
        stats_.rejectedFormat++;  return false;
    }
    if (pkt.direction != expectedIncoming_) {                // ③ 方向检查（防反射）
        stats_.rejectedFormat++;  return false;
    }
    if (!replayGuard_.accept(pkt.sequence)) {                // ④ 防重放（先查便宜的）
        stats_.rejectedReplay++;  log("Replay Attack Detected");
        return false;
    }
    const Bytes macInput = pkt.headerBytes() + pkt.body;     // ⑤ 完整性（Encrypt-then-MAC）
    if (!crypto_.verifyCmac(macKey_, macInput, pkt.mac)) {
        stats_.rejectedMac++;     log("CMAC verification failed");
        return false;
    }
    type = pkt.type;                                          // ⑥ 解密
    plaintext = crypto_.aesCtrDecrypt(encKey_, pkt.nonce, pkt.body);
    return true;
}
```

发送侧对称：构造 Nonce → 加密 Body → 生成头部（含 `PayloadLen`）→ 算 CMAC（头部+密文）→ 组装 Packet → `network_.sendFrame(Frame(packetBytes))`。

**注意顺序**：`PayloadLen` 与 `Sequence` 都必须在「头部」里、且在加密之前就定好，因为它们要参与 MAC。

### 7.4 失败处理策略（要做成「可演示」的）

| 情况 | 行为 | 打印/日志（演示要看得见） |
| --- | --- | --- |
| 认证失败（tag 不对） | 发送 `kError(AUTH_FAILED)` 后关闭连接 | `Authentication Failed / Connection rejected` |
| MAC 校验失败 | 拒绝该包，发送 `kError(INTEGRITY_FAILED)` 并关闭会话 | `CMAC verification failed - Message rejected` |
| 检测到重放 | 拒绝该包，关闭会话，`rejectedReplay++` | `Replay Attack Detected - Packet rejected` |
| 格式/版本/SessionId 非法 | 静默丢弃该包（不回应，避免给攻击者反馈） | `WARN` 级别日志 |
| 握手超时 | 关闭连接 | `Handshake timeout` |

【建议】演示时关闭会话（而不是「只丢这一个包继续跑」）更容易讲清楚；同时统计计数器保留，便于报告里给出「拒绝了多少个攻击包」。

【建议】`kError` 的内容用明文（仅错误码 + 简短说明），因为此时会话已不可信；它只用于演示提示，不作为协议安全性的依据。

---

## 8. 密钥与配置管理

### 8.1 K_master 的由来（要求里的「带外预配置」）

```text
Alice:  K_master = <16 字节>      Bob:  K_master = <16 字节>      Eve:  不知道
```

课程 `project_q1.md` §2.1 明确说 `K_master` 不能通过网络传输。本方案采用**配置文件带外预置**：

```ini
# /home/SecureTransfer/configs/keys.conf   （权限必须 600，属主为运行用户）
# 注意：仅用于课程实验，不是真实密钥管理方案
[identity]
alice_id = alice
bob_id   = bob

[keys]
master_key = 0f1e2d3c4b5a69788796a5b4c3d2e1f0
```

* 加载代码放在 `include/security/keystore.h`，只有两个入口：`loadMasterKey(path)`、`loadIdentity(path)`；
* 文件缺失 / 长度不对 / 权限过于宽松（例如 group 或 other 可读）时**报警并拒绝启动**——这本身就是访问控制的一个真实体现，可以写进报告；
* 任何日志都不打印密钥内容；`ST_LOG_LEVEL=DEBUG` 时最多打印 `master_key = <16 bytes loaded>` 这样的元信息；
* `configs/demo_config.conf` 里已经写了「后续阶段需要的长期密钥 K_master 绝不应该以明文形式长期保存在这里」——按这条原则，密钥单独放 `keys.conf`，并在 `.gitignore` 里排除。

### 8.2 密钥派生（【待决策 D6】）

同一把 `K_session` 同时用于 CTR 加密和 CMAC 是可以的，但更好的做法是**派生两把用途分离的子密钥**：

```text
K_enc = CMAC(K_session, L("ST-DATA-ENC"))     // 数据加密
K_mac = CMAC(K_session, L("ST-DATA-MAC"))     // 数据完整性
```

优点：算法隔离（同一把密钥下不同密码学原语的输出不混用），便于在报告里说明「我们做了密钥分离」。
成本：多两次 CMAC（只在会话建立时算一次，开销可忽略）。

【建议】采用；如果希望严格「只用课程指定的 K_session」，保持现状也不影响功能正确性。

---

## 9. 代码结构与改动清单

在现有 `/home/SecureTransfer` 上**增量**添加（第一阶段代码保持不动，只改 `alice` / `bob` 的 main）：

```text
SecureTransfer/
├── include/
│   ├── common/
│   │   ├── log.h                  [已有]
│   │   ├── types.h                [新增] Byte/Bytes/Key128/Nonce/SessionId/MacTag/Direction
│   │   ├── byte_buffer.h          [新增] TLV 编码助手（writeU16/U32/U64、appendTlv、读取器）
│   │   └── random.h               [新增] RandomSource + SystemRandom(/dev/urandom) + FixedRandom(测试)
│   ├── crypto/
│   │   ├── crypto_provider.h      [新增] 接口（§4.2）
│   │   ├── mock_crypto_provider.h [新增] 开发期 Mock（标注 WARNING）
│   │   └── aes_crypto_provider.h  [新增] 用第一部分的 AES/CMAC 实现该接口（§10）
│   ├── network/                   [已有，不改]
│   ├── protocol/
│   │   ├── message_type.h         [新增] MessageType 枚举
│   │   ├── packet.h               [新增] Packet 结构 + 常量（kHeaderSize=49 / kMacSize=16）
│   │   ├── packet_codec.cpp       [新增] serialize / deserialize / 边界校验
│   │   └── transcript.h           [新增] 握手转录串构造（域分离 + TLV）
│   └── security/
│       ├── keystore.h             [新增] K_master / 身份加载
│       ├── replay_guard.h         [新增] 序号检查
│       ├── session.h              [新增] SecureSession（§4.3）
│       └── handshake.cpp          [新增] 握手实现（客户端/服务端两个方向）
├── src/
│   └── security/                  [新增] packet_codec.cpp / handshake.cpp / session.cpp 等
├── apps/
│   ├── alice/main.cpp             [改] 握手 + 发 4 条测试消息 + 打印状态
│   └── bob/main.cpp               [改] 握手 + 校验 + 应答 + 打印统计
├── tests/
│   ├── unit/
│   │   ├── test_packet.cpp        [新增]
│   │   ├── test_transcript.cpp    [新增] 握手转录串/域分离/防反射的已知值测试
│   │   ├── test_replay_guard.cpp  [新增]
│   │   └── test_session_state.cpp [新增]
│   └── integration/
│       ├── test_secure_roundtrip.cpp [新增] 完整握手 + 4 条消息（含中文/二进制）
│       ├── test_tamper.cpp           [新增] 改 1 字节 ⇒ 必须被拒
│       ├── test_forge.cpp            [新增] 错误 K_master ⇒ 认证失败
│       └── test_replay.cpp           [新增] 重发合法包 ⇒ 必须被拒
├── scripts/
│   ├── import_aes.sh              [新增] 把 AES 源码导入 + 转 UTF-8
│   ├── capture_eve.sh             [新增] tcpdump 抓包 + 明文检索（配合第三部分演示）
│   └── verify_in_vm.sh            [改] 增加安全测试与演示步骤
└── docs/
    ├── protocol.md                [改] 用真实格式替换「后续扩展」草稿
    ├── architecture.md            [改] 补第二部分分层图
    ├── interfaces.md              [改] 追加 Packet / SecureSession / CryptoProvider
    └── test_report.md             [改] 追加本次实测结果
```

**改动量估计**：新增约 1500–2000 行 C++（含测试），修改约 200 行。

---

## 10. 把 AES 成果接进来

### 10.1 导入步骤

```bash
# 在 Ubuntu6.21 里（源码先在 Windows 上，用共享文件夹/vmrun/scp 传进去）
cd /home/SecureTransfer
mkdir -p src/crypto include/crypto

cp aes.h  include/crypto/aes_core.h
cp aes.c  src/crypto/aes_core.c
cp test.c tests/unit/test_aes.c        # 或改写成 C++ 测试
```

### 10.2 两个必须处理的兼容问题

**（1）编码**：现有 `aes.h` / `aes.c` 的中文注释是 **GBK**。在 Ubuntu（默认 UTF-8）下打开会乱码，虽然不影响编译，但会污染代码评审。建议一次性转换：

```bash
iconv -f GBK -t UTF-8 aes.h > aes_core.h.utf8 && mv aes_core.h.utf8 aes_core.h
# 或者更省事：把中文注释统一换成英文
```

**（2）C/C++ 混合编译**：`aes.c` 按 C 编译，C++ 里 `#include "aes_core.h"` 会因为 name mangling 找不到符号。两种做法可以同时用：

```cpp
// 做法 A：头文件加 extern "C"
#ifdef __cplusplus
extern "C" {
#endif
void aes_key_expand(const uint8_t key[16], uint8_t rk[176]);
/* ... 其余声明 ... */
#ifdef __cplusplus
}
#endif
```

```cmake
# 做法 B：CMake 里明确按 C 编译 aes_core.c
add_library(st_crypto STATIC src/crypto/aes_core.c src/crypto/cmac.cpp)
set_source_files_properties(src/crypto/aes_core.c PROPERTIES LANGUAGE C)
```

### 10.3 第一部分还需要补的（第二部分会依赖）

1. **CMAC 算法**：目前完全没有。需要 `aes_encrypt_block` + GF(2^128) 子密钥生成，用 **RFC 4493** 的 4 条标准向量自测（空消息、1 块、恰好 1 块、跨块）——这是要求 3「使用标准数据进行算法正确性测试」的直接得分点。
2. **C++ 适配层**：把 `aes.c` 的 C 接口包成 `projects/team_interfaces_original.md` 约定的 `AES::encryptBlock` / `AES::encryptCTR` / `CMAC::generate` / `CMAC::verify`，再实现 `AesCryptoProvider : public CryptoProvider`。
3. **decrypt 的说明**：CTR 下加密/解密是同一个函数，这点要在报告里写清楚（`aes_ctr_xor` 调两次就回到明文）。

### 10.4 第二部分在 AES 未就绪时的推进方式

```text
第 1 步    用 MockCryptoProvider 跑通：Packet 编解码 + 握手状态机 + 4 条消息
第 2 步    AES 到位 → 换 AesCryptoProvider（只改工厂函数那一行）
第 3 步    CMAC 到位 → 打开真实的完整性校验与篡改测试
```

风险：Mock 下通过的用例，换成真算法后可能暴露长度/边界问题。所以 Mock 阶段就要覆盖：空 Body、1 字节、15 / 16 / 17 字节、跨块（>16）、1 MB 边界。

---

## 11. 测试与验证方案

### 11.1 单元测试

| 测试 | 用例 | 通过标准 |
| --- | --- | --- |
| `test_packet.cpp` | 编解码往返；空 Body；最大 Body（1048511）；Body 超限；Magic 错；Version 错；`PayloadLen` 与实际长度不符；截断（缺 MAC / 缺 Body / 缺头）；多余尾巴字节 | 往返逐字节一致；非法输入全部被拒且不崩溃、不分配超大内存 |
| `test_transcript.cpp` | 固定 `K_master` + 固定 Nonce ⇒ 固定 tag；`"S2C"` 与 `"C2S"` 的 tag 必须不同；调换 `AliceID` / `BobID` 顺序 ⇒ tag 必须不同；长度前缀歧义（`("ab","c")` vs `("a","bc")`）⇒ tag 必须不同 | **已知值测试（KAT）**，用固定向量锁死实现细节 |
| `test_replay_guard.cpp` | 1,2,3 通过；重复 3 拒绝；回退到 2 拒绝；跳号 5 接受并记录缺口；方向独立（C→S 的 seq 不影响 S→C） | 与 §7.2 规则一致 |
| `test_session_state.cpp` | 未认证就 `sendMessage` ⇒ 失败；握手阶段收到 `kData` ⇒ 拒绝；握手超时 ⇒ `kFailed`；重复 `close()` 安全 | 状态机无非法转移 |
| `test_aes.c`（沿用已有） | FIPS-197 单块向量 + 5 条 CTR 往返 | 与现有 `test.c` 一致 |

### 11.2 集成测试（课程要求的「不少于 4 条测试数据消息」）

`test_secure_roundtrip.cpp`：真实 TCP + 完整握手 + 4 条消息，逐条比对发送的明文与服务端收到的明文：

| # | 测试消息 | 覆盖点 |
| --- | --- | --- |
| 1 | `Hello Bob!` | 短消息、不足 1 个 AES 分组 |
| 2 | `A secure message between Alice and Bob.` | 普通英文、正好跨块 |
| 3 | `Transfer #1024: Alice->Bob, amount=500.00 USD; status=OK! (check: 9f8e7d6c)` | 长文本 + 数字 + 特殊字符 |
| 4 | `你好，Bob，这是一次安全通信测试。` + 37 字节二进制数据 | UTF-8 多字节（中文）+ 非文本二进制（模拟文件分块） |

每条记录：`明文 → 密文（hex）→ CMAC（hex）→ 接收方解密结果 → 完整性验证结果 → 明文是否一致`。这正好对应课程 `project_q1.md` §4.4 要求的输出格式，可以直接抄进报告。

### 11.3 安全测试（要求 3 与 Eve 演示的「证据」）

这四个测试是第二部分最有说服力的产出，建议都做成**自动化的独立测试程序**（而不是手敲命令）：

| 测试 | 做法 | 期望结果 |
| --- | --- | --- |
| **篡改** `test_tamper.cpp` | 握手后，用 `tests/raw_client.h`（第一阶段已有的「裸 socket 客户端」）把合法数据包的第 1 个密文字节翻转，再发给 Bob | Bob 打印 `CMAC verification failed`，拒绝该包，`rejectedMac >= 1`，**明文没有到达上层** |
| **伪造身份** `test_forge.cpp` | 客户端用**错误的 K_master** 完成 HELLO，收到 HELLO_ACK 后仍尝试发 AUTH | Bob 验证失败，打印 `Authentication Failed`，关闭连接 |
| **重放** `test_replay.cpp` | 录下 Alice 发出的一个合法数据包，握手完成后再原样发一次 | 第二次被拒，`rejectedReplay >= 1`；第一次的数据只被上层处理一次 |
| **窃听** `scripts/capture_eve.sh` | 抓一条明文已知的消息（`sudo tcpdump -i lo -X port 9000 -w /tmp/eve.pcap`），再 `strings /tmp/eve.pcap \| grep -c "Hello Bob"` | 抓到的是密文；**明文关键字出现次数为 0**；同时能看到 Magic / Version / Seq / Nonce / CMAC 这些公开字段 |

补充一条**反射攻击**测试（可选但很加分）：把 Bob 发出的合法包原样发给 Bob，因为 `Direction` 字节与 MAC 输入已区分方向，必须被拒绝。

### 11.4 回归基线

每次提交前必须全绿：

```bash
cd /home/SecureTransfer/build
cmake --build . && ctest --output-on-failure
# 期望：第一阶段的 3 个套件（27 个用例）+ 新增的 8 个测试套件全部通过
```

### 11.5 独立交叉验证（不需要额外装东西，虚拟机里现成能做）

虚拟机已有 OpenSSL 1.1.1f + libssl-dev，可以用它**独立验算**第一部分的自写算法，避免「自己写的实现自己验证」的循环论证：

```bash
# AES-128-CTR：与我们实现的密文逐字节对比
printf 'Hello Bob!' | openssl enc -aes-128-ctr -K 000102030405060708090a0b0c0d0e0f -iv <我们的 nonce hex> | xxd -p

# CMAC：与第一部分实现的 tag 对比（注意 cmac 的 iv 全 0）
printf '...' | openssl dgst -mac cmac -macopt cipher:aes-128-cbc -macopt hexkey:000102030405060708090a0b0c0d0e0f
```

虽然第二部分不实现算法，但**用 OpenSSL 验算协议中实际出现的密文与 tag**，是证明「协议没有用错算法」的最强证据（例如证明 Nonce 构造与 CTR 约定一致、`PayloadLen` 真的进了 MAC）。

### 11.6 建议的执行顺序（每个里程碑都留证据）

```text
1. cmake 配置 + 编译 + 第一阶段 27 用例回归        → 截图 / 日志
2. test_packet / test_transcript 通过              → 截图 / 日志
3. alice / bob 完成一次完整握手（打印每一步）        → 截图
4. 4 条消息全部正确解密 + MAC 通过                  → 截图 + hex 记录
5. 篡改 / 伪造 / 重放 / 窃听 四个测试                → 截图 + 计数统计
6.（可选）局域网双机或两台虚拟机跑一次同一个程序       → 截图
```

---

## 12. 里程碑与实施顺序

> 时间估计是**相对工作量**，按每天 2–3 小时投入估算。

| 阶段 | 内容 | 产出 | 验收标准 |
| --- | --- | --- | --- |
| **M0** 环境对齐（0.5 天） | 导入 AES 源码、转编码、加 `extern "C"`；建 `st_crypto` / `st_protocol` 两个 CMake target；`docs/interfaces.md` 追加 §4 的接口 | 能编译的最小骨架 | 第一阶段 27 用例仍全绿；`aes_core.c` 参与编译且原有 5 条 AES 自测通过 |
| **M1** 类型与包格式（1 天） | `types.h` / `byte_buffer.h` / `random.h` / `message_type.h` / `packet.*` + `test_packet` | Packet 编解码 | 编解码往返 + 全部非法输入被拒 |
| **M2** 密码接缝（0.5 天） | `CryptoProvider` + `MockCryptoProvider`（真 AES 到位后补 `AesCryptoProvider`） | 可插拔算法层 | Mock 下协议能跑；替换实现只改一处 |
| **M3** 握手与认证（2 天） | `transcript` / `keystore` / 握手状态机 / `test_transcript` / `test_session_state` | 完整握手 | 固定向量 KAT 通过；错误 K_master 必须失败 |
| **M4** 数据通道（1.5 天） | Nonce 构造 / `ReplayGuard` / 收发流程 / 4 条消息集成测试 | 加密数据传输 | 4/4 消息明文一致；`ctest` 全绿 |
| **M5** 安全验证与文档（1.5 天） | 篡改 / 伪造 / 重放 / 窃听测试 + 更新 `protocol.md`、`test_report.md` + 整理截图 | 可写进报告的实验证据 | 四项攻击全部被拒绝 / 无泄漏；文档与代码一致 |
| **M6**（可选加分） | 局域网或双机测试、`ST_LOG_LEVEL=DEBUG` 的协议追踪、把 `--help` 与错误码整理成表格 | 加分材料 | 双机连通 |

**排序原因**：M1（包格式）与 M3（握手转录串）都是「一旦定下来就被别人依赖」的东西，必须尽早冻结；M4 依赖 M1 + M2 + M3；M5 依赖 M4。**不要跳过 M2 直接写 M4**——否则第一部分的算法没到位时，第二部分的进度会被卡住。

---

## 13. 风险、限制与需要你决策的开放问题

### 13.1 需要你决策

| 编号 | 问题 | 选项 | 我的建议 |
| --- | --- | --- | --- |
| **D1** | SessionId 长度 | 16 字节（对齐 `team_interfaces_original.md`）/ 8 字节（对齐课程建议格式） | **已决策：8 字节（课程要求）**，见 §16.3 |
| **D2** | 握手消息的 Body 是否加密 | 明文 + CMAC（本方案）/ 用 `K_master` 加密 | 明文 + CMAC：此时还没有 `K_session`，且明文便于演示与教学 |
| **D3** | `K_master` 取值与保存 | `configs/keys.conf`（600 权限）/ 命令行参数 / 环境变量 | 配置文件；命令行传密钥会进 shell 历史，不安全 |
| **D4** | CMAC 由谁实现 | 第一部分 / 第二部分代写 | 第一部分（要求 3 明确指向密码算法部分）；第二部分先用 Mock |
| **D5** | 是否新增 `Direction` 字节 | 新增 / 不新增（靠两把方向密钥代替） | 新增：实现简单、演示时肉眼可见，防反射的证据更直观 |
| **D6** | 是否派生 `K_enc` / `K_mac` | 派生 / 直接用 `K_session` | 派生：多两次 CMAC，换来密钥分离 |
| **D7** | 代码是否在 OS 里做版本管理 | 在 `projects/secure-transfer/` 建仓库并同步 / 只放在虚拟机里 | **建仓库**：现在代码只在虚拟机和 zip 里，一旦虚拟机损坏就全没了 |
| **D8** | 日志级别默认值 | INFO / DEBUG | INFO：网络与协议日志足够；DEBUG 只在排查时开 |

### 13.2 已知限制（要诚实写进报告）

1. **`K_session` 是固定值**（课程规定），所以不同会话之间真正的隔离依赖**每会话随机的 SessionId + Nonce Prefix**，而不是「每会话一把新密钥」。真实系统应当每次会话随机生成密钥——本方案已经把这一处收敛到单个函数 `makeCourseSessionKey()`，属于「一行可替换」的设计。
2. **不做前向保密**：`K_master` 一旦泄露，历史抓包中包裹的 `K_session` 都能解开（因为固定 K_session 可复现）。这是预共享密钥方案的固有性质，应作为限制说明。
3. **不做重连 / 密钥轮换**：一次会话一条连接，没有 rekey。
4. **不做抗 DoS**：未认证的 HELLO 任何人都能发，Bob 会为它做一次随机数生成与状态分配。演示规模下可接受。
5. **`kError` 是明文**：攻击者可以伪造它造成连接中断（只影响可用性，不影响机密性 / 完整性）。
6. **安装了 `libssl-dev` 但按要求 4 不使用它实现算法**：它只用于 §11.5 的独立交叉验证，这一点要在报告里说清楚，避免被误认为「用了库」。

### 13.3 容易踩的坑（都是这次实际看到的）

| 坑 | 现象 | 处理 |
| --- | --- | --- |
| AES 源码是 **GBK** 编码 | Ubuntu 下打开注释乱码 | 导入时 `iconv` 或改英文注释（§10.2） |
| C/C++ 混合编译 | `undefined reference to aes_key_expand` | `extern "C"` + CMake 指定 `LANGUAGE C`（§10.2） |
| 用 `char*` 存数据 | 中文解密后乱码（AES 目录的说明文件已提醒） | 全链路统一 `uint8_t` / `Bytes` |
| CTR Nonce 复用 | 两条消息密文异或后能看出明文痕迹 | 用 §7.1 的结构化 Nonce，不用「纯随机碰运气」 |
| 长度不进 MAC | 攻击者可截断 Body | `PayloadLen` 必须参与 CMAC（§3.2 原则 3） |
| 从 Windows 拷文件进虚拟机 | `make` 报 `Clock skew detected` | `find /home/SecureTransfer -exec touch {} +`（`docs/development.md` 第 7 节已记录） |
| 在日志里打印密钥 | 报告 / 演示时泄露 | 密钥相关输出只允许 DEBUG 且默认关闭（`docs/interfaces.md` §4 已约定） |

---

## 14. 附：操作与命令速查

### 14.1 把文件送进虚拟机 / 取回结果（本次已验证可用的通道）

VM 的 VMware Tools 与 Guest 账号可用（账号密码不要写进代码仓库）：

```powershell
$vmrun = "D:\圈圈\ctf\资料\LINUX\新建文件夹\vmrun.exe"
$vmx   = "D:\ctf\ubuntu\newtry6.21\Ubuntu6.21.vmx"

# 送进去
& $vmrun -T ws -gu <user> -gp <password> copyFileFromHostToGuest $vmx "<本地文件>" "/home/SecureTransfer/<目标路径>"

# 取回来
& $vmrun -T ws -gu <user> -gp <password> copyFileFromGuestToHost $vmx "<guest 路径>" "<本地路径>"

# 在 guest 里执行命令（把输出重定向到文件再取回来，因为 vmrun 不回传 stdout）
& $vmrun -T ws -gu <user> -gp <password> runProgramInGuest $vmx /bin/sh /tmp/xxx.sh
```

【建议】这台虚拟机目前**只有 NAT 出网、没有 SSH 服务**（本次实测 22 端口不通），所以每次都要用 `vmrun` 搬文件，效率不高。三个可选改善：装 `openssh-server` 并在 `vmnetnat.conf` 里加端口转发（`8889 = 192.168.111.139:22`）、用 VMware 共享文件夹、或直接在虚拟机里的终端写代码。

### 14.2 虚拟机内：编译与测试

```bash
cd /home/SecureTransfer
mkdir -p build && cd build
cmake .. && cmake --build . -j4
ctest --output-on-failure
```

### 14.3 虚拟机内：跑一次完整的安全通信演示

```bash
# 终端 1
cd /home/SecureTransfer/build && ./bob 9000

# 终端 2
cd /home/SecureTransfer/build && ./alice 127.0.0.1 9000
```

期望输出（新增部分用 ★ 标出）：

```text
★ [INFO] [Handshake] HELLO sent (SessionId=3f2a..., NonceA=9c41...)
★ [INFO] [Handshake] HELLO_ACK received, verifying K_master ... OK
★ [INFO] [Handshake] Bob authenticated
★ [INFO] [Handshake] AUTH sent, waiting for KEY_EXCHANGE ...
★ [INFO] [Handshake] KEY_EXCHANGE received, wrapped session key unwrapped
★ [INFO] [Session] KEY_CONFIRM verified - session ESTABLISHED (K_session 双方一致)
  Sent: Hello Bob!
  ...
★ [INFO] [Session] 4/4 messages verified; rejected(mac)=0 rejected(replay)=0
```

### 14.4 攻击演示命令

```bash
# 篡改 / 伪造 / 重放（自动化测试）
./tests/test_tamper && ./tests/test_forge && ./tests/test_replay

# 窃听：另一个终端先开抓包，再跑 alice/bob
sudo tcpdump -i lo -X port 9000 -w /tmp/eve.pcap
strings /tmp/eve.pcap | grep -c "Hello Bob"      # 期望 0
```

---

## 15. 一句话总结

第一部分的 AES 已经就位、网络骨架（TCP + Frame）已经跑通并测过，**第二部分真正要做的是三件事：把包格式定死（§5）、把握手状态机写对（§6）、把 Encrypt-then-MAC + Sequence 组合对并用攻击测试证明（§7、§11.3）**。建议按 M0 → M5 的顺序推进，先在 Mock 密码算法下把协议跑通，再换成真 AES / CMAC，最后用篡改 / 伪造 / 重放 / 窃听四个测试把「安全」从「声称」变成「可验证」。

---

### 附：本方案的事实来源标注

**【已验证】**（本次在 Ubuntu6.21 中实际执行）：第一阶段编译成功、`ctest` 3/3 套件通过；虚拟机的系统 / 工具链 / 库 / 抓包工具版本；`/home/SecureTransfer` 与 `/home/urruna/SecureTransfer.zip` 的文件清单；虚拟机内不存在 AES 源码；虚拟机 IP 与 NAT 配置。

**【已有材料】**（读取现有文件得到，路径为第一轮时的情况）：
`projects/project_q1.md`、`projects/team_interfaces_original.md`（两者现已移入本项目 `docs/` 目录）、
第一阶段 `README.md` / `docs/*.md` / `include/*` / `src/*` / `tests/*`；
`D:\圈圈\课程\算法设计与实验\AES\大作业\aes.h` / `aes.c` / `test.c` / `aes.文件使用说明.txt`。

**【建议 / 待决策】**（本方案提出、尚未验证的设计选择）：§5 的 Packet 具体布局、§6 的握手消息与转录串定义、§7.1 的 Nonce 结构、§8 的密钥管理与派生方案、§12 的里程碑划分与工时估计，以及 §13.1 的 D1–D8 八个决策点。

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
   └──────(Qt 信号：日志/状态/进度)─────┘ 握手 → 发送 → 250 ms 超时轮询接收
```

`SecureSession` 不是线程安全的，所以规定**只有工作线程碰它**；
界面永远不卡（对端消息最多延迟 250 ms 显示）。

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

1. 接收用 250 ms 超时轮询（`SecureSession` 目前只有阻塞接收接口）；
2. "接收失败是否为超时"依赖错误文本判断（接口未暴露 `Network::Result`）——已在代码注释标注；
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
| M6 | 全量回归 + 重新采集证据 | 16 个测试全绿；要求 5 的性能表、要求 6 的双机测试、要求 9 的逐字节一致 |
| M7 | 文档同步 | Linux / Windows 两套实测数据分别标注 |

## 22.4 本轮的经验

1. **跨平台迁移的第一道坎往往不是代码，而是路径与编码**：
   中文文件名在 GBK 环境下"编译能过、运行打不开"，先英文化是最省事的解法。
2. **备份要在改动之前做**：这一轮先改名、再建仓、再推送，顺序刚好；
   如果先改代码再备份，一旦迁移出错就没有可回退的干净点。
3. **沙箱/容器环境会带来"文件所有者"问题**：git 的 `safe.directory` 检查、
   以及某些工具的所有权校验，都可能在"文件能被读写但仍被拒绝"的情况下出现——
   先分清楚是**权限**问题还是**所有权校验**问题，再决定改 ACL 还是加例外。
