# 窃听攻击证据（Eve 只能看到密文）

> 对应 `project_q1.md` §9.1 窃听攻击：
>
> ```text
> Eve 可以看到      : TCP 数据包 / Ciphertext / Nonce / Sequence / CMAC
> Eve 不应该直接看到: 原始明文 / Session Key / K_master
> ```
>
> 用于验证 AES-128-CTR 是否真的提供了机密性保护。
>
> 本文记录的是**迁移到 Windows 之后、用 Wireshark/tshark 采集的跨机证据**
> （Windows 主机 ↔ Ubuntu 621 虚拟机，真实以太网链路）。
> Linux 侧的旧证据（tcpdump + `strings | grep`）见 `docs/development.md` §7 与
> `scripts/capture_eve.sh`。

---

## 1. 结论摘要

| 项目 | 结果 |
| --- | --- |
| 抓包工具 | `tshark`（Wireshark 4.6.0） |
| 抓包网卡 | VMware Network Adapter VMnet8（主机 `192.168.111.1` ↔ 虚拟机 `192.168.111.139`） |
| 被观察的会话 | Windows 上的 Alice → Ubuntu 上的 Bob，端口 9850 |
| 抓包文件 | [`experiment_data/captures/eve_9850_20261001_202422.pcapng`](../experiment_data/captures/eve_9850_20261001_202422.pcapng)（74 308 字节，75 帧） |
| 完整报告 | [`….txt`](../experiment_data/captures/eve_9850_20261001_202422.txt)（由脚本自动生成） |
| 业务明文命中次数 | **0**（4 条测试消息 + 文件内容片段） |
| 密钥命中次数 | **0**（K_master、K_session） |

## 2. Eve 能看到什么

把抓到的 TCP 字节流按 `[4 字节长度][Packet]` 重组后，逐包解出协议字段
（脚本 `scripts/capture_eve_windows.py` 自动完成）：

| # | 方向 | 类型 | SessionId | Sequence | Nonce | 密文长度 | 密文前 16 字节 | CMAC 前 16 字节 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | C→S | HELLO | ef199c594cf2d7c8 | 0 | 2adb67f64058a953… | 7 | `0005616c696365…` | `0000000000000000…` |
| 2 | C→S | AUTH | ef199c594cf2d7c8 | 0 | 2adb67f64058a953… | 0 | — | `678ad9c0b3bf9d5a…` |
| 3 | C→S | KEY_REQUEST | ef199c594cf2d7c8 | 0 | 2adb67f64058a953… | 0 | — | `64b63ba5bf9411ce…` |
| 4 | C→S | KEY_CONFIRM | ef199c594cf2d7c8 | 0 | 2adb67f64058a953… | 0 | — | `73924a8441905349…` |
| 5 | C→S | DATA | ef199c594cf2d7c8 | 1 | 9d63b294d2c2539a… | 10 | `320969a169cbaff2f189…` | `4cb47b5eea0fd92c…` |
| 6 | C→S | DATA | ef199c594cf2d7c8 | 2 | 9d63b294d2c2539a… | 39 | `03e07e6136214a76848c1a70f972b17e…` | `82723615ce4124c8…` |
| 7 | C→S | DATA | ef199c594cf2d7c8 | 3 | 9d63b294d2c2539a… | 75 | `75998111cfab0b1a5cad1f3524abad73…` | `95c27357bb7c38ec…` |
| 8 | C→S | DATA | ef199c594cf2d7c8 | 4 | 9d63b294d2c2539a… | 85 | `f9f9e6e3e400a7f36d8c94cf685c827d…` | `0b0333219755ee71…` |
| 9 | C→S | FILE_START | ef199c594cf2d7c8 | 5 | 9d63b294d2c2539a… | 39 | `2a987b20f19a30df3b0ecc3392697f45…` | `c90d4082cc73e4e1…` |
| 10 | C→S | FILE_CHUNK | ef199c594cf2d7c8 | 6 | 9d63b294d2c2539a… | 65536 | `c37995a53ee578ad7a36b04d8d44b196…` | `85573c62a5381b1c…` |
| 11 | C→S | FILE_END | ef199c594cf2d7c8 | 7 | 9d63b294d2c2539a… | 12 | `06592a5d3218c97c03a6914c…` | `4a4535a06d6d59fd…` |
| 12 | C→S | CLOSE | ef199c594cf2d7c8 | 8 | 9d63b294d2c2539a… | 0 | — | `7f38f073d639f7c4…` |

整场会话共解出 **20 个数据包**：加密的业务数据包 13 个（DATA / FILE_* / IMAGE / CLOSE），
握手包 7 个。可以看到，Eve 拿到的信息正好是课程预期的四项：

* **TCP 数据包**：75 帧、63 个带载荷的 TCP 段；
* **Ciphertext**：第 5 ~ 11 号包的 Body（10 / 39 / 75 / 85 / 39 / 65536 / 12 字节密文）；
* **Nonce**：每个包都带 16 字节结构化 Nonce（`随机前缀(8)‖0^4‖计数(4)`）；
* **CMAC / Sequence / SessionId**：这些字段本来就是明文传输并参与 MAC 计算。

> 第 1 行 HELLO 的 Body `0005616c696365` 可以用肉眼解出来：
> `00`（TLV 类型）+ `05`（长度）+ `616c696365`（ASCII `alice`）。
> 这是**握手阶段的身份标识**，不是业务数据 —— 此时双方还没有 K_session，
> 身份必须明文参与转录串与 CMAC（与 TLS 握手里的身份信息同理）。
> 业务数据（消息 / 文件 / 图像）从第 5 行起全部是密文。

## 3. Eve 不应该看到什么

在**整个抓包文件的原始字节**里检索（`raw.count(needle)`）：

| 检索目标 | 类型 | 命中次数 | 期望 | 结果 |
| --- | --- | --- | --- | --- |
| 明文关键字 `Hello Bob!` | 测试消息明文 | 0 | 0 | ✅ |
| 明文关键字 `A secure message between Alice and Bob.` | 测试消息明文 | 0 | 0 | ✅ |
| 明文关键字 `Transfer #1024` | 测试消息明文 | 0 | 0 | ✅ |
| 明文关键字 `你好，Bob`（UTF-8） | 测试消息明文 | 0 | 0 | ✅ |
| 发送文件（`test_file_64KB.bin`）的前 64 字节 | 文件内容明文 | 0 | 0 | ✅ |
| `K_master`（`0f1e2d3c4b5a69788796a5b4c3d2e1f0`） | 长期密钥 | 0 | 0 | ✅ |
| `K_session`（`000102…0f`，本工程规定值） | 会话密钥 | 0 | 0 | ✅ |

也就是说：

* Alice 确实发过这些消息（`alice` 终端日志里有，接收端也校验通过），
  但网络上一个字节的明文都检索不到；
* K_master 从不上网，K_session 是**被 K_master 包裹后传输**的（KEY_EXCHANGE 包里
  那 16 字节密文），所以直接检索明文密钥也是 0 命中。

## 4. 怎么复现（Windows）

抓包需要管理员权限（Npcap 驱动），脚本会自动完成
"启动虚拟机里的 Bob → 抓包 → 运行本机 Alice → 停止抓包 → 解析并写报告"：

```powershell
# 在项目根目录
python scripts/capture_eve_windows.py --file experiment_data/test_file_64KB.bin

# 其他常用参数
python scripts/capture_eve_windows.py --local           # Bob 跑在本机（不连虚拟机）
python scripts/capture_eve_windows.py --port 9860 --duration 30
python scripts/capture_eve_windows.py --analyze-only experiment_data/captures/xxx.pcapng
```

产物：

* `experiment_data/captures/eve_<端口>_<时间戳>.pcapng` —— 可直接用 Wireshark 打开
  （因为没有装 SSL 密钥，Wireshark 会提示"没有解密密钥"，这本身就是证据）；
* 同名 `.txt` —— 上面这份报告。

手工复现（不使用脚本）也可以：

```powershell
# 1) 开始抓包（网卡名用 tshark -D 查，选 VMnet8）
& "D:\AppGallery\wireshark\tshark.exe" -i "\Device\NPF_{...}" -f "tcp port 9850" `
    -a duration:25 -w cap.pcapng -q --global-profile

# 2) 在 Ubuntu 虚拟机里启动 Bob，然后在本机运行 Alice
.\dist\securityTransfer\bob.exe 9850        # 或虚拟机里 /home/securityTransfer/build/bob 9850
.\dist\securityTransfer\alice.exe 192.168.111.139 9850 --file experiment_data\test_file_64KB.bin

# 3) 分析：取 TCP 载荷并解析协议字段
& "D:\AppGallery\wireshark\tshark.exe" -r cap.pcapng -Y "tcp.len>0" -T fields `
    -e tcp.stream -e tcp.srcport -e tcp.dstport -e tcp.payload --global-profile

# 4) 明文检索（期望 0）
Select-String -Path cap.pcapng -Pattern "Hello Bob!" -SimpleMatch -Encoding Byte -Quiet
```

## 5. 与其它证据的关系

| 课程要求 | 对应证据 |
| --- | --- |
| 要求 6：信息经过网络传输 | 本文抓包（75 帧 TCP，主机 ↔ 虚拟机）＋ `docs/lan_test.md` 的双机测试 |
| 要求 7：安全协议在真实网络下工作 | 抓包里能看到完整握手 7 步与加密业务数据 |
| 要求 9：多种信息 | 抓包里同时有短消息（10 ~ 85 字节）与 64 KB 文件分块传输 |
| 要求 10 / §9：Eve 攻击演示 | 本文（窃听）＋ `tests/integration/test_tamper|forge|replay.cpp`（篡改 / 伪造 / 重放） |
