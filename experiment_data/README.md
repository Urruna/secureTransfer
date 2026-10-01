# 实验数据（文件 / 图像传输）

本目录存放"多种信息安全传输"（课程要求 9）用到的全部实验数据。
**主机与虚拟机中各保留一份完全相同的副本**，便于对照与复现实验结果。

| 文件 | 大小 | 用途 |
| --- | --- | --- |
| `text_messages.txt` | 521 B | 与程序内置的 4 条测试消息一致（要求 2 的"不少于 4 条测试数据消息"），便于人工核对明文 |
| `test_file_1KB.bin` | 1 KB | 小文件：验证小文件也能走分块流程 |
| `test_file_64KB.bin` | 64 KB | 恰好一个分块（块大小 64 KiB）的边界情形 |
| `test_file_1MB.bin` | 1 MB | 中等文件：约 16 个分块 |
| `test_image_256x256.png` | 147 KB | **小图像**：不超过单包上限，走 `IMAGE` 单包路径（元数据 + 数据同一个包） |
| `test_image_1024x768.png` | 2.2 MB | **大图像**：超过单包上限（约 1 MiB），自动走分块路径（起始包仍是 `IMAGE`，kind = 图像） |
| `received/` | — | Bob 侧接收文件的落盘目录（`./bob --out-dir experiment_data/received`） |

## 数据是怎么产生的

* 文本消息：与 `apps/alice/main.cpp` 中的 4 条测试消息一致；
* 两个 `.bin` 与 1 MB 文件：确定性伪随机字节（重新生成也完全一样，便于复现）；
* 两张 PNG：用标准库 `zlib` 手工构造的真彩色 PNG（渐变 + 棋盘格；大图额外叠加噪声以便超过单包上限），
  已逐块校验 PNG 的 CRC 与解压后长度；
* 全部为**自制测试数据**，不含任何个人隐私内容。

## 怎么用

```bash
# 1. 启动 Bob（接收端），接收结果落在 experiment_data/received/
cd build && ./bob 9000 --out-dir ../experiment_data/received

# 2. 启动 Alice（发送端）：4 条文本消息 + 文件 + 图像
cd build && ./alice 127.0.0.1 9000 --file test_file_64KB.bin --file test_file_1MB.bin --image test_image_256x256.png --image test_image_1024x768.png

# 3. 逐字节核对（期望全部一致）
for f in test_file_64KB.bin test_file_1MB.bin test_image_256x256.png test_image_1024x768.png; do
    cmp "../experiment_data/$f" "../experiment_data/received/$f" && echo "$f 一致"
done
```

`--data-dir` 默认为 `experiment_data/`，因此 `--file test_file_1MB.bin` 这类相对路径会去该目录里找。

## 说明

* 传输过程中每一块都通过安全会话发送，自动获得 AES-128-CTR 加密、CMAC 完整性保护、
  Sequence 防重放与会话绑定（见 `docs/protocol.md` 与 `docs/file_transfer.md`）；
* 接收端在重组完成后校验**总字节数**与**整文件 CRC32**；CRC32 只是差错检测，
  密码学完整性由每包的 CMAC 保证，两者不可互相替代。
