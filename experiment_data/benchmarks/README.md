# 性能对比原始数据（课程要求 5）

本目录保存 `scripts/run_benchmarks.sh` 在 **Windows（MSYS2 MinGW-w64）** 上跑出来的原始结果，
用于支撑 `docs/performance.md` §9 的多库对比结论。

| 文件 | 说明 |
| --- | --- |
| `bench_hw.log` | 默认组完整输出（Markdown 表格）：自实现 / OpenSSL / Mbed TLS / Botan，各库按发行包默认（大概率启用 AES-NI） |
| `bench_hw.csv` | 默认组的机器可读数据：`label,backend,size_bytes,operation,milliseconds,mb_per_s` |
| `bench_sw.log` | 纯软件组完整输出：OpenSSL 用 `OPENSSL_ia32cap` 关闭硬件加速；Mbed TLS / Botan 用**源码构建的禁用 AES-NI 版本** |
| `bench_sw.csv` | 纯软件组的机器可读数据 |
| `summary.md` | 由 `tools/bench_merge.py` 合并两组数据得到的**汇总表**（吞吐率 + 相对自实现的倍率） |

怎么复现：

```bash
# 在 MSYS2 的 MinGW64 shell 里（项目根目录）
bash scripts/run_benchmarks.sh            # 默认 100 MB；--max-mb 10 可快速跑
```

两组数据的口径完全一致（同一份源码、同样的计时方式、同一台机器），
差别只在于链接了哪一份库；**先做正确性交叉验证**（四方密文与 CMAC 逐字节一致）再比性能。
