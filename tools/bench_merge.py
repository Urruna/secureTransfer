#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureTransfer - 性能对比：把多次运行的结果汇总成一张表

用途：crypto_benchmark（默认/硬件加速）与 crypto_benchmark_soft（纯软件对照）
      各跑一次并导出 CSV（--csv），再用本脚本合并成 Markdown 汇总表，
      指标是"相对自实现的吞吐率倍率"，一眼能看出各库与我们的差距、以及
      硬件加速贡献了多少。

用法：
    python tools/bench_merge.py hw.csv sw.csv            # 打印 Markdown
    python tools/bench_merge.py hw.csv sw.csv -o summary.md

CSV 由 crypto_benchmark 生成，列：label,backend,size_bytes,operation,milliseconds,mb_per_s
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import OrderedDict
from pathlib import Path

OPERATIONS = [("aes_encrypt", "AES-CTR"), ("cmac", "CMAC")]


def load(paths):
    """读取多个 CSV，返回 {(label, backend): {size: {op: mbps}}}。"""
    data = OrderedDict()
    for path in paths:
        with open(path, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                key = (row["label"], row["backend"])
                entry = data.setdefault(key, {})
                size = int(row["size_bytes"])
                entry.setdefault(size, {})[row["operation"]] = float(row["mb_per_s"])
    return data


def human(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size // (1024 * 1024)} MB"
    return f"{size // 1024} KB"


def build_markdown(data) -> str:
    sizes = sorted({size for entry in data.values() for size in entry})
    keys = list(data.keys())

    lines = []
    add = lines.append
    add("# 性能对比汇总表（自动生成）")
    add("")
    add("> 由 `tools/bench_merge.py` 从各次运行的 CSV 汇总；数字为**吞吐率（MB/s）**，")
    add("> 括号内是相对自实现的倍率。运行标签（hw/sw）含义见对应的 `--csv` 运行说明。")
    add("")

    for op_id, op_name in OPERATIONS:
        add(f"## {op_name}")
        add("")
        add("| 数据大小 | " + " | ".join(f"{label}/{backend}" for label, backend in keys) + " |")
        add("| --- |" + " --- |" * len(keys))
        self_keys = [k for k in keys if k[1] == "self"]
        for size in sizes:
            cells = []
            for label, backend in keys:
                value = data[(label, backend)].get(size, {}).get(op_id)
                if value is None:
                    cells.append("—")
                    continue
                # 同一次运行内的自实现作为倍率基准
                base_key = (label, "self")
                base = data.get(base_key, {}).get(size, {}).get(op_id) if self_keys else None
                if base:
                    cells.append(f"{value:.1f}（{value / base:.2f}x）")
                else:
                    cells.append(f"{value:.1f}")
            add(f"| {human(size)} | " + " | ".join(cells) + " |")
        add("")

    # 相对自实现的倍率单独来一张（便于直接写进报告结论）
    add("## 相对自实现的倍率（仅列出各库）")
    add("")
    add("| 数据大小 | 运算 | " + " | ".join(f"{label}/{backend}" for label, backend in keys
                                              if backend != "self") + " |")
    add("| --- | --- |" + " --- |" * len([k for k in keys if k[1] != "self"]))
    for size in sizes:
        for op_id, op_name in OPERATIONS:
            cells = []
            for label, backend in keys:
                if backend == "self":
                    continue
                value = data[(label, backend)].get(size, {}).get(op_id)
                base = data[(label, "self")].get(size, {}).get(op_id)
                cells.append("—" if value is None or not base else f"{value / base:.2f}x")
            add(f"| {human(size)} | {op_name} | " + " | ".join(cells) + " |")
    add("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="汇总 crypto_benchmark 的 CSV 结果")
    parser.add_argument("csv", nargs="+", help="一次或多次运行的 CSV（--csv 生成）")
    parser.add_argument("-o", "--out", help="输出 Markdown 文件（不指定则打印到屏幕）")
    args = parser.parse_args()

    for path in args.csv:
        if not Path(path).exists():
            print(f"[ERROR] 找不到 CSV: {path}", file=sys.stderr)
            return 1

    markdown = build_markdown(load(args.csv))
    if args.out:
        Path(args.out).write_text(markdown, encoding="utf-8")
        print(f"[OK] 已写入 {args.out}")
    else:
        print(markdown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
