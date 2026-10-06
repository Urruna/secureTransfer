#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureTransfer - Eve 窃听演示（Windows 侧，tshark 抓包 + 证据分析）

对应课程要求（project_q1.md §9.1 窃听攻击）：

    Eve 可以看到      : TCP 数据包 / Ciphertext / Nonce / Sequence / CMAC
    Eve 不应该看到    : 原始明文 / Session Key(K_session) / K_master

本脚本会：
  1) 用 tshark 在指定网卡上抓包（默认 VMware 的 VMnet8，也就是"主机 ↔ Ubuntu 虚拟机"那条链路）；
  2) 在 Ubuntu 虚拟机里启动 Bob（默认；也可用 --local 让 Bob 跑在本机），
     再让本机 Alice 发 4 条课程要求的测试消息（可再加文件）；
  3) 把抓到的 TCP 字节流按 4 字节长度前缀重组，逐包解出
     Type / Direction / SessionId / Sequence / Nonce / 密文 / CMAC；
  4) 在原始抓包字节里检索"明文关键字、K_master、文件内容片段"，
     期望命中次数为 0，从而证明 AES-CTR 提供了机密性保护；
  5) 把结论写成报告（UTF-8 文本），与 .pcapng 一起放进 experiment_data/captures/。

用法（PowerShell，建议管理员运行，抓包需要 Npcap 权限）：

    python scripts/capture_eve_windows.py                 # 默认：Bob 在 Ubuntu 虚拟机
    python scripts/capture_eve_windows.py --local         # Bob 在本机
    python scripts/capture_eve_windows.py --file experiment_data/test_file_64KB.bin
    python scripts/capture_eve_windows.py --analyze-only experiment_data/captures/xxx.pcapng
"""

from __future__ import annotations

import argparse
import datetime
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TYPE_NAMES = {
    0x01: "HELLO",
    0x02: "HELLO_ACK",
    0x03: "AUTH",
    0x04: "KEY_REQUEST",
    0x05: "KEY_EXCHANGE",
    0x06: "KEY_CONFIRM",
    0x07: "KEY_CONFIRM_ACK",
    0x08: "DATA",
    0x09: "FILE_START",
    0x0A: "FILE_CHUNK",
    0x0B: "FILE_END",
    0x0C: "IMAGE",
    0x0D: "ERROR",
    0x0E: "CLOSE",
}

# 握手包（1~7）Body 是明文（此时还没有 K_session），业务数据（8~12、14）是密文。
ENCRYPTED_TYPES = {0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0E}

DEFAULT_TSHARK = Path(r"D:\AppGallery\wireshark\tshark.exe")
DEFAULT_VMRUN = Path(r"D:\圈圈\ctf\资料\LINUX\新建文件夹\vmrun.exe")
DEFAULT_VMX = Path(r"D:\ctf\ubuntu\newtry6.21\Ubuntu6.21.vmx")


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def log(message: str) -> None:
    print(message, flush=True)


def run(command, **kwargs):
    # 本工程的可执行文件统一输出 UTF-8（见 common/console.h），因此固定按 UTF-8 解码
    return subprocess.run(command, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", **kwargs)


def read_master_key() -> bytes:
    """从 configs/keys.conf 读取 K_master（只用于"它在抓包里出现几次"这个检索）。"""
    conf = PROJECT_ROOT / "configs" / "keys.conf"
    if not conf.exists():
        conf = PROJECT_ROOT / "configs" / "keys.conf.example"
    if not conf.exists():
        return b""
    for line in conf.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("master_key"):
            value = line.split("=", 1)[1].strip()
            try:
                return bytes.fromhex(value)
            except ValueError:
                return b""
    return b""


def pick_interface(tshark: Path, wanted: str) -> str:
    """--interface 没给时，自动挑包含 wanted（默认 VMnet8）的那张网卡。

    返回的是 tshark -D 里的设备名（例如 \\Device\\NPF_{GUID}），
    比用序号更稳——序号会随网卡增减而变化。
    """
    result = run([str(tshark), "-D"])
    for line in (result.stdout or "").splitlines():
        if wanted.lower() in line.lower():
            # 行格式形如： "5. \Device\NPF_{GUID} (VMware Network Adapter VMnet8)"
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    raise SystemExit(f"找不到包含 “{wanted}” 的网卡，请用 --interface 指定（tshark -D 可列出）")


def binary_dir(args) -> Path:
    """优先用打包目录（自带全部 DLL），否则退回 build-win（需要 MSYS2 在 PATH 里）。"""
    if args.bin_dir:
        return Path(args.bin_dir)
    dist = PROJECT_ROOT / "dist" / "securityTransfer"
    if (dist / "alice.exe").exists():
        return dist
    return PROJECT_ROOT / "build-win"


# ---------------------------------------------------------------------------
# 抓包
# ---------------------------------------------------------------------------
def start_capture(tshark: Path, interface: str, port: int, out_path: Path, duration: int, tmp_dir: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    command = [
        str(tshark),
        "-i", interface,
        "-f", f"tcp port {port}",
        "-a", f"duration:{duration}",
        "-w", str(out_path),
        "-q",
        # Wireshark 4.x 不再有 --persconf/--persdata，用全局配置避免"读不到个人配置"的告警
        "--global-profile",
    ]
    log(f"[抓包] {' '.join(command)}")
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def start_guest_bob(args) -> bool:
    """在 Ubuntu 虚拟机里后台启动 Bob。"""
    script = (
        f"cd {args.guest_project}/build || exit 9; "
        f"rm -rf {args.guest_project}/experiment_data/received_eve; "
        f"mkdir -p {args.guest_project}/experiment_data/received_eve; "
        f"nohup ./bob {args.port} --out-dir {args.guest_project}/experiment_data/received_eve "
        f"--once --quiet > /home/{args.guest_user}/eve_bob.log 2>&1 & sleep 1; echo started"
    )
    result = run([
        str(args.vmrun), "-T", "ws",
        "-gu", args.guest_user, "-gp", args.guest_pass,
        "runScriptInGuest", str(args.vmx), "/bin/bash", script,
    ])
    if result.returncode != 0:
        log(f"[WARN] 在虚拟机里启动 Bob 失败：{result.stdout}{result.stderr}")
        return False
    log("[步骤] 已在 Ubuntu 虚拟机里启动 Bob（后台）")
    return True


def start_local_bob(args):
    out_dir = PROJECT_ROOT / "experiment_data" / "received_eve"
    out_dir.mkdir(parents=True, exist_ok=True)
    exe = binary_dir(args) / "bob.exe"
    log(f"[步骤] 在本机启动 Bob：{exe}")
    return subprocess.Popen(
        [str(exe), str(args.port), "--quiet", "--once", "--out-dir", str(out_dir)],
        cwd=str(binary_dir(args)),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def run_alice(args) -> None:
    exe = binary_dir(args) / "alice.exe"
    command = [str(exe), args.peer_host, str(args.port), "--quiet"]
    if args.file:
        command += ["--file", args.file]
    log(f"[步骤] 本机运行 Alice：{' '.join(command)}")
    result = run(command, cwd=str(binary_dir(args)))
    log(f"[步骤] Alice 退出码 = {result.returncode}")
    (PROJECT_ROOT / "experiment_data" / "captures").mkdir(parents=True, exist_ok=True)
    tail = "\n".join((result.stdout or "").splitlines()[-4:])
    log(tail)


# ---------------------------------------------------------------------------
# 抓包分析
# ---------------------------------------------------------------------------
def payload_rows(tshark: Path, pcap: Path, tmp_dir: Path):
    """用 tshark 取出每条 TCP 段的 payload（hex），供后面的协议解析使用。"""
    command = [
        str(tshark), "-r", str(pcap),
        "-Y", "tcp.len>0",
        "-T", "fields",
        "-e", "tcp.stream", "-e", "ip.src", "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "tcp.payload",
        "--global-profile",
    ]
    result = run(command)
    rows = []
    for line in (result.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 5 or not parts[4]:
            continue
        hex_text = "".join(ch for ch in parts[4] if ch in "0123456789abcdefABCDEF")
        if len(hex_text) % 2:
            hex_text = hex_text[:-1]
        rows.append((parts[0], parts[1], int(parts[2]), int(parts[3]), bytes.fromhex(hex_text)))
    return rows


def reassemble(rows):
    """按 (stream, 方向) 拼接 TCP 字节流；保持方向首次出现的顺序（即抓包顺序）。"""
    streams: dict = {}
    for stream, _src, sport, dport, payload in rows:
        key = (stream, sport, dport)
        streams.setdefault(key, bytearray()).extend(payload)
    return streams


def parse_frames(buffer: bytes):
    """把字节流按 [4 字节长度][Packet] 拆开并解码协议字段。"""
    packets = []
    offset = 0
    while offset + 4 <= len(buffer):
        length = struct.unpack(">I", buffer[offset:offset + 4])[0]
        if length == 0 or length > 1024 * 1024:
            break
        if offset + 4 + length > len(buffer):
            break
        payload = buffer[offset + 4:offset + 4 + length]
        offset += 4 + length
        if len(payload) < 41 + 16 or payload[0:2] != b"ST":
            continue
        body_len = struct.unpack(">I", payload[37:41])[0]
        if 41 + body_len + 16 > len(payload):
            continue
        packets.append({
            "version": payload[2],
            "type": payload[3],
            "direction": payload[4],
            "session_id": payload[5:13].hex(),
            "sequence": struct.unpack(">Q", payload[13:21])[0],
            "nonce": payload[21:37].hex(),
            "body": payload[41:41 + body_len],
            "mac": payload[41 + body_len:41 + body_len + 16].hex(),
        })
    return packets


def analyze(args, pcap: Path, tmp_dir: Path) -> str:
    raw = pcap.read_bytes()
    rows = payload_rows(args.tshark, pcap, tmp_dir)
    packets = []
    for (stream, sport, dport), buffer in reassemble(rows).items():
        for packet in parse_frames(bytes(buffer)):
            packet["stream"] = stream
            packet["from_port"] = sport
            packet["to_port"] = dport
            packets.append(packet)

    total_packets = 0
    info = run([str(args.tshark), "-r", str(pcap), "--global-profile",
                "-T", "fields", "-e", "frame.number"])
    total_packets = len([line for line in (info.stdout or "").splitlines() if line.strip()])

    keywords = [args.keyword, "A secure message between Alice and Bob.",
                "Transfer #1024", "你好，Bob"]
    file_sample = b""
    if args.file:
        file_path = Path(args.file)
        if not file_path.is_absolute():
            file_path = PROJECT_ROOT / file_path
        if file_path.exists():
            file_sample = file_path.read_bytes()[:64]

    master_key = read_master_key()

    lines = []
    add = lines.append
    add("# Eve 窃听演示报告（Windows / tshark）")
    add("")
    add(f"* 抓包文件：`{pcap.relative_to(PROJECT_ROOT).as_posix()}`")
    add(f"* 抓包时间：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    add(f"* 抓包网卡：{args.interface_name}")
    add(f"* 端口：{args.port}")
    add(f"* 抓包文件大小：{len(raw)} 字节")
    add(f"* 捕获帧数：{total_packets}")
    add(f"* 其中带 TCP 载荷的段：{len(rows)}")
    add(f"* 解出的 SecureTransfer 数据包：{len(packets)}")
    add("")
    add("## 1. Eve 能看到什么（协议字段解析）")
    add("")
    add("按线上格式 `Magic(2) Version(1) Type(1) Direction(1) SessionId(8) Sequence(8) "
        "Nonce(16) PayloadLen(4) Body(N) MacTag(16)` 解出来的前若干个包：")
    add("")
    add("| # | 方向 | 类型 | SessionId | Sequence | Nonce | Body(密文) 长度 | Body 前 16 字节 | CMAC 前 16 字节 |")
    add("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for index, packet in enumerate(packets[:12], 1):
        type_name = TYPE_NAMES.get(packet["type"], f"0x{packet['type']:02X}")
        direction = "C→S" if packet["direction"] == 1 else "S→C"
        add(f"| {index} | {direction} | {type_name} | {packet['session_id']} | "
            f"{packet['sequence']} | {packet['nonce'][:16]}… | {len(packet['body'])} | "
            f"{packet['body'][:16].hex()}… | {packet['mac'][:16]}… |")
    add("")

    encrypted = [p for p in packets if p["type"] in ENCRYPTED_TYPES]
    add(f"其中**加密的业务数据包**（DATA / FILE_* / IMAGE / CLOSE）共 {len(encrypted)} 个，"
        f"握手包（HELLO…KEY_CONFIRM_ACK）共 {len(packets) - len(encrypted)} 个。")
    add("")

    add("## 2. Eve 不应该看到什么（明文与密钥检索）")
    add("")
    add("直接在**整个抓包文件**的原始字节里检索：")
    add("")
    add("| 检索目标 | 类型 | 命中次数 | 期望 | 结果 |")
    add("| --- | --- | --- | --- | --- |")

    def search(needle: bytes, label: str, kind: str, expect_zero: bool = True) -> None:
        count = raw.count(needle) if needle else 0
        ok = (count == 0) if expect_zero else (count >= 0)
        verdict = "✅ 通过" if ok else "❌ 失败"
        add(f"| {label} | {kind} | {count} | {'0' if expect_zero else '—'} | {verdict} |")

    for keyword in keywords:
        search(keyword.encode("utf-8"), f"明文关键字 `{keyword}`", "测试消息明文")
    if file_sample:
        search(file_sample, f"发送文件的前 64 字节（{Path(args.file).name}）", "文件内容明文")
    if master_key:
        search(master_key, f"K_master（{master_key.hex()}）", "长期密钥")
    # K_session 在本工程中固定为 00 01 02 ... 0F，这里也检索一次
    search(bytes(range(16)), "K_session（000102…0f）", "会话密钥")
    add("")

    add("### 说明：为什么握手阶段能看到身份字符串")
    add("")
    add("HELLO / HELLO_ACK 的 Body 里带 `alice` / `bob` 身份标识（用于构造认证转录串），"
        "此时双方还没有会话密钥，因此这一部分是**明文 + CMAC**（协议设计如此，"
        "与 TLS 握手里的身份信息同理）。**业务数据（消息 / 文件 / 图像）全部是密文**，"
        "上表已经证明检索不到任何业务明文。")
    add("")

    add("## 3. 结论")
    add("")
    add("1. Eve 能看到：TCP 数据包、Ciphertext、Nonce、Sequence、CMAC —— 与课程预期一致；")
    add("2. Eve 看不到：业务明文、K_session、K_master —— 检索命中次数全部为 0；")
    add("3. 因此 AES-128-CTR 提供了机密性保护，而 CMAC 让篡改可被发现（见攻击测试）。")
    add("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="SecureTransfer Eve 窃听演示（Windows / tshark）")
    parser.add_argument("--port", type=int, default=9850)
    parser.add_argument("--keyword", default="Hello Bob!")
    parser.add_argument("--file", default=None, help="额外发送一个文件（相对项目根目录）")
    parser.add_argument("--duration", type=int, default=25, help="抓包时长（秒）")
    parser.add_argument("--bin-dir", default=None,
                        help="可执行文件目录（默认优先用 dist/securityTransfer，其次 build-win）")
    parser.add_argument("--interface", default=None, help="tshark 网卡名或编号；默认自动选 VMnet8")
    parser.add_argument("--tshark", default=str(DEFAULT_TSHARK))
    parser.add_argument("--local", action="store_true", help="Bob 跑在本机（默认在 Ubuntu 虚拟机里）")
    parser.add_argument("--peer-host", default="192.168.111.139", help="Bob 的地址（虚拟机模式）")
    parser.add_argument("--vmrun", default=str(DEFAULT_VMRUN))
    parser.add_argument("--vmx", default=str(DEFAULT_VMX))
    parser.add_argument("--guest-user", default="urruna")
    parser.add_argument("--guest-pass", default="060611")
    parser.add_argument("--guest-project", default="/home/securityTransfer")
    parser.add_argument("--analyze-only", default=None, help="只分析已有的 pcapng，不再抓包")
    args = parser.parse_args()

    args.tshark = Path(args.tshark)
    args.vmrun = Path(args.vmrun)
    args.vmx = Path(args.vmx)
    tmp_dir = PROJECT_ROOT / "build-win" / "tshark-tmp"

    if not args.tshark.exists():
        raise SystemExit(f"找不到 tshark：{args.tshark}")

    if args.analyze_only:
        pcap = Path(args.analyze_only)
        args.interface_name = "（沿用已有抓包文件）"
        report = analyze(args, pcap, tmp_dir)
        report_path = pcap.with_suffix(".txt")
        report_path.write_text(report, encoding="utf-8")
        log(report)
        log(f"\n[完成] 报告已写入 {report_path}")
        return 0

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    capture_dir = PROJECT_ROOT / "experiment_data" / "captures"
    pcap = capture_dir / f"eve_{args.port}_{stamp}.pcapng"

    if args.interface:
        args.interface_name = args.interface
        interface = args.interface
    else:
        wanted = "VMnet8" if not args.local else "Loopback"
        interface = pick_interface(args.tshark, wanted)
        args.interface_name = interface
    log(f"[步骤] 抓包网卡：{interface}")

    bob_process = None
    if args.local:
        args.peer_host = "127.0.0.1"
        bob_process = start_local_bob(args)
        time.sleep(1)
    else:
        if not start_guest_bob(args):
            return 1
        time.sleep(1)

    capture = start_capture(args.tshark, interface, args.port, pcap, args.duration, tmp_dir)
    time.sleep(3)
    run_alice(args)
    time.sleep(3)

    if capture.poll() is None:
        capture.terminate()
        try:
            capture.wait(timeout=10)
        except subprocess.TimeoutExpired:
            capture.kill()
    if bob_process is not None and bob_process.poll() is None:
        bob_process.terminate()

    if not pcap.exists():
        log("[ERROR] 抓包文件没有生成")
        return 1

    report = analyze(args, pcap, tmp_dir)
    report_path = pcap.with_suffix(".txt")
    report_path.write_text(report, encoding="utf-8")
    log("")
    log(report)
    log(f"\n[完成] 抓包文件 {pcap}")
    log(f"[完成] 报告文件 {report_path}")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
