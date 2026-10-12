// ============================================================================
//  SecureTransfer - 第三部分：Eve 中间人中继（命令行）
//  file: apps/eve/main.cpp
//
//  课程要求 3（Eve 攻击测试）里的"中间人"角色：与 alice / bob 平级的
//  **独立进程**，坐在两端 TCP 链路中间，默认原样双工转发，可随时注入攻击：
//
//      Alice ──connect──▶ [ eve 中继 :9400 ] ──connect──▶ Bob :9000
//
//  它没有 K_master、也没有 K_session，所以：
//    * 纯转发时只能看到密文，而会话**照样正常建立** —— 这条本身就是结论：
//      协议不依赖链路可信，"站在链路上"不等于"能攻破会话"；
//    * 篡改任意一个包 → 收包方在对应关卡拒绝（⑤类型 ⑥重放 ⑦CMAC …）；
//    * 丢弃 / 延迟 → 密码学防不住，只表现为超时或断连（报告的 limitation）；
//    * 冒充 Bob → HELLO_ACK 要 K_master 签名，签不出来。
//
//  核心转发逻辑在 `src/attack/mitm_relay.cpp`（同一份代码也被集成测试
//  以线程方式复用）；本文件只做参数解析、stdin 命令与输出。
//
//  ---------------------------------------------------------------------------
//  用法：
//      ./eve [--listen 9400] [--target 127.0.0.1:9000] [--direction c2s|s2c] [--quiet]
//
//  运行中从 stdin 下发命令（图形界面就是这么驱动它的）：
//      tamper [n] [dir]       篡改第 n 个包（省略 n = 下一个包）后转发
//      drop   [n] [dir]       丢弃第 n 个包（不转发）
//      delay  <ms> [n] [dir]  延迟 ms 毫秒后转发
//      replay [n] [dir]       第 n 个包之后，原样重发上一个已转发的包
//      status                 打印统计
//      quit                   结束
//  （dir = c2s / s2c / both，省略时用 --direction 指定的默认方向）
//
//  stdout 每行都有固定前缀，供图形界面解析：
//      [EVE] LISTEN / CONNECTED / PACKET / ATTACK / QUEUED / STATUS / CLOSED / BYE
//  ---------------------------------------------------------------------------

#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include "attack/mitm_relay.h"
#include "common/console.h"

namespace {

using attack::MitmAttack;
using attack::MitmDirection;
using attack::MitmPacketType;
using attack::MitmRelay;
using attack::MitmStats;
using attack::MitmTarget;

void emit(const std::string& line) {
    std::cout << "[EVE] " << line << std::endl;
}

void printUsage() {
    std::cout <<
        "用法：./eve [--listen 9400] [--target 127.0.0.1:9000]\n"
        "            [--direction c2s|s2c] [--quiet]\n"
        "\n"
        "  让 Alice 连到 --listen 端口，本进程再连到 --target，即为链路中间人。\n"
        "\n"
        "运行中可输入：\n"
        "  tamper <目标>           篡改后转发\n"
        "  drop   <目标>           丢弃，不转发（不能打「最近一条」，那个包已经过去了）\n"
        "  delay  <ms> <目标>      延迟 ms 毫秒后转发\n"
        "  replay <目标>           原样重发目标包\n"
        "\n"
        "  <目标> 有四种写法（组合使用）：\n"
        "    （省略）                下一个包\n"
        "    --type DATA             下一个 DATA 包（也可 FILE_CHUNK / IMAGE）\n"
        "    --last --type DATA      最近一条 DATA —— 捕获-篡改/重发，立即下手\n"
        "    --index 7               第 7 个「匹配类型」的包：\n"
        "                            没写 --type 时=该方向第 7 个包（**含 4 个握手包**，\n"
        "                            所以第 5 个才是第一条业务数据）；\n"
        "                            写了 --type DATA 时=第 7 条 DATA，不受握手包干扰\n"
        "    --dir c2s|s2c|both      方向（默认 c2s）\n"
        "  旧写法 [n] [dir] 仍然可用，例如 `tamper 5 c2s`\n"
        "  ! 序号必须指向「将来」的包；填了已经过去的序号会立即报 ERR（不会静静挂着）\n"
        "\n"
        "  status                  打印统计\n"
        "  quit                    退出\n"
        "\n"
        "注意：本进程只能确认「已注入到链路」。对端是否接受、是否被拦下，\n"
        "      由受害端掌握 —— 它不会告诉你（这正是安全属性的一部分）。\n";
}

/// 解析 "host:port" / "host"（缺省端口 9000）。
bool parseTarget(const std::string& text, std::string& host, std::uint16_t& port) {
    const std::size_t colon = text.rfind(':');
    if (colon == std::string::npos) {
        host = text;
        port = 9000;
        return !host.empty();
    }
    host = text.substr(0, colon);
    const int value = std::atoi(text.substr(colon + 1).c_str());
    if (host.empty() || value <= 0 || value > 65535) {
        return false;
    }
    port = static_cast<std::uint16_t>(value);
    return true;
}

/// 解析方向参数；返回 kC2S / kS2C / kBoth。
MitmDirection parseDirection(const std::string& text, MitmDirection fallback) {
    if (text == "c2s" || text == "C2S") {
        return MitmDirection::kC2S;
    }
    if (text == "s2c" || text == "S2C") {
        return MitmDirection::kS2C;
    }
    if (text == "both" || text == "BOTH") {
        return MitmDirection::kBoth;
    }
    return fallback;
}

const char* directionTag(MitmDirection direction) {
    switch (direction) {
        case MitmDirection::kC2S: return "C2S";
        case MitmDirection::kS2C: return "S2C";
        case MitmDirection::kBoth: return "both";
    }
    return "?";
}

void printStatus(const MitmStats& stats) {
    std::ostringstream oss;
    oss << "STATUS forwarded=" << stats.forwarded << " tampered=" << stats.tampered
        << " dropped=" << stats.dropped << " delayed=" << stats.delayed
        << " replayed=" << stats.replayed << " undecodable=" << stats.undecodable
        << " c2s_packets=" << stats.c2sPackets << " s2c_packets=" << stats.s2cPackets;
    emit(oss.str());
}

/// "打哪一种包"：DATA / FILE_CHUNK / IMAGE（大小写不敏感，也接受前缀 FILE/IMG）。
/// 参数解析只做语法解析，不依赖网络，可以单独测试。
MitmPacketType parsePacketType(std::string text) {
    for (char& c : text) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    if (text == "DATA" || text == "MSG" || text == "MESSAGE") {
        return MitmPacketType::kData;
    }
    if (text == "FILE_CHUNK" || text == "FILE" || text == "CHUNK") {
        return MitmPacketType::kFileChunk;
    }
    if (text == "IMAGE" || text == "IMG") {
        return MitmPacketType::kImage;
    }
    return MitmPacketType::kAny;
}

/// 解析攻击目标：
///   tamper                       → 下一个包
///   tamper 7 c2s                 → 第 7 个包（兼容旧写法）
///   tamper --type DATA c2s       → 下一个 DATA 包
///   tamper --last --type DATA    → 最近一条 DATA（立即下手）
///   tamper --index 7 --dir c2s   → 第 7 个包
struct TargetArgs {
    attack::MitmTarget target;
    MitmDirection direction = MitmDirection::kC2S;
    bool ok = true;
};

TargetArgs parseTargetArgs(std::istringstream& stream, MitmDirection fallback) {
    TargetArgs args;
    args.direction = fallback;
    std::string token;
    while (stream >> token) {
        if (token == "--dir" || token == "--direction") {
            std::string value;
            if (stream >> value) {
                args.direction = parseDirection(value, fallback);
            }
        } else if (token == "--index") {
            std::string value;
            if (stream >> value) {
                args.target.index = std::strtoull(value.c_str(), nullptr, 10);
            }
        } else if (token == "--type") {
            std::string value;
            if (stream >> value) {
                args.target.type = parsePacketType(value);
            }
        } else if (token == "--last") {
            args.target.lastOfType = true;
        } else if (token == "c2s" || token == "s2c" || token == "both") {
            args.direction = parseDirection(token, fallback);
        } else {
            char* end = nullptr;
            const unsigned long long value = std::strtoull(token.c_str(), &end, 10);
            if (end != token.c_str() && *end == '\0') {
                args.target.index = value;
            } else {
                args.ok = false;
            }
        }
    }
    // "--last" 必须知道"哪一类"；没写 --type 时按最常用的"业务短消息"处理
    if (args.target.lastOfType && args.target.type == MitmPacketType::kAny) {
        args.target.type = MitmPacketType::kData;
    }
    return args;
}

/// 供 QUEUED 行显示的目标描述。
std::string targetDescription(const attack::MitmTarget& target) {
    if (target.lastOfType) {
        return std::string("last-") + attack::mitmPacketTypeToString(target.type);
    }
    if (target.index != 0) {
        return "index:" + std::to_string(target.index) +
               (target.type == MitmPacketType::kAny
                    ? std::string("(含握手包)")
                    : std::string(" of ") + attack::mitmPacketTypeToString(target.type));
    }
    if (target.type != MitmPacketType::kAny) {
        return std::string("next-") + attack::mitmPacketTypeToString(target.type);
    }
    return "next";
}

/// 这个目标在"等什么"——写清楚，避免用户以为"点了没反应"。
std::string waitingDescription(const attack::MitmTarget& target) {
    if (target.lastOfType) {
        return "立即执行（用最近一条已转发的包）";
    }
    if (target.index != 0) {
        return target.type == MitmPacketType::kAny
                   ? "等该方向第 " + std::to_string(target.index) + " 个包（含握手包）"
                   : "等第 " + std::to_string(target.index) + " 条" +
                         attack::mitmPacketTypeToString(target.type);
    }
    if (target.type != MitmPacketType::kAny) {
        return std::string("等下一个 ") + attack::mitmPacketTypeToString(target.type) + " 包";
    }
    return "等该方向的下一个包";
}

void handleCommand(MitmRelay& relay, const std::string& line, MitmDirection defaultDirection) {
    std::istringstream stream(line);
    std::string command;
    stream >> command;
    if (command.empty()) {
        return;
    }
    if (command == "quit" || command == "exit") {
        relay.stop();
        return;
    }
    if (command == "status") {
        printStatus(relay.stats());
        return;
    }
    if (command == "help") {
        printUsage();
        return;
    }
    if (command == "replay") {
        const TargetArgs args = parseTargetArgs(stream, defaultDirection);
        if (!args.ok) {
            emit("ERR replay 的参数看不懂（输入 help 看用法）");
            return;
        }
        relay.queueReplay(args.target, args.direction);
        emit(std::string("QUEUED kind=replay dir=") + directionTag(args.direction) +
             " target=" + targetDescription(args.target) +
             " waiting=" + waitingDescription(args.target));
        return;
    }

    MitmAttack kind = MitmAttack::kNone;
    int delayMs = 0;
    if (command == "tamper") {
        kind = MitmAttack::kTamper;
    } else if (command == "drop") {
        kind = MitmAttack::kDrop;
    } else if (command == "delay") {
        kind = MitmAttack::kDelay;
        if (!(stream >> delayMs)) {
            delayMs = 500;
        }
    } else {
        emit("ERR 无法识别的命令：" + command + "（输入 help 看用法）");
        return;
    }

    const TargetArgs args = parseTargetArgs(stream, defaultDirection);
    if (!args.ok) {
        emit("ERR 攻击参数看不懂（输入 help 看用法）");
        return;
    }
    if (kind == MitmAttack::kDrop && args.target.lastOfType) {
        emit("ERR drop 不能用于「最近一条包」——那个包早就转发过去了（改用 tamper/replay）");
        return;
    }
    relay.queueAttack(kind, args.target, args.direction, delayMs);
    std::ostringstream oss;
    oss << "QUEUED kind=" << attack::mitmAttackToString(kind) << " dir="
        << directionTag(args.direction) << " target=" << targetDescription(args.target)
        << " waiting=" << waitingDescription(args.target);
    if (kind == MitmAttack::kDelay) {
        oss << " ms=" << delayMs;
    }
    emit(oss.str());
}

}  // namespace

int main(int argc, char** argv) {
    stconsole::ensureUtf8();

    attack::MitmConfig config;
    MitmDirection defaultDirection = MitmDirection::kC2S;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const bool hasNext = (i + 1) < argc;
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        } else if (arg == "--listen" && hasNext) {
            config.listenPort = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        } else if (arg == "--target" && hasNext) {
            if (!parseTarget(argv[++i], config.targetHost, config.targetPort)) {
                std::cerr << "[EVE] --target 格式非法（应为 host:port）" << std::endl;
                return 2;
            }
        } else if (arg == "--direction" && hasNext) {
            defaultDirection = parseDirection(argv[++i], MitmDirection::kC2S);
        } else if (arg == "--quiet") {
            config.quiet = true;
        } else {
            std::cerr << "[EVE] 未知参数：" << arg << std::endl;
            printUsage();
            return 2;
        }
    }

    // 不传回调：库里直接以 "[EVE] ..." 打到 stdout，QProcess 才能读到。
    MitmRelay relay(std::move(config));
    std::string error;
    if (!relay.start(&error)) {
        emit("FATAL " + error);
        return 1;
    }

    // stdin 命令放在独立线程里读。
    //
    // ⚠ 不能让主线程去读 stdin：图形界面是用管道喂命令的（管道一直开着），
    //    getline 会一直阻塞，于是"连接已经结束"这件事主线程根本看不到 ——
    //    结果中继进程会赖着不走（端口不释放），下一次启动就会撞上"端口被占用"。
    //    实测就是这么翻车的。这里让主线程只负责盯着 relay.running()。
    std::thread stdinThread([&relay, defaultDirection]() {
        std::string line;
        while (relay.running() && std::getline(std::cin, line)) {
            handleCommand(relay, line, defaultDirection);
        }
    });
    stdinThread.detach();

    while (relay.running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    printStatus(relay.stats());
    emit("BYE");
    relay.stop();
    return 0;
}
