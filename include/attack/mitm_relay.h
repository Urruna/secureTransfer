// ============================================================================
//  SecureTransfer - 第三部分：中间人中继（攻击者侧工具）
//  file: include/attack/mitm_relay.h
//
//  一个"坐在链路中间"的 TCP 中继：默认原样双工转发，可被要求对某个方向的
//  某个包做篡改 / 丢弃 / 延迟 / 重放。它**没有任何密钥**，也不实现任何密码学
//  逻辑，因此它只能做到"转发 + 破坏"，做不到解密或冒充。
//
//      Alice ──connect──▶ [ MitmRelay :9400 ] ──connect──▶ Bob :9000
//
//  两种用法：
//    * `apps/eve`（独立进程）—— 图形界面的"真实链路中间人"演示；
//    * 单元 / 集成测试里作为线程 —— 不依赖外部进程，CI 友好。
//
//  线程模型：start() 之后内部起两条转发线程（C2S / S2C）；queueAttack() 等
//  控制接口线程安全，可从任意线程调用。
// ============================================================================

#ifndef SECURETRANSFER_ATTACK_MITM_RELAY_H
#define SECURETRANSFER_ATTACK_MITM_RELAY_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace attack {

/// 中继可以对一个包做的事。
enum class MitmAttack {
    kNone = 0,
    kTamper,  ///< 改 Body 首字节 + 序号加一（必然被 ⑥ 或 ⑦ 关拒绝）
    kDrop,    ///< 不转发（可用性攻击：密码学防不住，只能表现为超时）
    kDelay    ///< 延迟若干毫秒后转发
};

/// 中继对外的可读名（用于日志与界面）。
const char* mitmAttackToString(MitmAttack attack);

/// 限定"打哪种包"（比"第几个包"更贴近人的说法：我想改的是下一条短消息）。
enum class MitmPacketType {
    kAny = 0,   ///< 不限定
    kData,      ///< 短消息 / 业务数据（DATA）
    kFileChunk, ///< 文件块（FILE_CHUNK）
    kImage      ///< 图像（IMAGE）
};

const char* mitmPacketTypeToString(MitmPacketType type);

/// 攻击目标（"打哪一个包"）。
///
///   默认（index=0, type=kAny, lastOfType=false）  → 该方向的下一个包
///   index > 0                                     → 该方向第 index 个包
///   type != kAny，index == 0                       → 下一个该类型的包
///   type != kAny，lastOfType == true               → **最近一条已转发的该类型包**，立即下手
///                                                   （捕获-篡改-重发；只对篡改/重放有意义）
struct MitmTarget {
    std::uint64_t index = 0;
    MitmPacketType type = MitmPacketType::kAny;
    bool lastOfType = false;

    /// 是否"等下一个包"（true 时才需要挂在转发路径上）。
    bool waitsForNextPacket() const { return !(lastOfType && type != MitmPacketType::kAny); }
};

/// 方向常量：与 Packet::direction 的取值对应。
enum class MitmDirection { kC2S = 0, kS2C = 1, kBoth = 2 };

struct MitmConfig {
    std::uint16_t listenPort = 9400;     ///< 监听端口，0 = 由系统分配
    std::string targetHost = "127.0.0.1";///< 真正的服务端地址
    std::uint16_t targetPort = 9000;     ///< 真正的服务端端口
    bool quiet = false;                  ///< true = 不逐包回调（只回调攻击与状态）
};

/// 统计（供界面显示"转发 / 篡改 / 丢弃 / 延迟 / 重放"计数）。
struct MitmStats {
    std::uint64_t forwarded = 0;
    std::uint64_t tampered = 0;
    std::uint64_t dropped = 0;
    std::uint64_t delayed = 0;
    std::uint64_t replayed = 0;
    std::uint64_t undecodable = 0;
    std::uint64_t c2sPackets = 0;
    std::uint64_t s2cPackets = 0;
};

class MitmRelay {
public:
    /// 日志回调：中继每产生一行可读输出就调用一次。
    /// 形如 `PACKET dir=C2S n=5 type=DATA seq=1 …` / `ATTACK kind=tamper …`。
    using LineCallback = std::function<void(const std::string&)>;

    explicit MitmRelay(MitmConfig config, LineCallback onLine = nullptr);
    ~MitmRelay();

    MitmRelay(const MitmRelay&) = delete;
    MitmRelay& operator=(const MitmRelay&) = delete;

    /// 开始监听并等待客户端接入（内部起线程，本调用很快返回）。
    /// 返回 false 时 error 给出原因（端口占用等）。
    bool start(std::string* error = nullptr);

    /// 等待"客户端已接入且已连上真正的服务端"。测试用它同步。
    bool waitForConnection(int timeoutMs);

    /// 实际绑定的端口（listenPort == 0 时由系统分配，测试靠它拿到端口）。
    std::uint16_t listenPort() const;

    /// 是否还在转发（任一方断开后置 false）。
    bool running() const;

    /// 下发一次攻击。
    /// @param target    打哪一个包（见 MitmTarget；lastOfType 是"立即下手"，不进队列）
    /// @param delayMs   仅 kDelay 使用
    void queueAttack(MitmAttack attack, MitmTarget target = MitmTarget{},
                     MitmDirection direction = MitmDirection::kC2S, int delayMs = 0);

    /// 原样重发目标包（默认：把"刚转发的那一个"再发一遍）。
    void queueReplay(MitmTarget target = MitmTarget{},
                     MitmDirection direction = MitmDirection::kC2S);

    MitmStats stats() const;

    /// 停止转发并关闭两端连接（可重复调用）。
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace attack

#endif  // SECURETRANSFER_ATTACK_MITM_RELAY_H
