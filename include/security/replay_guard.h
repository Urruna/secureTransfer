// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/security/replay_guard.h
//
//  说明：防重放检查（每个方向一个实例）。
//
//  为什么分成两个步骤（wouldAccept / commit）：
//    如果"检查序号"直接推进状态，那么攻击者只要伪造一个序号很大的包
//    （MAC 会验证失败），就能把水位推到很大，导致后续所有合法包被误判为
//    重放 —— 这是一个拒绝服务漏洞。因此协议层先调用 wouldAccept()
//    （只判断、不改状态），MAC 验证通过之后再 commit() 推进水位。
// ============================================================================

#ifndef SECURETRANSFER_SECURITY_REPLAY_GUARD_H
#define SECURETRANSFER_SECURITY_REPLAY_GUARD_H

#include <cstdint>
#include <string>

class ReplayGuard {
public:
    void reset();

    /// 只判断该序号是否可以接受，不修改任何状态。
    bool wouldAccept(std::uint64_t sequence, std::string* reason = nullptr) const;

    /// 确认接受该序号（MAC 已验证通过后调用），并推进水位。
    bool commit(std::uint64_t sequence);

    /// = wouldAccept + commit，便于单元测试与简单场景使用。
    bool accept(std::uint64_t sequence, std::string* reason = nullptr);

    std::uint64_t lastSequence() const;
    bool hasLastSequence() const;
    std::uint64_t acceptedCount() const;
    std::uint64_t rejectedCount() const;
    std::uint64_t gapCount() const;

private:
    bool hasLast_ = false;
    std::uint64_t last_ = 0;
    std::uint64_t accepted_ = 0;
    std::uint64_t rejected_ = 0;
    std::uint64_t gaps_ = 0;
};

#endif  // SECURETRANSFER_SECURITY_REPLAY_GUARD_H
