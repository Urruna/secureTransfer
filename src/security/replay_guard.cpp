// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: src/security/replay_guard.cpp
// ============================================================================

#include "security/replay_guard.h"

void ReplayGuard::reset() {
    hasLast_ = false;
    last_ = 0;
    accepted_ = 0;
    rejected_ = 0;
    gaps_ = 0;
}

bool ReplayGuard::wouldAccept(std::uint64_t sequence, std::string* reason) const {
    if (!hasLast_) {
        return true;
    }
    if (sequence > last_) {
        return true;
    }
    if (reason != nullptr) {
        *reason = "序号 " + std::to_string(sequence) + " 不大于已接收的最大序号 " +
                  std::to_string(last_) + "（重放或乱序）";
    }
    return false;
}

bool ReplayGuard::commit(std::uint64_t sequence) {
    if (!hasLast_) {
        hasLast_ = true;
        last_ = sequence;
        ++accepted_;
        return true;
    }
    if (sequence <= last_) {
        ++rejected_;
        return false;
    }
    if (sequence != last_ + 1) {
        ++gaps_;
    }
    last_ = sequence;
    ++accepted_;
    return true;
}

bool ReplayGuard::accept(std::uint64_t sequence, std::string* reason) {
    if (!wouldAccept(sequence, reason)) {
        ++rejected_;
        return false;
    }
    return commit(sequence);
}

std::uint64_t ReplayGuard::lastSequence() const {
    return last_;
}

bool ReplayGuard::hasLastSequence() const {
    return hasLast_;
}

std::uint64_t ReplayGuard::acceptedCount() const {
    return accepted_;
}

std::uint64_t ReplayGuard::rejectedCount() const {
    return rejected_;
}

std::uint64_t ReplayGuard::gapCount() const {
    return gaps_;
}
