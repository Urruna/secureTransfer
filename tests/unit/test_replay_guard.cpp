// ============================================================================
//  SecureTransfer 测试
//  file: tests/unit/test_replay_guard.cpp
//
//  说明：防重放检查的行为测试，特别是"只判断不推进"的 wouldAccept()。
// ============================================================================

#include "test_util.h"

#include <string>

#include "security/replay_guard.h"

ST_TEST_CASE("replay_guard: 顺序序号全部接受") {
    ReplayGuard guard;
    std::string reason;
    ST_CHECK(guard.accept(1, &reason));
    ST_CHECK(guard.accept(2, &reason));
    ST_CHECK(guard.accept(3, &reason));
    ST_CHECK_EQ(guard.lastSequence(), 3u);
    ST_CHECK_EQ(guard.acceptedCount(), 3u);
    ST_CHECK_EQ(guard.rejectedCount(), 0u);
    ST_CHECK_EQ(guard.gapCount(), 0u);
}

ST_TEST_CASE("replay_guard: 重复序号被拒绝（重放）") {
    ReplayGuard guard;
    ST_CHECK(guard.accept(1));
    ST_CHECK(guard.accept(2));
    std::string reason;
    ST_CHECK(!guard.accept(2, &reason));
    ST_CHECK(!reason.empty());
    ST_CHECK_EQ(guard.lastSequence(), 2u);
    ST_CHECK_EQ(guard.rejectedCount(), 1u);
}

ST_TEST_CASE("replay_guard: 回退序号被拒绝") {
    ReplayGuard guard;
    ST_CHECK(guard.accept(5));
    ST_CHECK(!guard.accept(4));
    ST_CHECK(!guard.accept(1));
    ST_CHECK_EQ(guard.rejectedCount(), 2u);
}

ST_TEST_CASE("replay_guard: 首次接受任意序号") {
    ReplayGuard guard;
    ST_CHECK(guard.accept(1000));
    ST_CHECK(guard.hasLastSequence());
    ST_CHECK_EQ(guard.lastSequence(), 1000u);
}

ST_TEST_CASE("replay_guard: 跳号接受并记录缺口") {
    ReplayGuard guard;
    ST_CHECK(guard.accept(1));
    ST_CHECK(guard.accept(5));
    ST_CHECK_EQ(guard.gapCount(), 1u);
    ST_CHECK_EQ(guard.acceptedCount(), 2u);
}

ST_TEST_CASE("replay_guard: wouldAccept 不改变状态") {
    ReplayGuard guard;
    // 未接受过任何包时，任意序号都"看起来可以"
    ST_CHECK(guard.wouldAccept(999));
    ST_CHECK(!guard.hasLastSequence());
    ST_CHECK_EQ(guard.lastSequence(), 0u);

    ST_CHECK(guard.accept(10));
    // 伪造一个很大的序号：只是判断，不应推进水位
    ST_CHECK(guard.wouldAccept(100000));
    ST_CHECK_EQ(guard.lastSequence(), 10u);
    // 因此后续的合法序号仍然被接受（不会因为伪造包而误判重放）
    ST_CHECK(guard.accept(11));
}

ST_TEST_CASE("replay_guard: reset 清空状态") {
    ReplayGuard guard;
    ST_CHECK(guard.accept(7));
    guard.reset();
    ST_CHECK(!guard.hasLastSequence());
    ST_CHECK_EQ(guard.acceptedCount(), 0u);
    ST_CHECK_EQ(guard.rejectedCount(), 0u);
    ST_CHECK(guard.accept(1));
}

int main() {
    return ::testutil::runAll("replay_guard");
}
