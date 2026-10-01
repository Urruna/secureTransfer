// ============================================================================
//  SecureTransfer 测试
//  file: tests/test_util.h
//
//  说明：极简测试框架（header-only），不引入第三方依赖。
//        用法：
//            ST_TEST_CASE("名称") { ST_CHECK(...); ST_CHECK_EQ(a, b); }
//            int main() { return ::testutil::runAll("suite"); }
// ============================================================================

#ifndef SECURETRANSFER_TESTS_TEST_UTIL_H
#define SECURETRANSFER_TESTS_TEST_UTIL_H

#include <cstdlib>
#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "common/console.h"
#include "common/path_utils.h"

namespace testutil {

/// 跨平台临时目录：Windows 用 %TEMP%，Linux 用 /tmp。
inline std::string tempDir() {
#if defined(_WIN32)
    const char* base = std::getenv("TEMP");
    std::string dir = (base != nullptr && *base != '\0') ? base : std::string(".");
    for (char& c : dir) {
        if (c == '\\') {
            c = '/';
        }
    }
    return dir + "/st_tests";
#else
    return "/tmp/st_tests";
#endif
}

/// 取一个已经创建好的工作子目录。
inline std::string workDir(const std::string& name) {
    const std::string dir = tempDir() + "/" + name;
    (void)ensureDirectory(dir);
    return dir;
}

/// 断言失败时抛出的异常。
class Failure : public std::exception {
public:
    explicit Failure(std::string message) : message_(std::move(message)) {}

    const char* what() const noexcept override {
        return message_.c_str();
    }

private:
    std::string message_;
};

struct TestCase {
    std::string name;
    std::function<void()> body;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> cases;
    return cases;
}

/// 静态对象：在 main() 之前把测试用例注册进 registry()。
struct Registrar {
    Registrar(const char* name, std::function<void()> body) {
        registry().push_back(TestCase{std::string(name), std::move(body)});
    }
};

// ---------------------------------------------------------------------------
// 断言失败时的可读输出
// ---------------------------------------------------------------------------
inline std::string describe(const std::string& value) {
    return value;
}

inline std::string describe(const char* value) {
    return value != nullptr ? std::string(value) : std::string("(null)");
}

inline std::string describe(bool value) {
    return value ? "true" : "false";
}

inline std::string describe(unsigned char value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << static_cast<int>(value);
    return oss.str();
}

template <typename T>
std::string describe(const T& value) {
    std::ostringstream oss;
    oss << value;
    return oss.str();
}

inline int runAll(const std::string& suiteName) {
    ::stconsole::ensureUtf8();
    int failed = 0;
    const std::size_t total = registry().size();

    std::cout << "=== test suite: " << suiteName << " (" << total << " case(s)) ===" << std::endl;

    for (const TestCase& test : registry()) {
        try {
            test.body();
            std::cout << "  [PASS] " << test.name << std::endl;
        } catch (const Failure& failure) {
            ++failed;
            std::cout << "  [FAIL] " << test.name << "\n          " << failure.what() << std::endl;
        } catch (const std::exception& error) {
            ++failed;
            std::cout << "  [FAIL] " << test.name
                      << "\n          unexpected exception: " << error.what() << std::endl;
        } catch (...) {
            ++failed;
            std::cout << "  [FAIL] " << test.name << "\n          unknown exception" << std::endl;
        }
    }

    std::cout << "=== " << (failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED") << ": "
              << (total - static_cast<std::size_t>(failed)) << "/" << total << " passed ==="
              << std::endl;
    return failed == 0 ? 0 : 1;
}

}  // namespace testutil

#define ST_TEST_CONCAT_IMPL(a, b) a##b
#define ST_TEST_CONCAT(a, b) ST_TEST_CONCAT_IMPL(a, b)
#define ST_TEST_CASE_IMPL(name, id)                                                        \
    static void ST_TEST_CONCAT(st_testBody_, id)();                                        \
    static ::testutil::Registrar ST_TEST_CONCAT(st_testReg_, id)(                          \
        name, &ST_TEST_CONCAT(st_testBody_, id));                                          \
    static void ST_TEST_CONCAT(st_testBody_, id)()

#define ST_TEST_CASE(name) ST_TEST_CASE_IMPL(name, __COUNTER__)

#define ST_CHECK(condition)                                                                \
    do {                                                                                   \
        if (!(condition)) {                                                                \
            std::ostringstream st_message;                                                 \
            st_message << __FILE__ << ":" << __LINE__ << " ST_CHECK failed: " #condition;  \
            throw ::testutil::Failure(st_message.str());                                   \
        }                                                                                  \
    } while (false)

#define ST_CHECK_EQ(actual, expected)                                                      \
    do {                                                                                   \
        const auto& st_actual = (actual);                                                  \
        const auto& st_expected = (expected);                                              \
        if (!(st_actual == st_expected)) {                                                 \
            std::ostringstream st_message;                                                 \
            st_message << __FILE__ << ":" << __LINE__ << " ST_CHECK_EQ failed: " #actual   \
                       << " == " #expected << "\n          actual  : "                    \
                       << ::testutil::describe(st_actual) << "\n          expected: "      \
                       << ::testutil::describe(st_expected);                               \
            throw ::testutil::Failure(st_message.str());                                   \
        }                                                                                  \
    } while (false)

#endif  // SECURETRANSFER_TESTS_TEST_UTIL_H
