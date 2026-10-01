// ============================================================================
//  SecureTransfer - 公共：控制台编码（实现）
//  file: src/common/console.cpp
//
//  平台差异集中在这里：
//    * Windows：SetConsoleOutputCP(CP_UTF8) / SetConsoleCP(CP_UTF8)
//    * POSIX  ：无需处理（空实现）
// ============================================================================

#include "common/console.h"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// <windows.h> 会把 ERROR 定义成数值宏，与本工程的 stlog::Level::ERROR 冲突。
#ifdef ERROR
#undef ERROR
#endif

#endif  // _WIN32

namespace stconsole {

void ensureUtf8() {
#if defined(_WIN32)
    static bool applied = false;
    if (applied) {
        return;
    }
    applied = true;
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);
#endif
}

}  // namespace stconsole
