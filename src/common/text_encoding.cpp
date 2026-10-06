// ============================================================================
//  SecureTransfer - 公共：文本编码转换（实现）
//  file: src/common/text_encoding.cpp
// ============================================================================

#include "common/text_encoding.h"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>  // CommandLineToArgvW

// <windows.h> 会把 ERROR 定义成数值宏，与本工程的 stlog::Level::ERROR 冲突。
#ifdef ERROR
#undef ERROR
#endif

#endif  // _WIN32

namespace sttext {

std::string toUtf8(const std::wstring& text) {
#if defined(_WIN32)
    if (text.empty()) {
        return std::string();
    }
    const int needed = ::WideCharToMultiByte(CP_UTF8, 0, text.data(),
                                             static_cast<int>(text.size()), nullptr, 0, nullptr,
                                             nullptr);
    if (needed <= 0) {
        return std::string();
    }
    std::string out(static_cast<std::size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(),
                          needed, nullptr, nullptr);
    return out;
#else
    std::string out;
    out.reserve(text.size());
    for (wchar_t ch : text) {
        out.push_back(static_cast<char>(ch & 0xFF));
    }
    return out;
#endif
}

std::wstring toWide(const std::string& text) {
#if defined(_WIN32)
    if (text.empty()) {
        return std::wstring();
    }
    const int needed = ::MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                             static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) {
        return std::wstring();
    }
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(),
                          needed);
    return out;
#else
    std::wstring out;
    out.reserve(text.size());
    for (char ch : text) {
        out.push_back(static_cast<wchar_t>(static_cast<unsigned char>(ch)));
    }
    return out;
#endif
}

std::vector<std::string> utf8CommandLine(int argc, char** argv) {
#if defined(_WIN32)
    (void)argc;
    (void)argv;
    std::vector<std::string> args;
    int wideCount = 0;
    LPWSTR* wideArgs = ::CommandLineToArgvW(::GetCommandLineW(), &wideCount);
    if (wideArgs == nullptr) {
        return args;
    }
    args.reserve(static_cast<std::size_t>(wideCount));
    for (int i = 0; i < wideCount; ++i) {
        args.push_back(toUtf8(std::wstring(wideArgs[i])));
    }
    ::LocalFree(wideArgs);
    return args;
#else
    std::vector<std::string> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        args.push_back(argv[i] != nullptr ? std::string(argv[i]) : std::string());
    }
    return args;
#endif
}

}  // namespace sttext
