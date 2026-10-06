// ============================================================================
//  SecureTransfer - 公共：文本编码转换与命令行参数
//  file: include/common/text_encoding.h
//
//  背景：本工程内部统一用 **UTF-8** 表示字符串（路径、身份、日志）。
//        Linux 下这没问题（文件系统就是字节串），但 Windows 上：
//          * std::ifstream / std::ofstream / _mkdir 的窄字符接口按 **ANSI 代码页**
//            （简体中文系统是 GBK）解释路径，直接把 UTF-8 字节丢进去会打不开文件
//            —— 这就是"只能传英文路径"的根因；
//          * Win32 API 返回的错误文本是宽字符（或本地代码页），直接当 UTF-8 打印会乱码。
//        所以这里提供两件事：UTF-8 ↔ UTF-16 转换，以及"统一 UTF-8"的命令行参数。
// ============================================================================

#ifndef SECURETRANSFER_COMMON_TEXT_ENCODING_H
#define SECURETRANSFER_COMMON_TEXT_ENCODING_H

#include <string>
#include <vector>

namespace sttext {

/// UTF-16 → UTF-8。非 Windows 平台按"逐字符字节复制"处理（仅用于保持接口一致）。
std::string toUtf8(const std::wstring& text);

/// UTF-8 → UTF-16。非 Windows 平台按"逐字符字节复制"处理。
std::wstring toWide(const std::string& text);

/// 取统一为 UTF-8 的命令行参数。
///
/// Windows：用 GetCommandLineW + CommandLineToArgvW 取宽字符参数再转 UTF-8，
///          这样即使参数里有中文（例如 `--file 测试图像.png`）也不会被 ANSI 代码页破坏；
/// 其它平台：直接复制 argv（本来就是 UTF-8）。
std::vector<std::string> utf8CommandLine(int argc, char** argv);

}  // namespace sttext

#endif  // SECURETRANSFER_COMMON_TEXT_ENCODING_H
