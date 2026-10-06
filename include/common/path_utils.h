// ============================================================================
//  SecureTransfer - 公共：目录创建辅助
//  file: include/common/path_utils.h
//
//  说明：递归创建目录（等价于 `mkdir -p`）。
//        这里用 POSIX `mkdir()` 自己实现，而不用 `std::filesystem`——
//        因为 g++ 9 需要额外链接 `-lstdc++fs`，而本工程要求零额外依赖。
// ============================================================================

#ifndef SECURETRANSFER_COMMON_PATH_UTILS_H
#define SECURETRANSFER_COMMON_PATH_UTILS_H

#include <cerrno>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "common/text_encoding.h"

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

/// 把内部统一的 **UTF-8** 路径换成平台文件 API 需要的宽字符路径。
///
/// 为什么需要它：Windows 上 `std::ifstream(std::string)` / `::_mkdir()` 这类窄字符接口
/// 按 **ANSI 代码页**（简体中文系统 = GBK）解释路径，把 UTF-8 字节直接传进去
/// 会打不开文件——表现就是"只能传英文路径，带中文的文件选得到但发不出去"。
/// 转成宽字符后走的是 Unicode API，中文路径就正常了。
inline std::wstring widePathForFileApi(const std::string& utf8Path) {
    return sttext::toWide(utf8Path);
}

/// 以 UTF-8 路径打开输入文件（默认二进制，支持中文路径）。
inline std::ifstream openInputFile(const std::string& path,
                                   std::ios::openmode mode = std::ios::binary) {
#if defined(_WIN32)
    return std::ifstream(widePathForFileApi(path).c_str(), mode);
#else
    return std::ifstream(path, mode);
#endif
}

/// 以 UTF-8 路径打开输出文件（默认二进制 + 截断，支持中文路径）。
inline std::ofstream openOutputFile(const std::string& path,
                                    std::ios::openmode mode = std::ios::binary |
                                                               std::ios::trunc) {
#if defined(_WIN32)
    return std::ofstream(widePathForFileApi(path).c_str(), mode);
#else
    return std::ofstream(path, mode);
#endif
}

/// 递归创建目录（已存在则视为成功）。
inline bool ensureDirectory(const std::string& path) {
    if (path.empty()) {
        return true;
    }
    std::string current;
    std::size_t index = 0;
    if (path[0] == '/') {
        current = "/";
        index = 1;
    }
    while (index <= path.size()) {
        const std::size_t slash = path.find('/', index);
        const std::string part =
            slash == std::string::npos ? path.substr(index) : path.substr(index, slash - index);
        index = (slash == std::string::npos) ? path.size() + 1 : slash + 1;
        if (part.empty()) {
            continue;
        }
        if (!current.empty() && current.back() != '/') {
            current += '/';
        }
        current += part;
#if defined(_WIN32)
        // 盘符（如 "D:"）本身不是目录，跳过创建，只把它当成后续路径的前缀
        if (part.size() == 2 && part[1] == ':') {
            continue;
        }
        // 用宽字符版本 _wmkdir：这样路径里带中文也能创建成功
        if (::_wmkdir(widePathForFileApi(current).c_str()) != 0 && errno != EEXIST) {
#else
        if (::mkdir(current.c_str(), 0755) != 0 && errno != EEXIST) {
#endif
            return false;
        }
    }
    return true;
}

#endif  // SECURETRANSFER_COMMON_PATH_UTILS_H
