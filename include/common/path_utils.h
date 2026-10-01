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
#include <string>

#include <sys/stat.h>
#include <sys/types.h>

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
        if (::mkdir(current.c_str(), 0755) != 0 && errno != EEXIST) {
            return false;
        }
    }
    return true;
}

#endif  // SECURETRANSFER_COMMON_PATH_UTILS_H
