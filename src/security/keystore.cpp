// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: src/security/keystore.cpp
// ============================================================================

#include "security/keystore.h"

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

#include <cctype>
#include <fstream>
#include <sstream>

#include "common/hex.h"

namespace {

std::string trim(const std::string& text) {
    std::size_t begin = 0;
    std::size_t end = text.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) {
        --end;
    }
    return text.substr(begin, end - begin);
}

std::string stripInlineComment(const std::string& line) {
    const std::size_t hash = line.find('#');
    if (hash != std::string::npos) {
        return line.substr(0, hash);
    }
    return line;
}

}  // namespace

bool KeyStore::parseKey(const std::string& text, Key128& out, std::string& error) {
    Bytes parsed;
    if (!fromHex(text, parsed)) {
        error = "密钥不是合法的十六进制字符串";
        return false;
    }
    if (parsed.size() != out.size()) {
        error = "密钥长度必须为 16 字节（32 个十六进制字符），实际为 " +
                std::to_string(parsed.size()) + " 字节";
        return false;
    }
    return copyToArray(parsed, out);
}

bool KeyStore::parse(const std::string& text, KeyStoreConfig& out, std::string& error) {
    std::istringstream stream(text);
    std::string line;
    std::string rawKeyText;
    bool sawAnyKey = false;

    while (std::getline(stream, line)) {
        const std::string stripped = trim(stripInlineComment(line));
        if (stripped.empty() || stripped[0] == ';' || stripped[0] == '[') {
            continue;
        }

        const std::size_t equals = stripped.find('=');
        if (equals == std::string::npos) {
            // 简化写法：整个文件就是密钥
            rawKeyText += stripped;
            continue;
        }

        const std::string name = trim(stripped.substr(0, equals));
        const std::string value = trim(stripped.substr(equals + 1));
        if (name == "alice_id") {
            out.aliceId = value;
        } else if (name == "bob_id") {
            out.bobId = value;
        } else if (name == "master_key") {
            rawKeyText = value;
            sawAnyKey = true;
        }
    }

    if (rawKeyText.empty()) {
        error = "配置中没有找到 master_key";
        return false;
    }
    if (!parseKey(rawKeyText, out.masterKey, error)) {
        return false;
    }
    out.hasMasterKey = true;
    (void)sawAnyKey;
    return true;
}

bool KeyStore::loadFile(const std::string& path,
                        KeyStoreConfig& out,
                        std::string& error,
                        std::string& warning) {
    std::ifstream file(path);
    if (!file) {
        error = "无法打开密钥配置文件: " + path;
        return false;
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();

    if (!parse(buffer.str(), out, error)) {
        error = path + ": " + error;
        return false;
    }
    out.source = path;
    checkFilePermissions(path, warning);
    return true;
}

bool KeyStore::checkFilePermissions(const std::string& path, std::string& warning) {
#if defined(_WIN32)
    // Windows 没有 POSIX 权限位语义：密钥文件的访问控制由 NTFS ACL 负责，
    // 这里不做检查（避免对每个密钥文件都误报“权限过宽”）。
    (void)path;
    warning.clear();
    return true;
#else
    struct stat info {};
    if (::stat(path.c_str(), &info) != 0) {
        warning = "无法读取文件权限: " + path;
        return false;
    }
    if ((info.st_mode & S_IRGRP) != 0 || (info.st_mode & S_IROTH) != 0) {
        warning = "密钥文件 " + path +
                  " 对 group/other 可读，建议执行 chmod 600 收紧权限";
        return false;
    }
    return true;
#endif
}

std::string KeyStore::keyFingerprint(const Key128& key) {
    // FNV-1a 64 位，仅用于标识密钥，不能从中恢复密钥。
    std::uint64_t state = 1469598103934665603ULL;
    for (Byte b : key) {
        state = (state ^ b) * 1099511628211ULL;
    }
    std::ostringstream oss;
    oss << std::hex << state;
    return oss.str();
}
