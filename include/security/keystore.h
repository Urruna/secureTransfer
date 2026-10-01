// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/security/keystore.h
//
//  说明：长期认证密钥 K_master 与身份标识的"带外预配置"读取。
//
//  课程要求 K_master 不能通过网络传输，因此这里从本地配置文件读取
//  （见 configs/keys.conf）。配置文件最长 32 个十六进制字符的密钥，
//  并且建议权限为 600：如果 group/other 可读，会给出警告。
//
//  安全提示：本模块不会、也不允许把密钥写入日志。
// ============================================================================

#ifndef SECURETRANSFER_SECURITY_KEYSTORE_H
#define SECURETRANSFER_SECURITY_KEYSTORE_H

#include <string>

#include "common/types.h"

struct KeyStoreConfig {
    std::string aliceId = "alice";
    std::string bobId = "bob";
    Key128 masterKey{};
    bool hasMasterKey = false;
    std::string source;
};

class KeyStore {
public:
    /// 从配置文件读取；失败时 error 给出原因。
    /// 文件格式：`键 = 值`，以 # 或 ; 开头的行为注释。
    /// 也接受"整个文件就是 32 个十六进制字符"的简化写法。
    static bool loadFile(const std::string& path,
                         KeyStoreConfig& out,
                         std::string& error,
                         std::string& warning);

    /// 直接解析文本内容（便于测试）。
    static bool parse(const std::string& text, KeyStoreConfig& out, std::string& error);

    /// 解析 32 个十六进制字符的密钥。
    static bool parseKey(const std::string& text, Key128& out, std::string& error);

    /// 检查文件权限：group/other 可读时把提示写进 warning。
    static bool checkFilePermissions(const std::string& path, std::string& warning);

    /// 密钥指纹：只用于在报告中标识"用的是哪把密钥"，不泄漏密钥本身。
    static std::string keyFingerprint(const Key128& key);
};

#endif  // SECURETRANSFER_SECURITY_KEYSTORE_H
