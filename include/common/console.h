// ============================================================================
//  SecureTransfer - 公共：控制台编码
//  file: include/common/console.h
//
//  说明：Windows 控制台默认使用本地 ANSI 代码页（简体中文系统为 GBK），
//        而本工程的日志 / 提示全部是 UTF-8 字符串，直接输出会变成乱码。
//        在程序入口调用 stconsole::ensureUtf8() 把控制台输出切到 UTF-8。
//        POSIX（Ubuntu 621 虚拟机）下该函数是空操作，终端本身就是 UTF-8。
//
//  注意：只影响控制台输出，不改变文件读写的编码约定。
// ============================================================================

#ifndef SECURETRANSFER_COMMON_CONSOLE_H
#define SECURETRANSFER_COMMON_CONSOLE_H

namespace stconsole {

/// 把标准输出 / 标准错误切换到 UTF-8。可重复调用（内部只生效一次）。
/// Windows 下同时切换控制台输入代码页，便于输入中文测试消息。
void ensureUtf8();

}  // namespace stconsole

#endif  // SECURETRANSFER_COMMON_CONSOLE_H
