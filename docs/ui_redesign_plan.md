# UI 改造与 Eve 攻击面板 · 实施计划（修订版 v2）

> **状态：P1–P5 已实施完成并实测通过；P6 仅剩打包 `dist/`**（原稿 2026-10-09，修订与实施同日）。
>
> 修订依据：
> 1. **样式与布局以 `docs/SecureTransfer_UI改造草图.html` 为权威**（该草图给出顶部标题条、工具条、三栏比例、卡片风格、状态栏的完整视觉规范）；
> 2. 对原稿的全部行号与前提做了逐条核对，修正了 6 处（见 §1.2）；
> 3. 对原稿的 3 处会导致返工/回归的问题给出强制约束（见 §1.3）。
>
> 实施中每完成一个阶段都要重新定位行号——仓库一直在演进（例：`session.cpp` 原稿写 730 行，实际 736 行）。

---

## 0. 决策记录

| # | 决策点 | 结论 | 来源 |
| --- | --- | --- | --- |
| 1 | 攻击拦截"精确到第几关" | **改内核**：`SecureSession` 新增 `RejectGate` + 访问器 | 用户 |
| 2 | 受害端如何让攻击端看到判定结果 | **回执**：受害端在终止前回一条 `ATTACK-REPORT` | 用户 |
| 3 | 被拒绝后是否终止会话 | **先不动**：维持现状（拒绝即终止会话） | 用户 |
| 4 | 视觉风格 | **浅色扁平**，具体取值见 §5.1（取自草图） | 用户 |
| 5 | 改造范围 | **方案 B**：换皮 + 应用外壳重构（工具条/状态栏/三栏布局/高级设置） | 用户 |
| 6 | 亮点功能 | 日志分级着色 + 过滤、握手 7 步进度、高级设置收纳、Eve 攻击面板细化 | 用户 |
| 7 | 本轮不做 | 图像缩略图预览（O3） | 用户 |
| 8 | 握手进度条是否加内核钩子 | **加**（O1 选 a）——但只传 step 号，见 §5.4 | 本次修订 |
| 9 | 攻击回执是否留档 | **写**，但**单独一份 `experiment_data/attack_log.txt`**，不混进访问控制审计（O2） | 本次修订 |
| 10 | 协议文档与实现不一致 | **改文档对齐实现**（O4 选 b） | 本次修订 |

---

## 1. 评审结论

### 1.1 原稿正确的部分（已核对，保留）

| 事实 | 核对结果 |
| --- | --- |
| `main.cpp` 115 / `main_window.h` 129 / `main_window.cpp` 577 / `session_worker.h` 97 / `session_worker.cpp` 522 / `session.h` 238 / `demo_reply.h` 45 行 | **全部精确吻合** |
| 7 个 `QGroupBox` 行号 `:80/120/133/148/163/181/190` | **精确吻合** |
| 8 个信号在 `session_worker.h:67-74` | 吻合 |
| 篡改包构造在 `session_worker.cpp:337-348`（`body[0]^=0xFF`、`sequence+1`、`encodeWithMac()`） | 吻合 |
| `shouldAutoReply()` 白名单在 `demo_reply.h:26-43` | 吻合 |
| CMake `:114 find_package(Qt5 … QUIET)`、`:117 add_executable(st_ui)`、`:121 AUTOMOC ON` | 吻合；`Qt5` 是**可选**依赖，本轮不能破坏 |
| **§4.1 关键前提：`fail()` 不改变 `state_`** | **成立**（只设 `lastError_` + 日志）→ 回执发得出去 |
| `docs/protocol.md` §6.3 与实现不一致（文档"只拒绝该包/静默丢弃" vs 实现"拒绝即终止会话"） | **确实存在**，本轮按决策 10 修文档 |

### 1.2 原稿需要修正的 6 处

| # | 原稿说法 | 实际情况 | 处理 |
| --- | --- | --- | --- |
| C1 | `session.cpp` 730 行 | **736 行**（10-07 新增 `closeConnection()` 与握手总时限后 +6） | §7.9 强制"每阶段重新定位行号" |
| C2 | "`logHandshakeStep` 有 7 处调用点" | **13 处**：客户端 7（L224–L330）+ 服务端 6（L364–L456），且**服务端 ④⑤ 合并成一行** | 见 §5.4 的按角色映射方案 |
| C3 | 拒绝关卡"10 处记录 + 2 处置空" | 实际有 **11 处** `++stats_.rejected*`（3×format、6×state、1×replay、1×mac），原稿漏了 `protocolViolation()`（L728） | 见 §3.3，一并纳入 |
| C4 | `printGeometry` 在 `:508-533` | 实际 **L480–540**；`leftScroll_` 创建于 L223（原稿引的是 L232 的 `addWidget`） | 实施时重新定位 |
| C5 | "主界面只留 角色/地址/端口"，高级设置收 4 个路径项 | **本端身份/对端身份没交代**——而访问控制演示要频繁切换身份 | 见 §5.3：主界面保留"角色/地址/端口/本端身份"，对端身份随高级设置收纳 |
| C6 | 未给工作量估计 | — | 见 §6 分期表（含人天） |

### 1.3 原稿需要强制的 3 条约束（否则会回归）

| # | 风险 | 强制约束 |
| --- | --- | --- |
| R1 | **QSS 会改变 `sizeHint`**：现有"最小高度 = `sizeHint().height()`"的防回归机制（`main_window.cpp:215`）若在 QSS 之前算就失效 → "文字只显示一半"复发 | **QSS 必须在创建控件之前应用**：`main.cpp` 里 `QApplication` 构造之后、`MainWindow` 构造之前 `qApp->setStyleSheet(...)`；并在 P3/P4/P5 用 `--print-geometry` 验证（所有控件 height ≥ sizeHint） |
| R2 | 草图的 QSS 想用 `image:url(:/icons/*.svg)` 画下拉箭头，而 **Qt5::Svg 是可选依赖**；取不到图 → 箭头消失（正是原稿自己警告的坑） | 图标优先用 `QStyle::standardIcon()`（零资源、零依赖）；确需 SVG 时把 `Qt5::Svg` 设为可选，**找不到时回退内置箭头** |
| R3 | 界面改完只在 Windows 验证 | UI 代码跨平台，本项目回归基线包含 Linux 构建：每阶段在 Ubuntu621 里 `cmake --build` 一次（无 Qt 时跳过 st_ui 属正常） |

---

## 2. 目标与非目标

### 2.1 目标

1. 让 UI 从"课本式参数面板"变成"像一个真实的桌面软件"（外壳 + 信息层级 + 视觉规范），**外观以草图为准**。
2. 把不可见的安全流程可视化：**握手 7 步进度**、Eve 攻击的"动作 → 拦截关卡 → 结果"三段式面板。
3. 主界面瘦身：连接类配置收进"高级设置"，主界面只留角色 / 地址 / 端口 / 本端身份 + 操作按钮。
4. 日志升级为**按级别着色、可过滤、可导出**。
5. 全程**不改变协议、不改变线上字节格式、不破坏既有 16 个测试**。

### 2.2 非目标（本轮不做）

- 不改"拒绝即终止会话"的行为（决策 3）。
- 不做图像缩略图预览（决策 7）。
- 不做实时吞吐曲线 / 会话拓扑图。
- 不引入 `QtCharts`。
- **不重构线程模型**：`SessionWorker`（`QObject + std::thread` + 命令队列 + Qt 信号）保持不变。

---

## 3. Part A — 内核：`RejectGate`（纯增量）

### 3.1 动机

现在每个拒绝路径只递增一个粗粒度计数器（`session.h:70-78`）：`rejectedFormat` 把 Magic/版本、长度字段、SessionId、方向四件事混在一起，UI 无法说明"倒在哪一关"。

### 3.2 接口（`include/security/session.h`）

在 `ProtocolStats` 之后新增枚举与转换函数：

```cpp
/// 数据包被拒绝时，具体倒在哪一道校验（供 Eve 面板与报告精确显示）。
/// 纯进程内信息：不上网、不参与 MAC、不进 Packet。
enum class RejectGate {
    kNone,      ///< 未被拒绝
    kFrame,     ///< ① TCP 帧层读取失败（长度字段非法 / 连接中断）
    kFormat,    ///< ② 数据包解码失败（Magic / 版本 / 长度越界）
    kSessionId, ///< ③ SessionId 不属于本会话
    kDirection, ///< ④ 方向不符（疑似反射）
    kType,      ///< ⑤ 类型不允许（非业务包 / 发送类型非法）
    kReplay,    ///< ⑥ 序号重放
    kMac,       ///< ⑦ CMAC 校验失败
    kState      ///< ⑧ 状态机不允许
};

const char* rejectGateToString(RejectGate gate);   // 中文短名，供界面直接显示
```

`SecureSession` 诊断区新增访问器：

```cpp
RejectGate lastRejectGate() const { return lastRejectGate_; }
void resetLastRejectGate() { lastRejectGate_ = RejectGate::kNone; }
```

### 3.3 改动点（`src/security/session.cpp`，**行号以实施当时为准**）

原则：**每处 `++stats_.rejectedXxx;` 旁边紧跟一行 `lastRejectGate_ = ...;`**；现有计数器、日志、返回值一个都不动。

| 关卡 | 触发点 | 现有代码（10-09 行号） |
| --- | --- | --- |
| ① `kFrame` | `receiveFrame()` 失败 | `recvPacket()` 内 |
| ② `kFormat` | `Packet::decode()` 失败 | L177 |
| ③ `kSessionId` | SessionId 不匹配 | L181 |
| ④ `kDirection` | 方向不符 | L185 |
| ⑧ `kState` | `sendMessage()` 会话未建立 | L582 |
| ⑤ `kType` | `sendMessage()` 类型非法 | L587 |
| ⑧ `kState` | `receiveMessage()` 会话未建立 | L624 |
| ⑤ `kType` | `receiveMessage()` 收到非业务包 | L634 |
| ⑥ `kReplay` | 防重放拦截 | L643 |
| ⑦ `kMac` | CMAC 校验失败 | L649 |
| ⑧ `kState` | `tryReceiveMessage()` 会话未建立 | L671 |
| ⑧ `kState` | `protocolViolation()`（**原稿遗漏，本次补上**） | L728 |

**置空**：`recvPacket()` 与 `receiveMessage()` 入口各置 `kNone`（保证"成功接收 → 读到的一定是 kNone"）。

### 3.4 兼容性

- 线上字节零变化；`ProtocolStats` 字段、返回值、日志文本不变；
- 分层方向不变（仍在 `security/` 内）；
- 删掉 `lastRejectGate_` 也能编译（只是 UI 拿不到精确关卡）。

### 3.5 测试（新增 `tests/unit/test_reject_gate.cpp`）

| 用例 | 断言 |
| --- | --- |
| 篡改包（body 改 1 字节 + `sequence+1`） | `lastRejectGate() == kMac` |
| 原样重放包 | `== kReplay` |
| 改 SessionId | `== kSessionId` |
| **连续两次不同拒绝**（本次修订新增） | 第二次读到的是**第二个**关卡（验证置空时机，防陈旧值） |

> 说明：篡改演示故意 `sequence+1`，所以不会先被防重放拦下，才会走到 MAC 关——测试注释要写清。

---

## 4. Part B — 攻击回执 `ATTACK-REPORT`

### 4.1 时序

```text
Alice(攻击端)                          Bob(受害端，UI 工作线程)
  │ sendRawWireForTesting(篡改包)          │
  ├───────────────────────────────────────▶│ tryReceiveMessage → receiveMessage
  │                                        │  → kMac 失败：fail() 只设 lastError（state_ 仍 kEstablished）
  │  ◀──── ATTACK-REPORT: CMAC 校验失败 ────┤  ★ 终止前回执（sendMessage 允许）
  │                                        │ break → session.closeConnection()
  │ messageReceived("DATA", "ATTACK-…")     │
  │ 面板：第⑦关 + 原因 + 写 attack_log      │
```

### 4.2 落点（`apps/ui/session_worker.cpp` 的 `kClosed` 分支）

```cpp
if (status == SecureSession::ReceiveStatus::kClosed) {
    const RejectGate gate = session.lastRejectGate();
    if (isAttackReject(gate) && session.state() == SessionState::kEstablished) {
        std::string report = std::string("ATTACK-REPORT: ") + rejectGateToString(gate) +
                             " | seq=" + std::to_string(session.receiveSequence()) +
                             " | " + session.lastError();
        // 尽力而为：回执失败只记 DEBUG，不弹错、不刷 ERROR（本次修订新增约束）
        if (!session.sendMessage(MessageType::kData, stringToBytes(report))) {
            ST_LOG_DEBUG(kWorkerLogModule, "ATTACK-REPORT 发送失败（对端可能已关闭）");
        }
        emit attackDetected(QString::fromUtf8(rejectGateToString(gate)),
                            QString::fromStdString(session.lastError()));
    }
    emit sessionStopped(...);
    stoppedNotified = true;
    break;
}
```

`isAttackReject()`：只对 `kFormat / kSessionId / kDirection / kType / kReplay / kMac` 返回 true；
`kNone / kFrame / kState` 属非攻击性关闭，不回执（回执也发不出去）。

### 4.3 白名单（**必须同时改**，否则重演 3.4 万条死循环）

`include/common/demo_reply.h` 的 `shouldAutoReply()` 前缀表新增：

```cpp
"ATTACK-REPORT",   // Eve 攻击演示：受害端的拒绝回执，不再自动回复
```

### 4.4 攻击日志（决策 9）

新增**独立**日志 `experiment_data/attack_log.txt`（不复用访问控制审计，避免语义混淆）：

```text
2026-10-09 10:20:31  ATTACK  tamper  gate=kMac      reason=CMAC verification failed: …
2026-10-09 10:21:02  ATTACK  replay  gate=kReplay   reason=Replay Attack Detected: …
```

由工作线程在 `attackDetected` 时追加一行（复用 `ensureDirectory` + `openOutputFile`，注意中文路径支持）。

### 4.5 边界

| 场景 | 行为 |
| --- | --- |
| 正常 `kClose` | `gate == kNone` → 不回执、不写攻击日志 |
| socket 断开 / 超时 | `gate == kFrame` → 不回执 |
| 会话未建立时的状态错误 | `kState` → 不回执 |
| 连续两次攻击 | 第一次拒绝即终止会话（决策 3）；第二次攻击端只能看到"对端已关闭"，面板需如实提示"需重新建立会话" |
| 攻击端是命令行 alice | 回执被当普通消息打印；无副作用 |

---

## 5. Part C — UI 换皮（依草图）

### 5.1 视觉规范（草图 → Qt 取值）

草图用 CSS 变量，下表把变量映射成具体色值（QSS 直接用右列）：

| 草图变量 | 用途 | 取值 |
| --- | --- | --- |
| `--color-background-primary` | 窗口 / 卡片底色 | `#FFFFFF` |
| `--color-background-secondary` | 页面底色、次级块、对端气泡 | `#F5F6F8` |
| `--color-border-tertiary` | 卡片 / 输入框描边 | `#E3E5E8` |
| `--color-text-primary` | 正文 | `#1F2328` |
| `--color-text-secondary` | 次要文字、说明 | `#59636E` |
| `--color-text-tertiary` | 占位符、最弱信息 | `#8B949E` |
| `--color-text-success` | 已建立、成功、进度条 | `#12A150` |
| `--color-text-danger` | 拒绝、篡改、错误 | `#D1242F` |
| `--color-background-info` / `--color-text-info` | 主按钮、本端消息气泡 | `#E7F0FF` / `#1F6FEB` |
| 警告 | 握手中、提示 | `#D29922` / `#FFF6E5` |

- 圆角：控件 6–8px，卡片 8px。
- 字体：`"Microsoft YaHei UI", "Noto Sans CJK SC", "PingFang SC", sans-serif`。
- **语义色集中在一处**（`app_theme.h` + `style.qss`），不再出现散落的硬编码色值。

### 5.2 布局（照草图）

```text
┌ QMenuBar（文件 / 会话 / 帮助）────────────────────────────────────  ┐
├ 顶部标题条：SecureTransfer                     ● 安全会话已建立     │
├ 工具条：[连接][断开] │ [发送文件][发送图像][查询身份][审计日志]  … [高级设置] │
├──────────────┬──────────────────────────────┬────────────────────┤
│ 左 180px      │ 中（自适应）                  │ 右 142–200px        │
│ ・会话状态     │ ・短消息（气泡 + 输入 + 发送）  │ ・统计 2×2 数字块    │
│ ・握手进度(7)  │ ・文件 / 图像传输（进度 + CRC） │ ・运行日志（分级+过滤）│
│ ・连接设置     │ ・Eve 攻击演示（三段式 + 关卡） │                     │
├──────────────┴──────────────────────────────┴────────────────────┤
│ 状态栏：端口 9000 │ AES-128-CTR + CMAC │ 会话时长 00:12 │    就绪   │
└──────────────────────────────────────────────────────────────────┘
```

**与原稿的偏差（本次修订记录）**：草图右栏只有 142px，放不下"Eve 面板的关卡流水线"，
因此 **Eve 面板放中栏**（消息、文件传输之下）；右栏保持草图的"统计块 + 日志"。
主体三栏用 `QSplitter`（可拖拽），左栏内保留 `QScrollArea`（现有加固机制）。

### 5.3 主界面项 vs 高级设置（修正 C5）

| 位置 | 项 |
| --- | --- |
| 工具条 | 角色（下拉）、对端地址、端口、[连接] [断开] |
| 左栏"连接设置"卡片 | **本端身份**（访问控制演示要频繁切换） |
| 高级设置（对话框） | **对端身份**、密钥配置、访问策略、接收目录、审计日志 |

> 原稿把"本端身份"漏了：它放在主界面最顺手，而"对端身份"属于建链参数，与四个路径项一起收纳。

### 5.4 握手 7 步进度（修正 C2）

**内核侧**（`SessionConfig` 新增可选钩子，照 `onListening` 风格）：

```cpp
/// 握手每推进一步时回调一次（step ∈ 1..7；步骤名由 UI 侧映射，内核不发中文文案）。
std::function<void(int step)> onHandshakeStep;
```

触发点：在 `session.cpp` 现有的 `logHandshakeStep(...)` 调用点旁各触发一次，**按角色映射**：

| 角色 | 调用点（10-09 行号） | step |
| --- | --- | --- |
| 客户端 | L224 / L255 / L265 / L275 / L304 / L313 / L330 | 1 / 2 / 3 / 4 / 5 / 6 / 7 |
| 服务端 | L364 / L378 / L395 / **L430（④⑤ 合并）** / L447 / L456 | 1 / 2 / 3 / **4 与 5 各一次** / 6 / 7 |

- 服务端那一行**连续触发 step=4 与 step=5**，保持"7 步"语义一致；
- 步骤名由 **UI 侧静态表**给出：`HELLO / HELLO_ACK / AUTH / 密钥请求 / 密钥分发 / 密钥确认 / 确认应答`（与草图一致）；
- 回调发生在**工作线程**，必须经 Qt 信号跨线程回 GUI（`emit handshakeStep(...)`）。

### 5.5 日志分级 + 过滤（含接口规范化）

现状：级别混在文本里（`[ERROR]` / `[WARN]` / `✅` / `【访问控制拒绝】`），UI 只能猜字符串。

**本次修订**：worker → UI 增加规范化接口（旧 `logLine` 保留，避免破坏既有连接）：

```cpp
enum class LogLevel { kInfo, kWarn, kError, kSuccess };
void logEntry(int level, const QString& text);   // 新增信号
```

UI 侧：`QVector<LogEntry>` 缓存（level + text），按级别 / 关键字过滤后重绘；
着色用 `QTextCursor::setCharFormat()`（`QPlainTextEdit` 支持字符格式，无需换控件）；
新增"级别下拉 + 关键字框 + 导出日志"。

### 5.6 新建 / 改动文件

| 文件 | 动作 |
| --- | --- |
| `apps/ui/style.qss` | 新增（按 §5.1 取值） |
| `apps/ui/app_theme.h` | 新增（语义色 + 日志级别 + QSS 加载） |
| `apps/ui/handshake_bar.{h,cpp}` | 新增（7 步进度） |
| `apps/ui/attack_panel.{h,cpp}` | 新增（三段式 + 8 关流水线） |
| `apps/ui/advanced_settings_dialog.{h,cpp}` | 新增（高级设置） |
| `apps/ui/main_window.{h,cpp}` | 重写 `buildUi()`；新增分级日志 / 过滤 / 导出、标题条、工具条、状态栏 |
| `apps/ui/main.cpp` | 小改：QSS（**在建控件前**）、高 DPI（**在 QApplication 前**）、窗口图标 |
| `apps/ui/session_worker.{h,cpp}` | 新增 `handshakeStep` / `attackDetected` / `logEntry` 信号 + 回执 + 攻击日志 |
| `include/security/session.h`、`src/security/session.cpp` | Part A：`RejectGate` + `onHandshakeStep` |
| `include/common/demo_reply.h` | Part B：白名单 + `ATTACK-REPORT` |
| `CMakeLists.txt` | `AUTORCC`（仅当引入 qrc）、`Qt5::Svg` 可选 |
| `tests/unit/test_reject_gate.cpp` | 新增（4 条断言） |
| `docs/protocol.md` | 决策 10：§6.3 对齐实现 |
| `docs/ui.md` | 补新界面说明与截图；同步 §11 加固说明 |

---

## 6. 分期计划、工作量与验收

| 阶段 | 内容 | 验收 | 估计 |
| --- | --- | --- | --- |
| **P1** | Part A `RejectGate` + 测试 | `ctest` 16/16 且新增 4 条断言通过；无协议/字节变化 | 0.5 天 |
| **P2** | Part B 回执 + 白名单 + 攻击日志 | 双窗口演示出现 `ATTACK-REPORT: …`；**无死循环**；`attack_log.txt` 有记录；回执失败不报错 | 0.5 天 |
| **P3** | 主题（QSS）+ 高 DPI + 窗口图标 + 标题条/工具条/状态栏 | 构建通过；`--print-geometry` 全控件 height ≥ sizeHint | 1 天 |
| **P4** | 三栏重构 + 高级设置对话框 + 左栏滚动 | 小窗口不出现"文字只显示一半"；主界面只剩 §5.3 的项 | 1 天 |
| **P5** | 握手 7 步进度 + 日志分级/过滤/导出 + Eve 面板 | 7 步实时点亮；日志可过滤可导出；面板显示"关卡 + 原因 + 会话已终止" | 1.5 天 |
| **P6** | 打包 `dist/` + 文档同步 | `scripts/package_windows.sh` 重跑通过；`docs/ui.md` 更新并补截图 | 0.5 天 |

**合计约 4.5~5 天**。回归红线：**P1/P2 之后 `ctest` 必须仍为 16/16**；
P3/P4/P5 每阶段都要跑 `--print-geometry` 与 Linux 侧构建（R3）。

### 6.1 实施结果（2026-10-09 当天完成）

| 阶段 | 状态 | 实测证据 |
| --- | --- | --- |
| P1 `RejectGate` + 测试 | ✅ 完成 | `tests/unit/test_reject_gate.cpp` 4 条断言通过；`ctest` **17/17** |
| P2 攻击回执 + 白名单 + 攻击日志 | ✅ 完成 | 篡改 → 对端判定 ⑦ CMAC；重放 → ⑥ 防重放；`attack_log.txt` 落盘；**无死循环** |
| P3 主题 + 高 DPI + 图标 + 外壳 | ✅ 完成 | `app_theme.h` 内嵌 QSS；`main.cpp` 在 QApplication 前设高 DPI、在建控件前应用主题 |
| P4 三栏 + 高级设置 + 左栏滚动 | ✅ 完成 | `--print-geometry`（默认 1180×720 / 最小 1040×660）：控件高度全部 ≥ sizeHint；左栏 `hScroll=0` |
| P5 握手 7 步 + 日志分级/过滤/导出 + Eve 面板 | ✅ 完成 | 双窗口实跑，7 步全绿；日志按级别着色、可过滤、可导出；面板显示"动作 → 关卡 → 结果" |
| P6 打包 `dist/` + 文档同步 | 🔶 文档已同步；`dist/` 待重打包 | `docs/ui.md` §12、`docs/protocol.md` §6.3、`Part2_transfer.md` §29 已更新 |

**与计划的 3 处偏差**（详见 `docs/ui.md` §12.4）：
1. 连接参数留在左栏"连接设置"卡片（照草图），没放进工具条——实机逻辑分辨率只有 1080×720，
   塞进工具条会把按钮挤出窗口；
2. 日志分级改为 **UI 侧集中解析前缀**（`classifyLogLevel()`），未新增 worker 的结构化
   `logEntry(level, text)` 信号（行为等价、改动面更小）；
3. 原计划的 `style.qss` / `handshake_bar.{h,cpp}` / `attack_panel.{h,cpp}` /
   `advanced_settings_dialog.{h,cpp}` 四个独立文件**合并进 `main_window.cpp`**——
   这些部件都只被主窗口使用，独立成文件会增加 AUTOMOC 与包含关系，
   但换来的可读性有限（合计不到 300 行）。

---

## 7. 风险清单（实施时逐条对照）

1. **QSS × sizeHint（R1）**：QSS 必须在建控件之前应用；否则"文字显示一半"复发。
2. **图标依赖（R2）**：优先 `QStyle::standardIcon()`；用 SVG 则 `Qt5::Svg` 设为可选并有回退。
3. **`QComboBox`/`QSpinBox` 上 QSS 后子控件消失**：必须补 `::drop-down` / `::down-arrow` / `::up-button`。
4. **不要推倒 10-06 的布局加固**：`minHeight = sizeHint()`、文本区 `QSizePolicy::Ignored`、`--print-geometry` 三样保留。
5. **高 DPI**：`Qt::AA_EnableHighDpiScaling` / `AA_UseHighDpiPixmaps` 必须在 `QApplication` 之前设置。
6. **回执不得触发自动回复**：`ATTACK-REPORT` 必须进白名单。
7. **打包**：改 UI 就要重跑 `windeployqt`（`scripts/package_windows.sh` 已含）。
8. **Qt 可选性**：`find_package(Qt5 … QUIET)` 不能改成 REQUIRED。
9. **行号漂移**：本文件行号是 10-09 快照，实施每阶段前重新定位。
10. **`-Wall -Wextra` 零告警**：新增代码保持 0 警告。

---

## 8. 开放项（已按本次修订定案）

| # | 问题 | 结论 |
| --- | --- | --- |
| O1 | 握手步骤条是否加内核钩子 | **加**（决策 8）：按角色触发 7 步，回调只传 step 号 |
| O2 | 回执是否留档 | **写，但单独 `experiment_data/attack_log.txt`**（决策 9） |
| O3 | 图像缩略图预览 | 本轮不做；后续如需，先做"接收端缩略图" |
| O4 | 修 `docs/protocol.md` §6.3 措辞 | **改文档对齐实现**（决策 10） |

---

## 附：本计划的边界

- 内核两处（`RejectGate`、`onHandshakeStep`）都是**纯增量**：不改数据包格式、不改现有测试断言、不改分层依赖。
- 协议层 / 网络层 / 算法层（第一部分）**零改动**。
- 界面视觉取值**全部来自 `docs/SecureTransfer_UI改造草图.html`**；草图若更新，以草图为最终依据。
