# 访问控制（课程要求 7 的组成部分）

> 课程要求 7：设计并实现一套安全协议，包含加密、认证、密钥交换和**访问控制**等功能，
> 使 Alice 和 Bob 交互信息时，上述安全操作尽量对用户透明。
>
> 加密 / 认证 / 密钥交换已在第二部分完成；本文说明**访问控制**部分。

---

## 1. 结论摘要

| 项目 | 实现 |
| --- | --- |
| 模型 | 身份 → 角色（Role）→ 权限（Permission），策略写在 `configs/access_policy.conf` |
| 判定位置 | **服务端（Bob）权威判定**；客户端只做本地提示，不参与决策 |
| 操作粒度 | `send_message` / `send_file` / `send_image` / `view_log` / `manage_users` |
| 默认策略 | 未登记身份落到 `defaultRole`（默认 `guest`），角色未定义权限时**无权限**（默认拒绝） |
| 拒绝后的行为 | 拒绝**该操作**但**保持会话可用**（与"篡改/重放导致断连"区分开） |
| 审计 | 每次允许/拒绝都写审计日志（时间、身份、角色、操作、结果），管理员可查看 |
| 用户透明性 | 用户只需正常发消息/文件；权限判定在后台完成，被拒绝时给出明确原因 |

## 2. 为什么需要它（与认证的区别）

```text
身份认证 Authentication ：你是谁？        → 握手时用 K_master 验证身份（已完成）
访问控制 Authorization ：你可以做什么？  → 本文档
```

认证只保证"对方确实是它声称的身份"，不限制它做什么。例如访客 Mallory 即使能完成认证，
也不应该能往 Bob 的磁盘写文件。访问控制就是在**已认证的会话内**再限制操作。

## 3. 策略配置（改策略不用改代码）

`configs/access_policy.conf`：

```ini
[default]
role = guest                 # 未登记身份使用的最小权限角色

[identity]                   # 身份 → 角色
alice = admin
bob = admin
eve = user
mallory = guest

[role:admin]
permissions = send_message, send_file, send_image, view_log, manage_users

[role:user]
permissions = send_message, send_file, send_image

[role:guest]
permissions = send_message
```

* 增加一个用户只需在 `[identity]` 里加一行；
* 权限名拼错、默认角色没有定义权限、缺少身份段等都会**拒绝加载**（保证不会"静默放开"）；
* 角色未定义权限时按"无权限"处理（最小权限原则）。

## 4. 判定流程

```text
收到一条业务消息
   │
   ├─ 是传输消息吗（FILE_*/IMAGE/DATA）？不是（CLOSE/ERROR）→ 不做访问控制
   │
   ├─ 取身份：使用握手阶段**认证过的对端标识**（不是消息里自称的身份）
   │
   ├─ 查角色：identity → role（未登记 → defaultRole）
   │
   ├─ 查权限：role → permission set
   │
   ├─ 允许 → 写审计（ALLOW）→ 正常执行（落盘 / 分发上层）
   │
   └─ 拒绝 → 写审计（DENY）→ 回 "ACCESS DENIED: ..." → **不执行** → 会话保持可用
```

几个关键设计点：

1. **服务端权威**：客户端可以加载同一份策略做"本地提示"，但真正的判定在服务端；
   演示时故意让本地提示与最终结果同时出现，说明"客户端不可信"。
2. **拒绝不等于断连**：收到一个越权请求只拒绝该操作并计数；
   而篡改（MAC 失败）/重放属于协议级违规，仍然会终止会话——两者处理策略不同，报告里要讲清楚。
3. **被拒绝的传输必须整体丢弃**：如果 `FILE_START` 被拒绝，后续的 `FILE_CHUNK`
   不能再落盘（否则等于"拒绝了却还是写了文件"）。实现上用一个 `droppingTransfer`
   状态，把该次传输剩下的块与结束包静默丢弃。
4. **身份来源**：用握手阶段验证过的对端身份，而不是消息里携带的名字，
   否则任何人都可以在消息里写"我是 alice"。

## 5. 用户透明性（要求 7 的"对用户透明"）

正常使用时用户不需要知道策略存在：
`./alice --file test_file_1MB.bin` 就完成"加密 + 完整性 + 防重放 + 权限检查"。
只有被拒绝时才会收到一行明确说明（例如 `ACCESS DENIED: send_file 需要更高权限（当前角色 guest）`），
并且可以随时用两个内置命令查询自己的身份与权限：

| 命令 | 作用 | 权限要求 |
| --- | --- | --- |
| `./alice --whoami` | 向服务端查询"我的角色 + 权限清单" | 只需 `send_message` |
| `./alice --view-log` | 查看服务端审计日志（最近几条 + 允许/拒绝计数） | 需要 `view_log`（仅管理员） |

这两个命令本身也是数据消息，同样被加密与 MAC 保护，无法被伪造。

## 6. 实测结果（Ubuntu 20.04 虚拟机）

### 场景 1：管理员 Alice（角色 admin）

```text
访问策略      : ../configs/access_policy.conf（裁决方：服务端）
本端角色      : admin [send_message, send_file, send_image, view_log, manage_users]
对端角色      : admin [send_message, send_file, send_image, view_log, manage_users]

---------- 查询自己的角色与权限（CMD WHOAMI）----------
  服务端返回  : ROLE admin : send_message, send_file, send_image, view_log, manage_users
---------- 查看服务端审计日志（CMD VIEW_LOG）----------
  服务端返回  : AUDIT LOG (最近 7 条, 允许 7 次 / 拒绝 0 次)
  文件名      : test_file_64KB.bin   对端确认: FILE OK ... CRC32=0x1f50c2e7
  文件名      : test_image_256x256.png 对端确认: FILE OK ... CRC32=0xe30eac16
统计: sent=15 recv=11 reject(format/replay/mac/state)=0/0/0/0
```

### 场景 2：访客 Mallory（角色 guest）

```text
访问策略(本地提示): ../configs/access_policy.conf  本端角色: guest [send_message]
  服务端返回  : ROLE guest : send_message
  服务端返回  : ACCESS DENIED: view_log 仅管理员可用（当前角色 guest）
  [本地提示] 角色 guest 缺少权限 send_file，服务端预计会拒绝
  对端确认    : ACCESS DENIED: send_file 需要更高权限（当前角色 guest）
  [本地提示] 角色 guest 缺少权限 send_image，服务端预计会拒绝
  对端确认    : ACCESS DENIED: send_image 需要更高权限（当前角色 guest）

服务端（Bob）判定：
【访问控制拒绝】mallory 尝试 view_log
【访问控制拒绝】身份 mallory（角色 guest）尝试 send_file —— 已拒绝，未执行
【访问控制拒绝】身份 mallory（角色 guest）尝试 send_image —— 已拒绝，未执行
共接收 4 条加密消息，0 个文件/图像；访问控制拒绝 3 次（允许 6 次 / 拒绝 3 次）
```

要点：

* 访客的 4 条**短消息全部正常**（角色 guest 有 `send_message`）→ 证明拒绝是**按操作粒度**的；
* 文件与图像被拒绝，**磁盘上没有产生任何访客文件**（集成测试里用"文件不存在"断言）；
* 会话**没有中断**（这与篡改/重放导致断连不同）。

### 审计日志（`experiment_data/access_log.txt` 节选）

```text
2026-09-27 18:37:10 ALLOW alice(admin) send_message
2026-09-27 18:37:10 ALLOW alice(admin) view_log
2026-09-27 18:37:10 ALLOW alice(admin) send_file
2026-09-27 18:37:10 ALLOW alice(admin) send_image
2026-09-27 18:37:11 ALLOW mallory(guest) send_message
2026-09-27 18:37:11 DENY  mallory(guest) view_log 尝试查看审计日志
2026-09-27 18:37:11 DENY  mallory(guest) send_file 服务端判定无权限
2026-09-27 18:37:11 DENY  mallory(guest) send_image 服务端判定无权限
```

## 7. 代码与接口

| 文件 | 作用 |
| --- | --- |
| `include/security/access_control.h`、`src/security/access_control.cpp` | `Operation` / `PermissionSet` / `Policy` / `AccessController`（加载策略、判定、审计） |
| `configs/access_policy.conf` | 角色、权限、身份映射 |
| `apps/bob` | `--policy` / `--access-log` / `--id` / `--peer`；服务端权威判定 + 命令处理 |
| `apps/alice` | `--id` / `--policy`（本地提示）/ `--whoami` / `--view-log` |
| `tests/unit/test_access_control.cpp`（8 例） | 策略解析、判定矩阵、默认拒绝、非法策略拒绝、消息类型映射、审计记录与写文件 |
| `tests/integration/test_access_control.cpp` | 端到端：管理员发文件成功落盘；访客发文件被拒绝且**不落盘**、会话继续可用、审计里同时有 ALLOW 与 DENY |

```cpp
access::AccessController access;
std::string error, warning;
access.loadFile("configs/access_policy.conf", error, warning);
access.setAuditLogFile("experiment_data/access_log.txt", error);

if (!access.isAllowed(peerIdentity, access::Operation::kSendFile)) {
    access.record(peerIdentity, access::Operation::kSendFile, false, "服务端判定无权限");
    // 拒绝该操作，但保持会话
}
```

## 8. 局限与诚实说明（写进报告更稳妥）

1. **本实验里所有身份共用同一把 `K_master`**（`configs/keys.conf`），
   因此"身份"的密码学强度等同于"知道 K_master"：
   能通过握手的人可以声称自己是 alice 或 mallory（服务端会用 `--peer` 校验期望身份）。
   真实系统应给每个身份配置**独立凭证**（独立密钥或证书），本模块的判定逻辑不变；
2. 服务端一次只接受一个对端身份（`SessionConfig::peerId`，可用 `--peer` 指定），
   这是实验环境下的简化；多用户场景应改为"服务端维护身份白名单 + 多连接"；
3. 审计日志是本地追加文本文件，没有做防篡改保护（真实系统应写只追加的日志服务或签名日志）；
4. 权限粒度到"操作类型"，没有做"按文件/按目录"的细粒度授权（如需可扩展 `Operation` 与策略格式）；
5. `manage_users` 目前只在策略里定义、未提供运行时修改用户的命令
   （避免演示中把策略改坏；如需可以加一个管理员命令）。
