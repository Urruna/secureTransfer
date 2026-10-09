## Windows 图形界面发布包（课程项目《安全的信息传输套件》）

下载 `securityTransfer-ui-win64.zip`（约 32 MB），解压后即可运行，
**无需安装 Qt / MSYS2 / 编译器**。

> **2026-10-09 更新（界面改版）**：界面按 `docs/SecureTransfer_UI改造草图.html` 重做——
> 标题条 / 工具条 / 三栏 / 状态栏，浅色扁平主题；新增**握手 7 步进度**、
> **Eve 攻击面板（动作 → 拦截关卡 → 结果）**、**统计数字块**、
> **日志分级着色 + 过滤 + 导出**、**高级设置对话框**（收纳对端身份与全部路径项）。
> 攻击演示现在能看到对端"倒在哪一关"（内核 `RejectGate` + `ATTACK-REPORT` 回执）。
> 详见 `docs/ui.md` §12 与 `Part2_transfer.md` §29。

### 快速开始

1. 解压（建议放在纯英文路径，例如 `D:\securityTransfer`）；
2. 把 `configs\keys.conf.example` 复制成 `configs\keys.conf`，填写 K_master
   （32 位十六进制 = 16 字节）—— **与你要通信的另一端必须是同一把 K_master**；
3. 双击 `run_ui.bat` 启动图形界面（控制台窗口会同步显示日志）；
   也可以用 `run_bob.bat` / `run_alice.bat` 做命令行演示。

### 包含内容

`alice.exe` / `bob.exe` / `st_ui.exe`；Qt 5.15.19 及全部依赖 DLL 与平台插件；
配置模板；实验数据；双击即用的启动脚本。

### 校验

* 大小：约 32 MB（解压后约 75 MB）；
* SHA-256：**以 Release 附件里的 `sha256.txt` 为准**（每次构建都会重新生成，
  硬编码在文档里容易过期）；
* 校验方式：`certutil -hashfile securityTransfer-ui-win64.zip SHA256`（Windows）
  或 `sha256sum securityTransfer-ui-win64.zip`（Linux）。

### 说明

* 只包含 `keys.conf` 的**模板**，不含任何真实密钥；
* 首次运行若被 SmartScreen 拦截，选择“更多信息 → 仍要运行”；
* 仓库为私有仓库，下载前需要用有权限的 GitHub 账号登录；
* 功能说明、测试与攻击演示证据见 README 与 `Part2_transfer.md`；
* 这个包由 `.github/workflows/windows-ui.yml` 在**发布 Release 时自动构建并挂载**
  （同时附上 `sha256.txt`）：维护者只需要打 tag、发 Release，其余交给 CI。
