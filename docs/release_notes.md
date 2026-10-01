## Windows 图形界面发布包（课程项目《安全的信息传输套件》）

下载 `securityTransfer-ui-win64.zip`（32.18 MB），解压后即可运行，
**无需安装 Qt / MSYS2 / 编译器**。

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

* 大小：`32.18 MB`
* SHA-256：`9797A04B7AB9CC4C507C00AD6967D40C0BE487D4F5110B23BE80DB6F3984C10A`

### 说明

* 只包含 `keys.conf` 的**模板**，不含任何真实密钥；
* 首次运行若被 SmartScreen 拦截，选择“更多信息 → 仍要运行”；
* 仓库为私有仓库，下载前需要用有权限的 GitHub 账号登录；
* 功能说明、测试与攻击演示证据见 README 与 `Part2_transfer.md`；
* 这个包由 `.github/workflows/windows-ui.yml` 在发布 Release 时自动生成并挂载，
  下次发版时本文件会被 CI 用新的校验值覆盖（见工作流）。
