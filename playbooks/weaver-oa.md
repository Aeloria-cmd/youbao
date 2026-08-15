# 泛微 OA（Weaver）专项手册

适用：题目描述或指纹出现 泛微 / Weaver / e-cology / e-office / e-mobile / e-bridge / OA 系统。

## 1. 指纹与产品识别

- e-cology（ ecology9 ）：路径含 `/weaver/`、`/wui/`，登录页 `/login.jsp`，JS 引 `/ ecology/`，响应头/cookie 常见 `ecology_JSessionId`、`SecureLanToken`。
- e-office：路径含 `/general/`、`/inc/`，风格较老。
- e-mobile / emobile：路径含 `/client.do`、`/api/`。
- 版本探测：`/weaver/upgrade/getVersionInfo`、页面版权脚注、JS/CSS 路径里的版本号。

## 2. 已知漏洞面（按类型记，不按 CVE 背）

泛微各产品线历史上反复出以下几类洞，按指纹逐一验证存在性再深入：

- **BeanShell 远程代码执行（e-cology 经典）**：`POST /weaver/bsh.servlet.BshServlet`，参数 `bsh.script=...`。存在即 RCE。
- **前台 SQL 注入**：e-cology 多个接口历史上可注（workflow、hrm、message 相关 jsp/servlet），参数级尝试报错/布尔/time-based；有 sqlmap 直接上。
- **文件上传**：e-office `/general/index/UploadFile.php` 等上传点，配合后缀绕过（参考 multistage.md 上传清单）。
- **未授权访问**：部分版本接口（用户列表 `/messager/users`、移动端接口）可未授权拉取用户/组织架构——**用户名单是凭证喷洒的原料**。
- **任意文件读取/下载**：filedownload、pic 等参数的路径穿越。

打真实产品就用现成 PoC 思路；sqlmap/nuclei（templates 里有 weaver 相关模板）优先于手写。

## 3. 靶场里的"类泛微 OA"（自研模拟应用）

靶场常把 OA 做成自研登录框（Flask/PHP + 验证码 + MariaDB），考的不是 CVE 而是**凭证链**：

1. **默认/弱凭证**：sysadmin、admin、test、工号（如 001/1001）+ 常见弱口令（词表 `/opt/wordlists/`）。
2. **验证码处置**：按 multistage.md 的验证码规则——先测绕过（复用/缺失参数/响应泄露），10 分钟不通就换路，不自建 OCR。
3. **凭证在配置里**：这类应用的 DB 凭证写在配置文件（`config.php`、`config.py`、`.env`、WEB-INF 下）。从 web 容器的 LFI/webshell 翻配置 → 拿 DB 凭证 → 连内网 DB → 用户表里有 OA 账号密码哈希（弱哈希直接撞，或改库里的密码哈希为自己已知的）。
4. **Flask session 伪造**：拿到 SECRET_KEY（配置/env）后用 flask-unsign 签一个 admin session，直接进后台。
5. OA 后台通常是下一个跳板：找文件管理/上传/计划任务/接口配置 → RCE 或读文件 → 摸 SSH 凭证（题目提示"管理员后台服务器开放 SSH"时，凭证多半就在 OA 库或配置里）。

## 4. 记住

- OA 的价值不在 OA 本身，在它身后的**内网凭证与拓扑**。每拿一个东西就问：它能不能开下一扇门（DB → 用户表 → SSH → 核心系统）。
- 所有凭证/主机立刻写 journal 的 `access` / `internal_hosts`。
