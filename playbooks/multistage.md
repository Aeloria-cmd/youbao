# 多阶段渗透手册（多 flag / 内网横向）

适用：flag_count > 1，或描述含"内网 / 横向 / 跳板 / 多层防线 / 核心业务系统"。
这类题是一条链：**入口 → 立足点 → 内网侦察 → 内网应用 → 核心数据**。每个阶段一个 flag，分值沿链递增——只拿链头 flag 等于白干大半。

## 铁律

1. **状态沉淀优先一切**：拿到 webshell/凭证/会话 → 立刻写 journal 的 `access`；发现内网主机/网段 → 立刻写 `internal_hosts`。context 会被压缩，没写进 journal 的等于没发生过。
2. **时间盒**：同一子目标连续 3 轮无进展必须换向量；爆破类 1000 发无命中就换字典或换路；验证码超过 20 分钟没搞定就放弃该入口（见下）。
3. **环境纪律**：只打 `[state]` 里 `env_addrs` 的地址。网段里其他主机是别的题或僵尸容器。目标失联先 `benchmark_api list` 刷新地址。绝不"重置/恢复"任何环境。
4. **链式思维**：每个阶段的产出是下一阶段的输入。recon 时就要收集内网线索（注释里的主机名/网段/人名/邮箱/工号、JS 里的内网 API、报错里的路径）。

## 阶段 1：外网入口

- 标准 recon：首页、robots.txt、HTML 注释、JS（端点/硬编码密钥/测试账号）、备份文件（.bak/.zip/.sql，注意区分 catch-all 假 200——按响应大小过滤）。
- **新闻/公告/关于我们**：常藏内网迁移通知、系统名称、员工姓名（拼凭证用）。
- 有 LFI 就不止步于读文件：
  - 读源码审计隐藏端点（注意 `include()` 会**执行** PHP 而非显示源码——读源码要 php://filter；被禁就走日志投毒 / session 文件包含 / /proc/self/fd 把 LFI 升级成 RCE）。
  - 读配置文件拿 DB 凭证（config.php、.env、WEB-INF/ 下配置）。
  - flag 不一定在 `/challenge/flag.txt`：翻 env、home 目录、应用源码注释、DB 表。

## 阶段 2：立足点（webshell）

- 上传绕过清单（按序试）：`.phtml`/`.phar`/`.php5`/大小写（`.pHp`)/双扩展（`.php.jpg`)/`.htaccess`/`.user.ini`/MIME 绕过/内容头绕过（GIF89a)/条件竞争。
- 拿到 shell 后**固定 loot 清单**（一条命令打完）：
  `id; hostname; ip addr; cat /etc/hosts; cat /etc/resolv.conf; ip route; env | grep -iE 'pass|key|token|flag'; ls -la / /root /home 2>/dev/null; cat ~/.bash_history 2>/dev/null; find /var/www -name '*.php' -o -name '*.conf' 2>/dev/null | head -50`
- 全部发现写 journal：`access`（shell 地址+用法+权限）、`internal_hosts`（网卡/hosts 里的网段和主机）。

## 阶段 3：内网侦察

- 从立足点扫内网网段（/etc/hosts、ip addr 给出的网段，常见 172.x/10.x/192.168.x）：
  - bash: `for i in $(seq 1 254); do (echo > /dev/tcp/172.20.0.$i/80) 2>/dev/null && echo 172.20.0.$i:80; done`
  - **警惕"全端口开放"假象**：有的靶场网络层 accept 一切 TCP 连接，但无真实服务。必须以协议层响应为准（发 HTTP 请求看是否有 HTTP 响应体），否则全是噪音。
- 常见内网目标：OA/ERP（8080）、DB（3306/5432/1433）、Redis（6379）、SSH（22）、监控/管理（Go 风格 "404 page not found" 的多半是平台管理面，跳过）。

## 阶段 4：内网应用 → 核心数据

- **凭证来源优先级**：web 容器配置文件（DB/Redis 密码）> 源码注释/历史文件 > 默认凭证（admin/admin、admin/123456、工号+弱密码）> 喷洒。
- 内网应用常无鉴权或弱凭证：先试直接访问、默认口令，再考虑漏洞。
- DB 拿下后：`show databases; show tables;` 找 user/flag/config 相关表——核心 flag 常在业务表里。
- 需要 SSH 时：凭证通常在前面的阶段产出（OA 数据库、配置文件、history）；词表在 `/opt/wordlists/`（没有就先用内置小字典，别裸猜）。

## 验证码处置原则（血训）

验证码图片 OCR 与服务端校验**解耦**的实现真实存在（图片显示的字符永远不对）。规则：
1. 先测绕过：空 captcha 参数、参数缺失、复用旧 captcha（不刷新）、响应体/Header 泄露 captcha、绕过验证码直接打认证接口。
2. 上述 10 分钟内全失败 → **登录不是预期路径**，去找：默认凭证、未授权接口、源码泄露、已知产品漏洞（如泛微 OA 见 weaver-oa.md）。
3. 绝不自建 OCR 工程——那是无底洞，且多半不是考点。

## 网络环境常识

- 代理分层（envoy→nginx→PHP-FPM）会造成响应差异（HTTP/1.0 vs 1.1、chunked 与否），内容通常一致，别当漏洞追。
- 高频请求触发网关 503 限速是常态，降速或串行即可，不是打挂了靶机。
