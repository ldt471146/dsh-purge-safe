---
name: redteam-kit-host-notes
description: 红队技能包的【本机 Windows 适配说明】。ARTEX 跑在 Windows 上，而技能原文按 Kali/Linux 写。本文件把技能里点名的工具映射到本机真实路径与替代方案，并说明 redteam_* 工具在 ARTEX 里对应的落库工具。凡用到技能包里任一技能，先读本文件再执行。
---

# 红队技能包 · 本机（Windows）适配说明

技能正文按 **Kali/Linux** 写（`/usr/bin/…`、`<部署根>/data/tools/<工具>/<工具>` 无扩展名二进制）。
ARTEX 跑在 **Windows**，Shell 是 **PowerShell**（`powershell -NoProfile -NonInteractive -Command`）。
直接照抄技能里的命令会失败（Linux 变体是 ELF，Windows 跑不了）。执行前按本表换成 Windows 路径。

## 工具根目录

**`<部署根>\data\tools\`**（部署根 = `artex.exe` 所在目录，例如 `D:\ARTEX`）。

> 技能正文里的 `<部署根>/data/tools/xxx` 就指本机的 `<部署根>\data\tools\`（部署根 = artex.exe 所在目录）。
> Linux 变体是没有扩展名的 ELF，Windows 版带 `.exe` 后缀 —— 按下面映射表换成实际文件名再执行。
> `~/.dsh/data/tools/` 是**旧部署**的位置，本机没有这个目录，不要照它找。

## 一、工具路径映射（以此为准）

| 技能里的写法 | Windows 实际路径 | 说明 |
| --- | --- | --- |
| `toolkit/fscan/fscan` | `data\tools\fscan.exe` | 内网综合扫描 |
| `toolkit/gogo/gogo` | `data\tools\gogo.exe` | 内网测绘/指纹 |
| `toolkit/suo5/suo5-linux-amd64` | `data\tools\suo5` | HTTP 隧道（无 .exe 后缀） |
| `toolkit/chisel/chisel` | `data\tools\chisel.exe` | v1.12.0，服务端客户端同一二进制 |
| `toolkit/frp/frpc` | `data\tools\frpc.exe` | v0.62.1 |
| `toolkit/frp/frps` | `data\tools\frps.exe` | v0.62.1，本机也能当服务端 |
| `toolkit/subfinder/subfinder` | `data\tools\subfinder.exe` | 子域枚举 |
| `toolkit/dnsx/dnsx` | `data\tools\dnsx.exe` | DNS 解析 |
| `toolkit/naabu` | `data\tools\naabu.exe` | 端口扫描 |
| `toolkit/httpx/httpx` | `data\tools\httpx` | Web 存活/指纹（无 .exe 后缀） |
| `toolkit/nuclei` / `/usr/bin/nuclei` | `data\tools\nuclei.exe` | 模板化漏洞扫描 |
| `toolkit/gospider/gospider` | `data\tools\gospider.exe` | 爬虫 |
| `ffuf` | `data\tools\ffuf.exe` | 目录/参数爆破 |
| `katana` | `data\tools\katana` | Web 爬虫（无 .exe 后缀） |
| `toolkit/dirsearch/dirsearch` | `data\tools\dirsearch\dirsearch.py` | 需 `python313\python.exe` 跑，先 cd 到该目录 |
| `toolkit/oneforall` | `data\tools\oneforall\oneforall.py` | 同上 |
| `mimikatz` | `data\tools\mimikatz.exe` | 凭据提取 |
| `laZagne` | `data\tools\laZagne.exe` | 本机保存口令提取 |
| `ligolo` | `data\tools\ligolo-agent.exe` / `data\tools\ligolo-proxy` | TUN 组网 |
| `peass` | `data\tools\peass\winPEASx64.exe` | 提权枚举 |
| `nmap` | `C:\Program Files (x86)\Nmap\nmap.exe` | 端口/服务扫描 |

**Python 工具**（impacket / nxc / pypykatz / sqlmap）：

```
<部署根>\data\tools\python313\python.exe <部署根>\data\tools\python313\Scripts\<脚本>.py
```

## 二、字典

**`<部署根>\data\tools\wordlists\`**：

| 用途 | 文件 | 条数 |
| --- | --- | --- |
| 目录/文件爆破 | `dir-common-10769.txt` | 10,769 |
| 子域/vhost 前缀 | `subdomain-20024.txt` | 20,024 |
| 弱口令 | `top_100.txt` | 100 |

## 三、nuclei 模板与配置

- 模板库（**不要联网重下**）：`<部署根>\nuclei-templates`
- 配置目录：`$env:USERPROFILE\AppData\Roaming\nuclei`

## 四、本机不可用的工具

以下在包里只有 Linux ELF 或完全没装，**Windows 上跑不了**，请用等价替代：

| 工具 | 用到的技能 | 替代方案 |
| --- | --- | --- |
| `cfr.jar` / `procyon` | chains-rev、reverse-skill | 反编译器不随包（体积 + 许可）。需要时自己拉到 `data\tools\decompilers\` |
| 各类 Linux ELF | 视技能而定 | 用 `data\tools\` 里对应的 Windows 构建；没有就找等价工具 |

## 五、ARTEX 里的落库工具

技能里说的 `redteam_*` 系列工具在 ARTEX 里由这些工具承担：

| 技能里的说法 | ARTEX 工具 |
| --- | --- |
| 记录事实 | `record_fact` / `confirm_fact` |
| 报漏洞 | `report_finding`（`vulnclass` 决定严重度下限） |
| 登记资产 | `insert_assets` / `list_assets` |
| 立足点登记 | `register_session`（`generate_webshell` 生成马） |
| 隧道 | `tunnel_deploy` / `tunnel_probe` / `tunnel_list` / `tunnel_teardown` |
| 意图 | `add_intent`（人机接口用 `add_hint` 注入战略提示） |
| 知识库 | `kb_search` / `kb_get` / `kb_add` |
| C2 | `c2_exec` / `c2_list_sessions` / `c2_task_result` |

## 六、注意事项

- **绝对路径**：`data\tools\` 下的工具用全路径调用，**不要**用裸命令名（PATH 里没有）。
- **无 .exe 后缀的**：`httpx`、`katana`、`suo5`、`ligolo-proxy` —— 直接写全名，不要加 `.exe`。
- **Python 脚本**：必须用 `python313\python.exe` 的绝对路径；`dirsearch` / `oneforall` 要先 `cd` 到脚本所在目录。
- **不要装东西**：本机已备齐常用工具。真缺了先 `where <名字>` 找，再考虑等价替代，禁止 `apt`/`pip install` 装系统级依赖。
