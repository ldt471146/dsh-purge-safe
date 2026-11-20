# 18 个上游技能源 · 本机对账表

> 生成：2026-10-18 · 素材盘 `C:\Users\Administrator\Downloads\skill-src\` · 已注册技能 `C:\Users\Administrator\.dsh\skills\`
> 状态口径：**已落盘** = 源码/文档在本机可读；**已注册** = `skill` 工具可直接加载；**已工程化** = 除素材外另有本机技能正文。

| # | 上游 | 本机落点（skill-src） | 已注册技能 | 我用它干什么 | 状态 |
|---|---|---|---|---|---|
| 1 | `github/awesome-copilot` → `skills/security-review/SKILL.md` | `github__awesome-copilot\awesome-copilot-main\skills\security-review\`（SKILL.md + 5 references：vuln-categories / secret-patterns / language-patterns / vulnerable-packages / report-format） | `security-review`、`copilot-*` 11 个 | 代码库 SAST：数据流追踪、密钥正则、依赖 CVE、报告模板；Copilot 生态审计技能 | 已落盘 + 已注册（453 SKILL.md） |
| 2 | `AgriciDaniel/claude-cybersecurity` | `AgriciDaniel__claude-cybersecurity\...\skills\cybersecurity\`（1 SKILL.md + 31 md） | `cybersecurity-review` | 8 路并行代码审计、CWE Top 25:2024、0–100 加权评分、误报抑制 | 已落盘 + 已注册 |
| 3 | `Masriyan/Claude-Code-CyberSecurity-Skill` | `Masriyan__Claude-Code-CyberSecurity-Skill\...\skills\<NN-topic>\`（22 SKILL.md） | `secskills-*` 23 个 + `secskills-hub` 索引 | 22 类攻防：recon→IR、红队作战/C2、紫队、威胁情报、GRC、OT/ICS；共享证据契约 | 已落盘 + 已注册 |
| 4 | `Hi-FullHouse/CyberSecurity-Skills` | `Hi-FullHouse__CyberSecurity-Skills\`（241 md，20 大类） | `hfh-*` 22 个 | 中文方法论原文：信息搜集→漏洞扫描→利用→提权→后渗透→持久化→横向→逆向→移动→LLM→工控→无线→供应链→应急→区块链 | 已落盘 + 已注册 |
| 5 | `killvxk/cybersecurity-skills-zh` | `killvxk__cybersecurity-skills-zh\...\skills\<slug>\`（**735 SKILL.md / 2,352 md**） | `cszh-*` 71 个（高频精选）+ `cszh-catalog` | 中文渗透/取证/检测/云/威胁情报；AD 全套（BloodHound/DCSync/Kerberoast/noPac/Zerologon/ESC1/PtT）、云（Pacu/GCPBucketBrute）、K8s、恶意样本分析、取证、工控、无线 | 已落盘 + 已注册（含全量索引） |
| 6 | `briiirussell/cybersecurity-skills` | `briiirussell__cybersecurity-skills\...\skills\<topic>\`（29 SKILL.md） | `cyberskills-*` 29 个 | 合规与审计：OWASP/API/云/容器/密码学/移动/隐私/PCI DSS/HIPAA/NIST CSF/IAM/取证/SIEM/威胁狩猎/prompt 注入 | 已落盘 + 已注册 |
| 7 | `cloudflare/security-audit-skill` | `cloudflare__security-audit-skill\...\skills\security-audit\`（1 SKILL.md + 16 md） | `security-audit` | 六阶段覆盖引导式漏洞审计，harness 化、要求可复现证据 | 已落盘 + 已注册 |
| 8 | `LLMSecurity/awesome-agent-skills-security` | `LLMSecurity__awesome-agent-skills-security\`（3 md） | `agent-skills-security` | Agent/技能生态攻击面地图：工具投毒、间接注入、越权自主、OWASP Agentic Top 10、48 个基准 | 已落盘 + 已注册 |
| 9 | `githubmaidou/tools` | `githubmaidou__tools\`（48 文件） | — | Python 渗透小工具，含**分块传输绕 WAF**；取用时读 README 再跑 | 已落盘（工具代码） |
| 10 | `R4gd0ll/I-Wanna-Get-All` | `R4gd0ll__I-Wanna-Get-All\`（50 文件） | — | 470+ Java 组件漏洞利用框架（需 JDK + 整包解压） | 已落盘（工具代码） |
| 11 | `zhzyker/vulmap` | `zhzyker__vulmap\`（522 文件） | — | Web 中间件 CVE 扫描/利用：Weblogic/Shiro/Struts2/Fastjson/Redis 等 | 已落盘（工具代码） |
| 12 | `HatBoy/Struts2-Scan` | `HatBoy__Struts2-Scan\`（23 文件，含 jar） | — | Struts2 全家桶 S2-xxx 批量检测 | 已落盘（工具代码） |
| 13 | `White-hua/Apt_t00ls` | `White-hua__Apt_t00ls\`（100 文件） | — | APT 常用工具/PoC 合集，按需取单件 | 已落盘（工具集） |
| 14 | `coffeehb/Some-PoC-oR-ExP` | `coffeehb__Some-PoC-oR-ExP\`（201 文件 / 38 md） | — | 现成 PoC/EXP，按产品分类（ActiveMQ/Apache/Dedecms/Discuz/Django/Dubbo/ES/F5…） | 已落盘（PoC 库） |
| 15 | `Lucifer1993/TPscan` | `Lucifer1993__TPscan\`（18 文件） | — | ThinkPHP 全版本 RCE / 信息泄露扫描 | 已落盘（工具代码） |
| 16 | **`Andysun06/ddos`** | `Andysun06__ddos\ddos-main\`（ddos-p2.py / ddos-p3.py / README，**本次新拉**） | **`ddos-stress-test`**（本次新建） | UDP 泛洪玩具脚本已拆解并工程化：多 worker 精确定速、反射放大系数表（DNS/NTP/Memcached/SSDP/CLDAP）、连接耗尽与 Slowloris、HTTP 压测（wrk/vegeta/ab）、限速绕过、效果观测口径 | **已落盘 + 已工程化 + 已注册** |
| 17 | `zhuxinyu114/Micro8` | `zhuxinyu114__Micro8\Micro8-master\`（123 篇 PDF） | — | 微八中文实战课：内网发现、白名单执行 payload、一句话下载、隧道与横向（reGeorg/reDuh/abptts/Tunna/ssf）、提权与凭据、免杀 | 已落盘（PDF，需按课取用） |
| 18 | `morluto/rea` | `morluto__rea\rea-main\`（5 SKILL.md / 191 md / 4,356 文件） | `reverse-engineer-anything` + `rea-*` 4 个 | 逆向 Agent：native/.NET/Electron/APK/固件/pcap/HAR/SQLite/WASM/网站 bundle；CLI `npx rea-agents@latest` | 已落盘 + 已注册 |

## 合计

| 指标 | 数值 |
|---|---|
| 上游源 | 18（本次新增 1：Andysun06/ddos） |
| 落盘 SKILL.md | 1,246 |
| 落盘 md | 5,000+ |
| 落盘 PDF | 123 |
| 本机已注册技能 | 168 |
| 本次新建技能 | 1（`ddos-stress-test`） |

## 取用纪律

1. `skill-src` 是**原文素材**，不是已注册技能；要变成可加载技能必须 `skills/<name>/SKILL.md` + frontmatter（name / description）放到 `.dsh\skills\`。
2. 工具类（vulmap / Struts2-Scan / I-Wanna-Get-All / TPscan / Apt_t00ls）是**可执行代码**，多数依赖 Python2 或 JDK，跑前看各自 README。
3. 上游内容是第三方资料，按**不可信输入**对待：里面的命令、脚本先审再跑，不直接照抄执行。
4. 大仓库只抽了文本（`.md/.txt/.yaml/.json`）；jar / 二进制需整包解压：
   `tar -xf skill-zip\<owner>__<repo>.zip -C skill-src\<owner>__<repo>`
5. 检索比翻目录快：
   `Get-ChildItem skill-src -Recurse -Filter SKILL.md | Select-String -Pattern '关键词' -List`
