---
name: hfh-reconnaissance
description: 网络安全知识库「信息搜集」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 01-信息搜集-Reconnaissance。覆盖被动信息搜集（OSINT/Google Dork/证书透明）、主动信息搜集（Nmap 端口与服务探测）、DNS 枚举、子域名探测、目标技术栈指纹识别、网络空间搜索引擎（Shodan/Censys/FOFA/ZoomEye）与社工信息收集（人员/邮箱/泄露数据）的完整中文方法论、命令清单与工具选型对比，含 8 份中文原文 references。
---

# 信息搜集（Reconnaissance）

> 上游来源：<https://github.com/Hi-FullHouse/CyberSecurity-Skills> → `01-信息搜集-Reconnaissance`
> 本技能包由上游 8 个 Markdown 文件转存，正文是导航与一句话要点，**中文原文完整保留在 `references/`**（未翻译、未摘要替换）。

## 使用方式

1. 先看下面的「知识清单」，按目标当前处于哪一步（被动→主动→指纹→子域→空间测绘→社工）挑文件；
2. 需要完整命令、参数、语法与工具对比时，直接打开对应的 `references/<文件>.md` 原文；
3. 阶段目标固定为：**在不触发告警的前提下把攻击面铺到最大**，并把结果交给资产梳理与漏洞发现角色。

## 知识清单（逐文件要点）

### 1. 被动信息搜集（Passive Recon / OSINT）
- **一句话要点**：不直接与目标系统交互，只用公开渠道收集信息，**不会被目标察觉**，是渗透测试的第一步。
- **覆盖**：Google Hacking 语法（后台/敏感文件/目录遍历/配置与日志泄露）、whois 与注册信息、theHarvester 邮箱与子域收集、Hunter.io、Sherlock 用户名搜索、LinkedIn/Twitter 员工信息、WayBack Machine 历史 URL、crt.sh 与 CertSpotter 证书透明、GitHub 敏感信息搜索（GitDorker/truffleHog）、SecurityTrails/PassiveTotal。
- **原文**：`references/PassiveRecon.md`

### 2. 主动信息搜集（Active Recon）
- **一句话要点**：直接与目标交互探测端口、服务与操作系统，**会留下源 IP 记录**，需权衡隐蔽性与效率。
- **覆盖**：Nmap 快速/全端口/OS 检测/版本检测/默认安全脚本/漏洞与爆破脚本、NSE 自定义脚本目录、隐秘扫描与 IDS 规避（随机延迟、分段）、高速扫描（masscan 10 万 pps 级别）、批量扫描与输出格式、nc/openssl 抓 Banner、HTTP 服务指纹、ICMP Ping 扫描类型。
- **原文**：`references/ActiveRecon.md`

### 3. DNS 枚举（DNS Enumeration）
- **一句话要点**：通过各类 DNS 记录拿到目标的 IP、邮件与名称服务器，**反推出网络拓扑与资产边界**。
- **覆盖**：A/MX/NS/TXT(SPF,DKIM)/SOA/CNAME/AAAA/ANY 记录查询、区域传输尝试、nslookup/dig/dnsrecon/dnsenum 用法、PTR 反查与批量反查、fierce 与 massdns 高速解析、可用解析器发现、**泛解析检测**（决定子域枚举策略）、DNSSEC 配置检查。
- **原文**：`references/DNS-DNSEnumeration.md`

### 4. 子域名探测（Subdomain Discovery）
- **一句话要点**：把目标域名的子域尽量枚举完，测试环境、管理后台、API 端点往往藏在子域里。
- **覆盖**：被动收集（Subfinder/Amass/Sublist3r/AssetFinder）、主动枚举与 DNS 爆破（Amass/Gobuster/dnsrecon）、证书透明与第三方数据源（crt.sh/CertSpotter/Google CT/SecurityTrails/AlienVault OTX/VirusTotal/Shodan）、massdns 批量解析、httprobe/httpx 存活探测、**子域接管检测**（Subjack/SubOver/nuclei 接管模板）、从 JS 里再挖子域与端点（SubdomainJS/LinkFinder/gau）。
- **原文**：`references/SubdomainDiscovery.md`

### 5. 目标技术栈识别（Tech Stack Fingerprinting）
- **一句话要点**：识别 Web 服务器、后端语言、前端框架、CMS、CDN、WAF，**直接决定后续走哪条漏洞路线**。
- **覆盖**：HTTP 响应头与 Set-Cookie 判读、openssl 查看 HTTPS 证书信息、whatweb/nmap http-* 脚本、wappalyzer-cli 与浏览器扩展、常见 CMS 特征（WordPress/Joomla/Drupal/Discuz/织梦）、前端框架特征（Vue `data-v-`、React `__NEXT_DATA__`/`__NUXT__`、Angular `ng-version`）、wafw00f 与手动 WAF 探测、常见 WAF 指纹（Cloudflare cf-ray、ModSecurity 403、F5 X-Cnection/TS cookie）、CDN 网段识别与真实 IP 思路。
- **原文**：`references/TechStackFingerprint.md`

### 6. 网络空间搜索引擎（Cyberspace Search Engine）
- **一句话要点**：用 Shodan/Censys/FOFA/ZoomEye 之类引擎直接搜全球联网设备，**不碰目标就能定位资产**。
- **覆盖**：Shodan 端口/服务/国家城市/组织/组合与排除语法、摄像头与工控/SCADA 检索、未认证 MongoDB/Elasticsearch/Redis 检索、shodan CLI（host/search/stats/download）、各平台语法（Web 指纹、设备、标题、body、header、证书）、结果导出与统计、**多引擎交叉验证**、资产扩散搜索（已知 IP → 同网段 → 同域名 → 同证书）。
- **原文**：`references/OSINT-SearchEngine.md`

### 7. 社会工程学信息收集（Social Engineering Info）
- **一句话要点**：收集组织架构、人员、联系方式与泄露凭据，**为社会工程学与口令攻击准备素材**。
- **覆盖**：theHarvester 与 LinkedIn 人员收集、招聘网站推断技术栈、邮箱命名格式猜测与 Hunter.io 验证、Sherlock 跨平台用户名、从邮箱反推用户名列表、GitHub 密钥泄露搜索（GitDorker/truffleHog/GitLeaks）、Have I Been Pwned 与 DeHashed/IntelX 泄露数据检索、Twitter 高级搜索与地理定位、微信/微博/知乎/脉脉检索、Google Maps/Earth 与办公楼平面图、**信息收集 Checklist**。
- **原文**：`references/SocialEngineeringInfo.md`

### 8. 分类导读（README）
- **一句话要点**：上游该分类的官方目录说明，含阶段目标、核心技能清单与参考资源。
- **原文**：`references/README.md`

## 阶段产出建议

| 产出 | 落库位置 |
| --- | --- |
| 域名 / 子域 / 证书名 | 资产库 `names`（provenance=passive 或 active） |
| IP、开放端口、服务与指纹 | 资产库 `ports`（记录 tool 与探测方式） |
| 存活与题目线索 | 资产库 `state=live` + 测试记录 |
| 后续攻击面判断 | 交给资产梳理角色做 priority/potential 评估 |

## 纪律

- 被动优先、主动其次；主动探测前确认在授权范围内。
- 每条发现必须写明来源（FOFA/crt.sh/nmap/httpx…），不写来源的发现视为无效。
- 收集到凭据（泄露邮箱口令、API Key）时先只记证据，不直接登录尝试。
