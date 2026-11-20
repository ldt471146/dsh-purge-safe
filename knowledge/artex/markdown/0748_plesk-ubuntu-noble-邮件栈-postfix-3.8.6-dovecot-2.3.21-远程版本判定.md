# Plesk/Ubuntu noble 邮件栈（Postfix 3.8.6 + Dovecot 2.3.21）远程版本判定与预认证 CVE 收口判据（含 SASL DIGEST-MD5 客户端侧边界）

- **code**: plesk-ubuntu-noble-邮件栈-postfix-3.8.6-dovecot-2.3.21-远程版本判定
- **kind**: poc
- **category**: recon
- **component**: Postfix / Dovecot / Cyrus SASL / Plesk / Ubuntu noble
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12 在 88.208.224.249（mail.goffsgames.co.uk，Plesk 18.0.82.2）实测：SSH banner=OpenSSH_9.6p1 Ubuntu-3ubuntu13.20（noble）；Postfix banner 25/465/587="220 server2.visionhost.co.uk ESMTP Postfix (Ubuntu)"，EHLO 含 CHUNKING、无 SMTPUTF8/VRFY/LIMITS；裸 LF NOOP→250 2.0.0 Ok（3.8 默认 no / 3.9 默认 normalize 均如此，不判别）；单包抢发 EHLO+MAIL→完整 EHLO 能力+250 2.1.0 Ok 未断连（=3.8.x 默认 smtpd_forbid_unauth_pipelining=no；3.9 默认 yes 会断连）；IMAP 993 CAPABILITY 无版本、ID 仅 ("name" "Dovecot")、失败 LOGIN→NO [AUTHENTICATIONFAILED] 且延迟>1s；本机 noble apt 对照 postfix 3.8.6-1ubuntu0.1、dovecot-core 1:2.3.21+dfsg1-2ubuntu6.5；CVE 语料核对 CVE-2023-51764 修复线 3.8.6、CVE-2022-30550 修复线 2.3.20；CVE-2026-107161（Red Hat CNA）为 DIGEST-MD5 客户端侧（恶意服务器触发客户端崩溃），服务器角色不适用，Ubuntu noble cyrus-sasl2 “Vulnerable, fix deferred”（2026-10-16）。
- **path**: pocs/plesk-ubuntu-noble-邮件栈-postfix-3.8.6-dovecot-2.3.21-远程版本判定/poc.md
- **tags**: recon,mail,postfix,dovecot,cyrus-sasl,plesk,ubuntu,noble,version-fingerprint,cve-reconciliation,negative-intel
- **created_at**: 2026-11-12T11:18:05.018Z
- **engine**: 88.208.224.249
- **found_by**: recon

## 描述

Plesk/Ubuntu noble 邮件主机（Postfix+Dovecot）无版本串时的远程版本族判定方法与预认证 CVE 收口判据；含裸 LF 非判别、unauth-pipelining 判别、SASL DIGEST-MD5 客户端侧 CVE 的适用性边界。

## 用法

```
1) SSH banner 定发行版；2) Postfix banner/EHLO 能力（CHUNKING≥3.4，LIMITS 非判据）；3) 裸 LF NOOP 不判别 3.8/3.9；4) 单包抢发 EHLO+MAIL 测 smtpd_forbid_unauth_pipelining（3.8 默认 no→250 正常处理；3.9 默认 yes→断连）；5) IMAP CAPABILITY/ID 无版本，靠发行版交叉推断；6) 对照 noble 仓库 postfix 3.8.6-1ubuntu0.x / dovecot 1:2.3.21+dfsg1-2ubuntu6.x；7) 按上表核对修复线，DoS 类一律不触发；8) 别忘了查 Cyrus SASL（CVE-2026-107161 是客户端侧，服务器角色不适用）。
```

## 正文

```
# Ubuntu noble + Plesk 邮件栈远程版本判定与预认证 CVE 收口判据

## 适用面
目标为 Plesk 托管的邮件主机（Postfix 25/465/587 + Dovecot 993），无版本串直读信道，需要远程推断版本并判断预认证控制类 CVE 是否适用。

## 1) 版本判定（按强度排序）
1. SSH banner 定发行版：`SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20` → Ubuntu 24.04 noble（3ubuntu13.x 为 noble 分支，补丁位可看更新水位）。
2. Postfix banner：`220 <host> ESMTP Postfix (Ubuntu)` 只证明发行版包（Debian/Ubuntu main.cf 的 smtpd_banner），**不泄版本**。
3. EHLO 能力：CHUNKING→≥3.4；SMTPUTF8/VRFY 取决于配置；**LIMITS 不能当判据**（3.9/3.10 公告均未提）。
4. **裸 LF 不是判别点**：Postfix 3.8.4+ 回填 smtpd_forbid_bare_newline 但默认禁用(no)，3.9.0 默认 normalize——两者都会接受裸 LF 命令（NOOP\n→250 2.0.0 Ok），不能区分 3.8/3.9。
5. **未授权 pipelining 才是判别点**：3.9.0 默认 smtpd_forbid_unauth_pipelining=yes（抢发即断连），3.8.x 默认 no。测法（非破坏性）：连接后不读 banner 直接单包发 `EHLO x\r\nMAIL FROM:<probe@example.com>\r\n`；3.8 会正常回 EHLO 能力 + `250 2.1.0 Ok`，3.9 默认会立即断连。注意：MAIL FROM 在未认证 25 口通常被接受，不产生投递（不发 RCPT/DATA）。
6. Dovecot：CAPABILITY/ID 不泄版本（ID 仅 `("name" "Dovecot")`）；只能靠发行版交叉推断。
7. 交叉推断：Ubuntu noble 仓库 postfix=3.8.6-1build2（updates 3.8.6-1ubuntu0.x）、dovecot-core=1:2.3.21+dfsg1-2ubuntu5（updates …ubuntu6.x）；Plesk 18.0.8x 在 noble 上即用这两条线。

## 2) 预认证控制类 CVE 修复线（2022-2026 语料）
- Postfix CVE-2023-51764（SMTP smuggling）：影响 through 3.8.5，修复线 3.8.6（另有 3.7.9/3.6.13/3.5.23）→ 3.8.6 目标等于修复线。
- Postfix CVE-2026-43964（enhanced status code 畸形致 buffer over-read/崩溃）：上游修复 3.8.16/3.9.10/3.10.9，3.8.6 上游口径在范围内，但属 DoS 类，未触发；Ubuntu 回补状态远程不可判。
- Dovecot CVE-2022-30550（auth 绕过）：影响 2.3 <2.3.20，修复线 2.3.20 → 2.3.21 高于；且需两条同 driver+args passdb（Plesk 单 passdb 不适用）。
- Dovecot 2026 批次（CVE-2026-24031 SQL auth 绕过 / 27860 LDAP filter 注入 / 42008 trusted-proxy 认证注入 / 73208、40205 OAuth2 scope / 0394 per-domain passwd 路径穿越）：均需非默认配置（SQL/LDAP/OAuth2/trusted_proxies/per-domain passwd），Plesk 默认不具备 → 不适用。
- 其余 2024-2026 Dovecot CVE 全为 DoS 类（23184/23185 头解析、25584 dot-LF-DOT-LF、59028 非法 base64、59032/33605/40019/40013 ManageSieve、27857/42006 括号、42391 ID 参数等）——按“不触发 DoS”约束一律不验证；ManageSieve 4190 关闭时天然不适用。

## 3) SASL 依赖层（易漏）
- Postfix AUTH 依赖 Cyrus SASL：先看 EHLO AUTH 机制清单。
- CVE-2026-107161（DIGEST-MD5 add_to_challenge 堆溢出，2026-10）是**客户端侧**：需目标作为 DIGEST-MD5 客户端连恶意/on-path 服务器；Postfix/IMAP 服务器角色不适用（Ubuntu noble 该包 “Vulnerable, fix deferred” 仅对客户端角色有意义）。
- openwall 2026-10 未编号问题：SCRAM GS2 解析 1-byte OOB 读（需 SCRAM）、SRP 认证绕过 A==0 mod N（需 SRP）——机制未广告即不适用。

## 4) 失败/误判点
- 465/993 必须先 TLS 包裹才出 banner。
- 目标 SMTP AUTH 无速率限制（本类主机常见），但 IMAP 有 auth_failure_delay≈1.65s，别把延迟当封禁。
- 用裸 LF/大括号/畸形 base64 去“验证版本”会踩到 DoS 类 CVE（27857/42391/59028），违反非破坏性约束。
- 发行版交叉推断只能到“版本族”，精确补丁号（是否回补 CVE-2026-43964、CVE-2024-23184/23185）必须经立足点读 dpkg -l / apt changelog。

## 5) 结论口径
版本族达到全部预认证控制类修复线时，可落“控制类 CVE 面收口”的量化阴性事实；残余只写 DoS 类（未触发）与需非默认配置类（不适用），并注明远程不可判补丁号。
```
