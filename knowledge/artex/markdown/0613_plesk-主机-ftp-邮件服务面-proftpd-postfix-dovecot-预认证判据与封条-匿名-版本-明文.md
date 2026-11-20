# Plesk 主机 FTP/邮件服务面（ProFTPD+Postfix+Dovecot）预认证判据：匿名/版本/明文认证 + 默认 SNI 过期自签证书

- **code**: plesk-主机-ftp-邮件服务面-proftpd-postfix-dovecot-预认证判据与封条-匿名-版本-明文
- **kind**: poc
- **category**: recon
- **component**: ProFTPD / Postfix / Dovecot / Plesk
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 在 old.retro32.com 源站 92.205.178.49（GoDaddy/Host Europe Plesk 主机）实测：21 ProFTPD banner 无版本、SITE HELP 无 CPFR/CPTO、anonymous/ftp/admin 全 530、USER 任意名统一 331；25 filtered；587 强制 STARTTLS 且外部 RCPT 全部 554 Client host rejected；465/993/995 默认 SNI 返回过期自签 Plesk 证书（subject/issuer=O=Plesk, CN=Plesk，notAfter=Jul 9 12:28:36 2024 GMT，Verify return code: 10）；换同主机另一已配置邮件域的 SNI 返回 Let's Encrypt 有效证书（Verify return code: 0），证明证书选择依赖 SNI 且目标域无有效邮件证书；143 明文 LOGIN 返回 NO [AUTHENTICATIONFAILED] 而非 NO [PRIVACYREQUIRED]；110 明文 USER→+OK / PASS→-ERR [AUTH] Authentication failed.；4190 Dovecot Pigeonhole 开放。findings finding_id=132 / finding_checks.verdict=verified / status=confirmed。
- **path**: pocs/plesk-主机-ftp-邮件服务面-proftpd-postfix-dovecot-预认证判据与封条-匿名-版本-明文/plesk_mail_tls_plaintext_auth.md
- **tags**: recon,mail,plesk,postfix,dovecot,imap,pop3,smtp,tls,sni,expired-cert,self-signed,cleartext-auth,weak-credential,mitm,preauth
- **created_at**: 2026-11-11T17:31:37.147Z
- **engine**: 92.205.178.49
- **found_by**: vuln-scan

## 描述

Plesk/Linux 主机非 HTTP 服务的预认证判据集：如何快速区分「服务已加固」与「服务不存在」，以及哪些回显可作为阴性封条。适用于拿到源站 IP 后的服务面首轮确定性验证。其中邮件侧已确认的弱点是：默认/目标 SNI 下发过期自签 Plesk 证书，且 IMAP 143 / POP3 110 未禁用明文 LOGIN/USER-PASS（返回 AUTHENTICATIONFAILED 而非 PRIVACYREQUIRED），属低危弱凭据/明文传输面，需 on-path 嗅探或 MITM（客户端忽略证书告警）才能截获邮件凭据。

## 用法

```
1) banner：python socket 直连 21/22/110/143/587；465/993/995 必须 TLS 包裹后才出 banner（openssl s_client -connect IP:465 -servername <域名>），不做 TLS 会空等。
2) FTP 判据：anonymous:anonymous / anonymous 空 / ftp:ftp / admin:admin 全 "530 Login incorrect." = 匿名与默认口令关闭（ProFTPD 对存在/不存在用户响应无差分，不能当用户枚举 oracle）；SITE HELP 只列 QUOTA/RATIO/HELP/CHGRP/CHMOD = mod_copy(CPFR/CPTO) 未启用，CVE-2015-3306 类不适用；USER 任意名统一 331 = 无预认证枚举；AUTH TLS 后证书 CN 可判主机归属（LE 有效证书 vs Plesk 自签）。
3) SMTP 判据：EHLO 无 STARTTLS 但在 STARTTLS 前 VRFY/MAIL/RCPT 全 530 = 强制 STARTTLS（正加固）；STARTTLS 后 VRFY 502 = VRFY 关闭；外部 MAIL FROM 250 + RCPT 554 "Client host rejected" = 客户端策略拒绝（非开放中继，且 RCPT 差分不可用，勿把统一 554 误读成"用户不存在"）；25 STATE=filtered = 无入站 SMTP。
4) Dovecot 判据：banner/ID 只给 name=Dovecot 不给版本；143 明文 LOGIN 返回 NO [AUTHENTICATIONFAILED] = 允许明文认证（若返回 NO [PRIVACYREQUIRED] 才是禁用明文）；110 明文 USER→+OK / PASS→-ERR [AUTH] 同理；pre-login CAPABILITY 含 STARTTLS 只表示支持，不代表强制。
5) 证书 SNI 差分：同一 IP 不同 -servername 返回不同证书 → 该主机为多域邮件服务；默认/目标域返回过期自签 = 该域未配置邮件证书（很可能邮件由别处承载，如 M365 MX）。
6) 版本不可得时的 CVE 口径：ProFTPD/Postfix/Dovecot 默认都不泄版本，禁止按"看起来像"匹配 CVE；ProFTPD pre-auth 候选 CVE-2026-42167 需 mod_sql+%U 日志+SQL 后端 COPY TO PROGRAM，CVE-2026-44331 需 mod_wrap2_sql+UseReverseDNS，均需配置证据。
7) 漏洞复现（weak-credential/low）：默认 SNI 过期自签证书 + IMAP/POP3 明文认证未禁；完整命令与判据见 content。仅 on-path 或能让客户端忽略证书告警的 MITM 才可截获凭据，不能据此直接接管邮箱。
```

## 正文

```
# 邮件服务「默认 SNI 过期自签证书 + IMAP/POP3 明文认证」验证

## 适用面与前置
- 目标是自建/托管邮件主机（Plesk + Postfix + Dovecot 常见），暴露 465/587（SMTP submission）、993（IMAPS）、995（POP3S）、143（IMAP）、110（POP3）。
- 无需任何邮箱账号即可验证证书与「明文认证是否被受理」；测试口令用随机不存在的收件人，禁止用真实凭据。
- 要构成实际凭据截获，还需额外条件：攻击者位于客户端到该主机的网络路径上（嗅探明文认证），或作为中间人使客户端接受过期自签证书（用户习惯性忽略告警）。因此按 low 记录，作为 MITM/凭据捕获的前置条件，而不是直接接管邮箱。

## 1) 证书：默认 SNI 返回过期自签证书
对 465 / 587 / 993 / 995 分别执行：

```bash
openssl s_client -connect <TARGET_IP>:465 -servername <TARGET_MAIL_SNI> </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
openssl s_client -connect <TARGET_IP>:465 -servername <TARGET_MAIL_SNI> </dev/null 2>&1 \
  | grep -E 'Verify return code|subject=|issuer='
# 993 / 995 / 587 重复同样命令
```

判据：
- subject 与 issuer 相同且为 Plesk（自签），notAfter 已过期，`Verify return code: 10 (certificate has expired)` → 默认/目标 SNI 没有有效证书。
- 换成该主机上另一个「已配置有效证书」的邮件域做 SNI 对照：`Verify return code: 0 (ok)`，CN 为该域 → 证明证书按 SNI 选择，目标域本身未配置邮件证书。
- 465/993/995 支持 TLS1.3 不代表证书有效，两个维度分开判。

本次实测（2026-11-11）：465/993/995 默认 SNI 均为 `subject=C=CH, L=Schaffhausen, O=Plesk, CN=Plesk`、`notAfter=Jul 9 12:28:36 2024 GMT`、`Verify return code: 10`；换同主机另一已配置邮件域的 SNI 后为 Let's Encrypt 有效证书、`Verify return code: 0`。

## 2) IMAP 143：明文 LOGIN 未被禁用

```python
import socket
s = socket.create_connection(("<TARGET_IP>", 143), timeout=10)
print(s.recv(4096).decode(errors="replace"))          # 期望 * OK [CAPABILITY ... STARTTLS AUTH=PLAIN AUTH=LOGIN ...] Dovecot ready.
s.sendall(b"a1 LOGIN <nonexistent-user> <WrongPass!123>\r\n")
print(s.recv(4096).decode(errors="replace"))
s.close()
```

判据：
- 返回 `a1 NO [AUTHENTICATIONFAILED] Authentication failed.` = 明文 LOGIN 被受理并送到认证后端，凭据在链路上明文可见。
- 若返回 `NO [PRIVACYREQUIRED]`，或 banner/响应明确 `Plaintext authentication disallowed` = 明文认证已禁用，本条不成立。
- `AUTHENTICATIONFAILED` 只证明「明文命令被受理」，不证明口令正确。

## 3) POP3 110：明文 USER/PASS 未被禁用

```python
import socket
s = socket.create_connection(("<TARGET_IP>", 110), timeout=10)
print(s.recv(4096).decode(errors="replace"))          # 期望 +OK Dovecot ready.
s.sendall(b"USER <nonexistent-user>\r\n")
print(s.recv(4096).decode(errors="replace"))          # 期望 +OK
s.sendall(b"PASS <WrongPass!123>\r\n")
print(s.recv(4096).decode(errors="replace"))          # 期望 -ERR [AUTH] Authentication failed.
s.close()
```

判据：
- `USER` 返回 `+OK`、`PASS` 返回 `-ERR [AUTH] Authentication failed.` = 明文凭据已提交认证后端。
- 若返回 `-ERR [AUTH] Plaintext authentication disallowed` 或 `PRIVACYREQUIRED` = 已禁用明文。

## 4) 对照：SMTP 587 已强制 STARTTLS

```bash
# 不做 STARTTLS，直接发 EHLO 后再试 VRFY/MAIL
printf 'EHLO probe.local\r\nVRFY <user@example.com>\r\nMAIL FROM:<probe@example.net>\r\nQUIT\r\n' \
  | nc -w 8 <TARGET_IP> 587
```

判据：
- STARTTLS 前 `VRFY` / `MAIL` / `RCPT` 一律 `530 5.7.0 Must issue a STARTTLS command first` = SMTP 提交口加固正常，问题只局限在 IMAP/POP3 明文口与证书配置。
- 若 587 也接受明文 MAIL，则问题面更大，需单独记录。

## 失败/误判常见原因
- 465/993/995 必须先完成 TLS 握手才出 banner；直接 TCP connect 会「无 banner」假阴性。
- `openssl s_client` 不加 `-servername` 会落到默认 vhost；SNI 不同结果不同，必须做「目标域 vs 已知有效域」成对测试。
- 证书过期不等于服务不可用：客户端可能仍能连接，只是验证失败/需手动忽略告警——这正是 MITM 面成立的前提。
- Dovecot 可能把认证代理到后端（如 Plesk auth service），仍返回 `AUTHENTICATIONFAILED`；这不影响「明文可达」的判定。
- 25 端口 inbound SMTP 被 filtered 不代表 587/465 submission 不可达，需分开测。
- 不要用真实邮箱账号验证明文认证；随机不存在的用户即可，避免触发锁定或留下真实凭据。

## 结论口径
- 成立条件：默认/目标 SNI 返回过期自签证书 + IMAP 143 或 POP3 110 明文认证返回 `AUTHENTICATIONFAILED`（而非 `PRIVACYREQUIRED`）。
- 影响：on-path 攻击者可嗅探邮件凭据；或利用过期自签证书实施 MITM（客户端忽略告警时）。单靠本弱点不能直接登录邮箱，需配合凭据捕获。
- 定级：low；归类 weak-credential / 明文传输与证书配置弱点。
```
