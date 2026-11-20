# 宝塔 WAF 来源封禁实测判据：multipart 上传后全出口 000/ProxyError，而同代理到 baidu 200（区分「代理失效」vs「目标拒我」）

- **code**: 宝塔-waf-来源封禁实测判据-multipart-上传后全出口-000-proxyerror-而同代理到-baidu-200-区分-代理失效-vs-目标拒我
- **kind**: poc
- **category**: waf
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-08 在 203.0.113.78（example.com，PHPWind 7.3.2 GBK 站群）实测：上传前 200|151628；POST /example.com?action=uploadicon（multipart）返回 200|0 后，同一出口对目标立刻 000|0 / ProxyError；同批代理到 https://www.baidu.com/ 仍 200|29506 ⇒ 确认是目标侧来源封禁。直连 http://203.0.113.78/example.com 返回 nginx 444|0，而 Test-NetConnection 443 = True ⇒ 目标在线仅拒绝来源。27 分钟内 6 个出口 IP（203.0.113.43:17981、203.0.113.44:17981、203.0.113.29:18888、203.0.113.75:19450、203.0.113.100:17981、203.0.113.35:17981）依次被打掉。
- **path**: pocs/宝塔-waf-来源封禁实测判据-multipart-上传后全出口-000-proxyerror-而同代理到-baidu-200-区分-代理失效-vs-目标拒我/waf-source-ban-criteria.sh
- **created_at**: 2026-10-08T05:49:00.157Z
- **found_by**: exploit

## 描述

这是判定「目标是否因上传动作封禁我方出口」的通用判据：①同出口上传前后对照 ②用第三方站点(baidu)做活性对照区分「代理挂了」与「目标拒我」 ③TCP 通但 HTTP 444/000 区分「目标宕机」与「目标活着但拒绝来源」。

## 用法

```
按顺序跑 5 段；第 4 段的「同代理 → baidu 200」是判据的核心对照项。用于任何"客户现场/靶标每次上传就掉线"的场景：先确认是目标封你，而不是免费代理自己挂了。UA 固定（PHPWind 的 verify 只绑 UA，跨出口可携带）。
```

## 正文

```
# 判据：multipart 上传 POST 后目标立即拒绝我方来源（宝塔 WAF 行为）
# 1) 上传前：任一出口访问目标应正常
curl.exe -sk --ssl-no-revoke --proxy http://203.0.113.35:17981 \
  -H 'Host: example.com' -A "$UA" -o x \
  -w '%{http_code}|%{size_download}\n' --max-time 25 \
  'https://example.com/example.com'
#   => 200|151628  (正常)

# 2) 发 1 次 multipart 上传（PHPWind 头像上传真实端点）
#    python requests: POST https://example.com/example.com?action=uploadicon&step=2&verify=<vh>&
#    files={"upload": (name, content, "image/gif")}
#    data={"uploadurl[1]":"80","uploadurl[2]":"80","facetype":"3","step":"2"}
#   => 200|0  (请求被接受)

# 3) 上传后立刻复测：同一出口对目标全部失败
#   curl -w '%{http_code}|%{size_download}'  => 000|0
#   python requests                          => ProxyError (连 CONNECT 都建不起来)

# 4) 判据分离（关键）：同批代理到 baidu 仍通 => 代理活着，是目标在拒我们
curl.exe -sk --proxy http://203.0.113.37:17981 -o y -w '%{http_code}|%{size_download}\n' --max-time 12 'https://www.baidu.com/'   # => 200|29506
curl.exe -sk --proxy http://203.0.113.37:17981 -o z -w '%{http_code}|%{size_download}\n' --max-time 15 'https://example.com/example.com'  # => ProxyError

# 5) 直连特征：TCP 443 通，但 HTTP 被 nginx 444 主动断连
Test-NetConnection 203.0.113.78 -Port 443   # => True (TCP 可达，目标在线)
curl.exe -sk -H 'Host: example.com' -o w -w '%{http_code}|%{size_download}\n' --max-time 20 'http://203.0.113.78/example.com'   # => 444|0
curl.exe -sk --ssl-no-revoke -H 'Host: example.com' -o v -w '%{http_code}\n' --max-time 20 'https://203.0.113.78/example.com'  # => 000 (TLS 阶段即失败)

```
