# Fanatical（www.fanatical.com）GET /api/products/video-check/{src} 已证否 SSRF：src 仅按 YouTube 视频 ID 解析，不做服务端任意取源

- **code**: fanatical-video-check-not-ssrf
- **kind**: poc
- **category**: ssrf
- **component**: Fanatical 主站 API（www.fanatical.com / admin.fanatical.com 同 Heroku app）
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机（Linux，经平台记录代理）实测：CF 通路（www + 任意 anonid）与源站直连通路（--noproxy + --resolve admin.fanatical.com:443:3.33.161.45）各打 20+ 变体。src=https://httpbin.org/delay/5（本机同 URL 实测 5.289s）时端点仅 0.306/0.437s；黑洞 10.255.255.1 0.311s、192.0.2.1 0.248s，与裸 ID 基线 0.22-0.37s 无差异。唯一 webhook.site token 本地自测 1 条可收，端点注入后 total 始终=1；dnslog.cn 本地解析对照正常入账，注入的 vc-cf-dns/vc-org-dns 子域全量记录零命中。同族 download-sample/key-preview/get-suggested-by-product-id/get-fan-favourites 带 URL 参数均无取源。前端源码 product-service.js checkVideoData(src) 的 src 为 YouTube videoId（Video.jsx 播放器错误回调），合法 ID→"Video passed all conditionals"，其余→"Video is unlisted or private"。
- **tags**: fanatical,ssrf,negative,video-check,products-api
- **created_at**: 2026-11-11T17:54:28.258Z
- **engine**: https://www.fanatical.com/api/products/video-check/%7Bsrc%7D

## 描述

Fanatical 主站/后台同 Heroku app 的 video-check 路由曾被登记为潜在 SSRF 候选（客户端可控 src 进路径）。实测否证：src 不是 URL 而是 YouTube 视频 ID，服务端只向固定视频提供方查询，URL/内网/元数据/file/gopher/相对路径等全部无取源行为，时序与 OOB 双重判据均为阴性。后续 worker 不要在该端点重复 SSRF 探测。

## 用法

```
复测/判据：curl -sk -A "$ARTEX_UA" -H 'anonid: 11111111-1111-4111-8111-111111111111' 'https://www.fanatical.com/api/products/video-check/https%3A%2F%2Fhttpbin.org%2Fdelay%2F5' → 200 {"status":"Video is unlisted or private"}，time_total≈0.3s（对照本机 httpbin 5.29s）；源站直连：curl -sk --noproxy '*' --resolve admin.fanatical.com:443:3.33.161.45 'https://admin.fanatical.com/api/products/video-check/dQw4w9WgXcQ' → 200 {"status":"Video passed all conditionals"}。若未来出现 ≥5s 延迟或 OOB 命中，则该阴性结论被推翻。
```
