# Vue3/Vite SPA 接口测绘法：入口 JS 只给路由，真实 API 在懒加载 chunk 的数据层 use*.js 里

- **code**: vue3-vite-spa-接口测绘法-入口-js-只给路由-真实-api-在懒加载-chunk-的数据层-use-.js-里
- **kind**: script
- **category**: frontend-reverse
- **component**: Vue3/Vite SPA 前端
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 tgt6403-com 靶标 https://example.com 实测：入口 index-CJpgplpq.js(322KB) 只有 60 条路由字面量、0 个 axios 调用；改抓 41 个懒加载 chunk 后提出 50+ 真实端点（/reseller/{dashboard,orders,ledger-entries,balance-accounts,withdraws,domains,site-config,product-settings}、/api-credential、/guest/orders、/me/* 等），并据此完成 24 条未授权探测（全部 401，零命中）。baseURL=/api/v1 由入口 JS 中 Mc="/api/v1" 确认。
- **path**: pocs/vue3-vite-spa-接口测绘法-入口-js-只给路由-真实-api-在懒加载-chunk-的数据层-use-.js-里/poc.sh
- **tags**: 前端接口提取,Vite,Vue,chunk,SPA,接口测绘,只读
- **created_at**: 2026-09-28T14:23:00.999Z

## 描述

对 Vue3/Vite SPA 商城的前端产物做接口测绘：抓入口 JS → 按模块名挑懒加载 chunk → 在数据层 use*.js 里提取 axios 调用，得到 50+ 真实端点（含 Reseller 财务/提现、游客订单、API 凭据）。

## 用法

```
1) 把 TARGET 换成目标（带 SNI 的域名，VPS 出口执行）；2) 按步骤 1-3 抓入口 JS 与挑选 chunk（同名两套 hash 用 awk 去重）；3) 步骤 4 提端点；4) 步骤 5 用 401 vs 404 区分「需鉴权」与「不存在」。本案例产出见 runs/tg/api-endpoints.txt。
```

## 正文

```
# 目标画像
Vue3 + Vite 构建的 SPA（`/assets/index-<hash>.js`），业务接口全部在懒加载 chunk 里。

# 步骤（全部只读 GET；VPS 出口执行，本机 Windows 出网被 TUN 劫持不可信）
1) 抓首页拿入口 JS
   curl -sS -A "$UA" "https://TARGET/" -o page.html
   grep -oE 'src="[^"]+\.js"' page.html

2) 抓入口 JS，提取 chunk 清单（Vite 把 chunk 名内联在入口 bundle 里）
   curl -sS -A "$UA" "https://TARGET/assets/index-XXXX.js" -o index.js
   grep -oE '[A-Za-z0-9_.-]+-[A-Za-z0-9_-]{8}\.js' index.js | sort -u > chunks.txt

3) **关键**：chunk 名就是路由/模块名，按业务关键字挑选，别全下（本例 199 个 chunk，只下 41 个）
   grep -E '^(use|use[A-Z]|.*Console|.*Dashboard|.*Finance|.*Orders|.*Payment|.*Checkout|.*Login|.*Register|.*Profile|Guest.*|Reseller.*)-' chunks.txt \
     | awk '{p=$0; sub(/-[A-Za-z0-9_-]{8}\.js$/,"",p); if(!seen[p]++) print}' > sel.txt   # 同名两套 hash 去重
   while read -r f; do curl -sS -A "$UA" "https://TARGET/assets/$f" -o "chunks/$f"; sleep 1; done < sel.txt

4) 提取真实端点（**比在入口 bundle 里找 /api 有效得多**——axios 调用都在数据层 use*.js）
   grep -ohE '\.(get|post|put|patch|delete)\(("|`)/[^"`]{1,90}' chunks/*.js | sort -u
   # 相对路径即可；baseURL 在入口 JS 里，本例 `Mc="/api/v1"`

5) 区分「路由存在但需鉴权」与「路由不存在」（判 401 vs 404 的观测量必须一致）
   curl -sS -o out -w '%{http_code}' "https://TARGET/api/v1/me"           # 200 + {"status_code":401,...} = 存在需鉴权
   curl -sS -o out -w '%{http_code}' "https://TARGET/api/v1/me/orders"    # 404 page not found      = 不存在

# 本例战果
入口 JS 只含 60 条路由字面量，几乎无 /api；换到 chunk 层后一次提出 **50+ 个真实端点**
（含 /reseller/* 17 条财务与提现、/me/* 用户态、/guest/orders 游客订单、/api-credential）。

```
