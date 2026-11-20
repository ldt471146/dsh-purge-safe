# Webpack 异步 chunk 收割枚举 SPA 全量 API 面（new-api 定制构建实测）

- **code**: webpack-异步-chunk-收割枚举-spa-全量-api-面-new-api-定制构建实测
- **kind**: script
- **category**: info-leak
- **component**: Webpack SPA（new-api 及一切 webpack 构建的后台）
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（new-api 定制构建 invite-rebate-live）实测：从主包提取 114 个 chunk 全部下载成功，枚举出 40+ 个主包未出现的定制端点（/api/user/lottery/draw、/api/user/aff_transfer、/api/subscription/admin/*、/api/funding-sources/:id/credentials、/api/stripe/webhook、/api/waffo-pancake/webhook/* 等），随后据此完成匿名与鉴权面测试。
- **path**: pocs/webpack-异步-chunk-收割枚举-spa-全量-api-面-new-api-定制构建实测/poc.py
- **tags**: webpack,spa,api枚举,异步chunk,new-api,前端信息收集
- **created_at**: 2026-09-28T14:56:11.411Z
- **found_by**: vuln-scan

## 描述

从 SPA 主包 index.js 的 webpack d.u 映射中提取 chunkId->hash 表，批量下载全部 /static/js/async/<id>.<hash>.js 懒加载 chunk，正则提取全部 /api/ URL。能枚举出主包中不存在、只有懒加载页面才引用的定制 API 端点（本靶标：主包 113 条 → 收割后获 114 个 chunk、lottery/aff_transfer/funding-sources/subscription/admin/stripe-webhook 等全部定制端点）。

## 用法

```
python webpack_chunk_api_enum.py <BASE_URL> <主包js路径>
主包路径从 GET / 返回的 HTML <script src="/static/js/index.*.js"> 获取；确认主包内存在 d.u=e=>"static/js/async/"+e+"."+{...}[e]+".js" 模板后即可收割。注意走代理时大文件易断流，加重试。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Webpack 异步 chunk 收割：从主包提取 chunkId->hash 映射，批量下载 /static/js/async/<id>.<hash>.js，
# 正则提取全部 /api/ 端点。比目录字典爆破准确率高一个量级（覆盖懒加载页面才调用的定制 API）。
import requests, re, time, sys
BASE = sys.argv[1].rstrip("/")          # e.g. https://example.com
MAIN = sys.argv[2]                      # 主包路径，如 /static/js/index.3137992311.js
S = requests.Session(); S.trust_env = True
S.headers.update({"User-Agent": "Mozilla/5.0", "Referer": BASE + "/"})
body = S.get(BASE + MAIN, timeout=60).text
chunks = {}
for k, v in re.findall(r'(\d{1,4}):"([a-f0-9]{8,20})"', body):
    chunks.setdefault(k, v)
print("chunk ids:", len(chunks))
# 主包本身也提取
urls = set(re.findall(r'["`/](/api/[A-Za-z0-9._/${}?:=&-]{2,70})', body))
for cid, h in sorted(chunks.items(), key=lambda x: int(x[0])):
    url = f"{BASE}/static/js/async/{cid}.{h}.js"
    for t in range(3):
        try:
            r = S.get(url, timeout=40)
            if r.status_code == 200:
                urls |= set(re.findall(r'["`/](/api/[A-Za-z0-9._/${}?:=&-]{2,70})', r.text))
            break
        except Exception:
            time.sleep(3 + t * 3)
    time.sleep(0.4)
for u in sorted(urls): print(u)
# 用法: python webpack_chunk_api_enum.py https://example.com /static/js/index.3137992311.js
# 主包路径从 GET / 首页 HTML 的 <script src> 取；模板串 "static/js/async/"+e+"."+{...}[e]+".js" 确认目录。

```
