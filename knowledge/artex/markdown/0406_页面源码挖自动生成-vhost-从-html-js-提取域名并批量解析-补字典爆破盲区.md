# 页面源码挖自动生成 vhost —— 从 HTML/JS 提取域名并批量解析（补字典爆破盲区）

- **code**: 页面源码挖自动生成-vhost-从-html-js-提取域名并批量解析-补字典爆破盲区
- **kind**: script
- **category**: info-leak
- **component**: 通用（Web 页面源码）
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.86 的 PHPWind 后台登录页实测：从 <input name="submit" type="image" src="http://example.com:1031/bbs/images/admin/login/login.gif"> 挖出域名 example.com，DNS 实测解析到 203.0.113.86（真实有效）。该域名前缀带随机后缀 9hrrz，148 词表子域爆破完全无法命中 —— 证明本方法能补字典爆破的盲区。同时据此纠正了前序「1031 端口只是 301 跳转」的错误结论（1031 是该 vhost 的正式站点端口）。
- **path**: pocs/页面源码挖自动生成-vhost-从-html-js-提取域名并批量解析-补字典爆破盲区/mine_hosts.py
- **tags**: recon,vhost,页面源码,自动生成域名,subdomain,方法论
- **created_at**: 2026-10-15T20:43:55.094Z
- **found_by**: recon

## 描述

从 Web 页面源码/JS 挖取域名与主机名并批量解析，专治字典爆破查不到的「自动生成 vhost」（前缀带随机后缀）；输出标出哪些真实解析

## 用法

```
python mine_hosts.py <url1> <url2> ...   # 或  python mine_hosts.py -f urls.txt
建议铺面步骤：
1) 先把已收站点的首页/登录页/后台页/JS 全部抓下来（含 .js / .css 里的硬编码 URL）
2) 跑本脚本 → 得到候选主机名
3) 看输出里标「真实解析」的那些 → 就是有效 vhost
4) 用 Host 头把每个域名打到对应 IP 上探站点（注意目标可能有通配 vhost，需先用随机域名测出基线尺寸做过滤）
需要替换: 目标 URL 列表；代理出口按环境显式设置。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 Web 页面源码/JS 中挖掘域名与主机名 —— 专治「自动生成 vhost」
比字典爆破强的地方：自动生成的 vhost 前缀常带随机后缀（如 655590com-9hrrz.xxx.top），
148 词表不可能命中，但站点自己的 HTML/JS/CSS 里会硬编码其绝对 URL。

用法:
    python mine_hosts.py <url1> [url2] ...            # 直接给 URL
    python mine_hosts.py -f urls.txt                  # 从文件读 URL 列表
可选: 环境变量 HTTP_PROXY / HTTPS_PROXY 控制出口（本环境需显式设置，勿依赖全局）
"""
import sys, re, socket, concurrent.futures as cf

# 只挖这些 TLD 有助于降噪（可按目标增删）
TLD_HINT = re.compile(r'\.(top|com|cn|net|org|shop|xyz|vip|club|site|online|store|icu|cc|me|info|biz|pro|wang|xin|ren|asia)\b', re.I)

PATTERNS = [
    r'https?://([A-Za-z0-9][A-Za-z0-9._-]{2,80})',        # http(s) 绝对 URL
    r'//([A-Za-z0-9][A-Za-z0-9._-]{2,80})/',              # 协议相对 URL
    r'(?<![A-Za-z0-9._-])([A-Za-z0-9][A-Za-z0-9-]{1,40}(?:\.[A-Za-z0-9-]{1,40}){1,4}\.(?:top|com|cn|net|org|shop|xyz|vip|club|site|online|store|icu|cc|me|info|biz|pro|wang|xin|ren|asia))',
    r'["\']((?:[A-Za-z0-9-]+\.)+(?:top|com|cn|net|org|shop|xyz|vip|club|site|online|store|icu|cc|me)[^"\']{0,40})["\']', # JS 字符串里的域名
]

def fetch(url, timeout=20):
    import urllib.request as u
    try:
        req = u.Request(url, headers={'User-Agent': 'Mozilla/5.0', 'Accept': '*/*', 'Connection': 'close'})
        with u.urlopen(req, timeout=timeout) as r:
            return r.read(3_000_000)
    except Exception as e:
        return b''

def mine(text):
    found = set()
    for p in PATTERNS:
        for m in re.finditer(p, text):
            h = m.group(1).split('/')[0].split(':')[0].strip('."\'').lower()
            if 4 < len(h) < 100 and '.' in h and TLD_HINT.search(h):
                if not h.replace('.', '').isdigit() and 'w3.org' not in h:
                    found.add(h)
    return found

def resolve(host):
    try:
        return socket.gethostbyname_ex(host)[2]
    except Exception:
        return None

def main(urls, workers=12):
    all_hosts = {}
    def one(u):
        b = fetch(u)
        if not b: return None
        txt = b.decode('utf-8', 'ignore') + b.decode('gbk', 'ignore')
        return (u, mine(txt))
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(one, urls):
            if r: all_hosts.setdefault(r[0], set()).update(r[1])
    merged = set().union(*all_hosts.values()) if all_hosts else set()
    print('从 %d 个页面挖到 %d 个候选主机名\n' % (len(urls), len(merged)))
    # 解析验证（关键：区分真解析 vs 死链）
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for host, ips in zip(sorted(merged), ex.map(resolve, sorted(merged))):
            flag = ('  ← 真实解析: %s' % ips) if ips else ''
            print('  %-56s%s' % (host, flag))
    print('\n提示：标出「真实解析」的就是有效 vhost，逐个用 Host 头去对应的 IP 上探站点即可。')

if __name__ == '__main__':
    args = sys.argv[1:]
    if args and args[0] == '-f':
        urls = [l.strip() for l in open(args[1]) if l.strip()]
    else:
        urls = args
    main(urls)
```
