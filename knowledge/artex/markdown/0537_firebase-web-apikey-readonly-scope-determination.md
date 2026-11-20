# Firebase Web apiKey 只读验活与「可达服务面」判定法（FIS/RemoteConfig 可用 vs Firestore/Auth/RTDB/Storage 不可达）

- **code**: firebase-web-apikey-readonly-scope-determination
- **kind**: template
- **category**: methodology
- **component**: Firebase / Google Cloud API key (web client)
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 fanatical.com task#5 实测：前端 bundle 内嵌 Firebase web 配置（apiKey AIzaSyB7L...Slfo，project 4251474956 / iterable-webpush-prod）。无效 key 对照 translation→400 API_KEY_INVALID；本 key→403 API_KEY_SERVICE_BLOCKED consumer=projects/4251474956（有效）。POST firebaseinstallations .../projects/iterable-webpush-prod/installations（X-Goog-Api-Key+真实 appId）→HTTP 200 返回 FID/refreshToken/签名 authToken(JWT,projectNumber:4251474956)。RemoteConfig firebase:fetch→200 {"state":"NO_TEMPLATE"}。Firestore 带 key→403 ACCESS_DENIED / 匿名→403 SERVICE_DISABLED；Identity Toolkit→400 CONFIGURATION_NOT_FOUND；RTDB 各区域名→404；Storage 桶→404 NoSuchBucket；FCM send/Management→401 需 OAuth。结论落 fact#689(confirmed)/finding#74(node 691)。
- **created_at**: 2026-11-11T15:01:26.149Z
- **engine**: https://www.fanatical.com

## 用法

```
给任何从源码/前端 bundle 挖到 `AIza…` key 的场景用。全部只读、无写、不产生数据面调用。
1) 取配置：grep bundle 找 `"firebase":{...}` 或 `AIzaSy[A-Za-z0-9_-]{33}`；记下 apiKey/appId/projectId/messagingSenderId。
2) 验活+解析项目号（对照法，最稳）：
   curl -s "https://translation.googleapis.com/language/translate/v2/languages?target=en&key=<K>"
   本key→403 reason=API_KEY_SERVICE_BLOCKED + metadata.consumer=projects/<编号>（有效，带 API 级限制）；无效key→400 reason=API_KEY_INVALID。books/googleapis 常见返回 403 SERVICE_DISABLED(带 project id)。
3) 逐服务只读判定可达面（带 key，必要时带 X-Goog-Api-Key 头）：
   · FIS（写但无副作用，可丢弃）：POST firebaseinstallations.googleapis.com/v1/projects/<proj>/installations，头 X-Goog-Api-Key:<K>，体 {"appId":"<真实appId>","authVersion":"FIS_v2","fid":"<22位base64url>","sdkVersion":"w:0.6.0"} → 200=可用（得 authToken）；400 INVALID_ARGUMENT=appId 格式/不匹配。
   · RemoteConfig client：POST firebaseremoteconfig.googleapis.com/v1/projects/<proj>/namespaces/firebase:fetch?key=<K> {"appInstanceId":"..","appId":".."} → 200 {"state":"NO_TEMPLATE"} 或模板。
   · Firestore：POST firestore.googleapis.com/v1/projects/<proj>/databases/(default)/documents:listCollectionIds?key=<K> {} → 403 ACCESS_DENIED=key 级封死；去 key 匿名 → 403 SERVICE_DISABLED=API 未启用；两者对比可区分“未启用” vs “key 不允许”。
   · Auth/Identity Toolkit：POST identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=<K> → 400 CONFIGURATION_NOT_FOUND=未配置；否则会回 EMAIL_NOT_FOUND/INVALID_PASSWORD（=可做账号枚举 oracle）。
   · RTDB：GET https://<proj>.firebaseio.com/.json 与 <proj>-default-rtdb[.<region>].firebasedatabase.app/.json → 404=无库；200 且返回 JSON=开放规则（高危）。
   · Storage：GET firebasestorage.googleapis.com/v0/b/<bucket>/o 与 storage.googleapis.com/<bucket>/?list-type=2 → 404 NoSuchBucket=不存在；200 列表=公开列举。
   · FCM：POST fcm.googleapis.com/v1/projects/<proj>/messages:send → 401 CREDENTIALS_MISSING（API key 不能发，需 OAuth 服务端凭据）。
4) 结论口径：Firebase web 配置按设计即公开，单凭 apiKey 不算漏洞；只有「某服务返回数据/可写」才算成果。典型可打点：RTDB/Firestore/Storage 的开放规则、Auth 的账号枚举、无 App Check 时可被资源滥用的 FIS/FCM 注册面。
坑：Firebase Installations 的 POST 必须用真实 appId（1:<项目号>:web:<hash>）；GET 该路径是 404，别误判；firebaseappcheck v1beta 路径易 404。
```
