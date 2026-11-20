# club-upload 未授权任意图片上传 + AES-ECB 响应解密（密钥 7EGWY67N31RFK7GY）+ FastDFS 落地回读

- **code**: club-upload-未授权任意图片上传-aes-ecb-响应解密-密钥-7egwy67n31rfk7gy-fastdfs-落地回读
- **kind**: poc
- **category**: unauthorized
- **component**: example.com /club/upload
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-03 在 example.com/club/upload 实测：filename=vs_probe_1.png 上传返回 code:200；data 用 AES-ECB(key=7EGWY67N31RFK7GY) 解出 {"fileUrl":"/group1/M00/1A/87/ooYBAGrAvK-Ea0M8AAAAAAeVpCY975.png","fileHttpUrl":"https://target157.example.com/group1/M00/1A/87/ooYBAGrAvK-Ea0M8AAAAAAeVpCY975.png",...}；GET 该 URL 返回 200 image/png 70 字节，sha256 c414cd0e204de974f73753c7e28d7638… 与上传的原始 1x1 PNG 完全一致。无需任何鉴权。
- **tags**: unauthorized-upload,file-storage,fastdfs,aes-ecb,frontend-key-recovery,target158.example.com,livelive888
- **created_at**: 2026-10-03T09:07:40.675Z
- **found_by**: vuln-scan

## 描述

example.com 的 /club/upload 接口无任何鉴权（无 token / 无签名 / 无 Cookie）即可上传文件。响应的 data 字段是 AES-128-ECB/Pkcs7 加密的 JSON，密钥是前端 app.*.js 中 window.yunweiConfig.aesKey 的硬编码默认值 7EGWY67N31RFK7GY —— 这把钥匙不在任何已泄露的密钥里，必须从前端源码逆出。解密后得到 FastDFS 落地路径，回静态域 target157.example.com 可匿名读回，字节完全一致。扩展名白名单按最后一段扩展名判定，存储路径与文件名全部由 FastDFS 服务端生成，攻击者不可控，因此该接口无法升级为 RCE。

## 用法

```
python club_upload_unauth.py

依赖：requests + pycryptodome。本机环境代理会把 200 变 403，必须 s.trust_env = False。
该接口有频控：连续上传约 7 次后端转持续 500，测试上传务必间隔 >= 5s。
支持的场景：只要能确定一把前端 cryptoKey/aesKey 就能套用同样的 AES-ECB 解密套路去读任意
同类 uploadUrl 的加密响应。
```
