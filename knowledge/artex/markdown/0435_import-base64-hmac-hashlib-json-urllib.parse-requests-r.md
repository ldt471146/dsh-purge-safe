# 七牛云 Kodo AK/SK 接管验证与桶枚举（QBox 签名保留 base64 填充）

- **code**: import-base64-hmac-hashlib-json-urllib.parse-requests-r
- **kind**: script
- **category**: unauthorized
- **component**: Qiniu Kodo
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 靶标 example.com 的 sys_config.CLOUD_STORAGE_CONFIG_KEY 泄露 AK/SK 后实测：/buckets 返回 200 ["app-zh","im-yg"]；/bucket/im-yg 返回 private:0、uid:1382817524、zone:z2；rsf.qbox.me/list 列出 373 个租户前缀；upload-z2.qiniup.com 上传探针 200 返回 hash 且 CDN 匿名 200 可读，/delete 200 后 CDN 404。签名去掉 base64 填充时返回 401 {"error":"bad token","error_code":"BadToken"}。
- **tags**: qiniu,kodo,cloud,aksk,object-storage,info-leak
- **created_at**: 2026-10-19T20:18:47.032Z
- **found_by**: internal

## 描述

拿到七牛 AccessKey/SecretKey 后如何只读确认身份与权限：/buckets 列空间、/bucket/<name> 看 private/uid/zone、rsf.qbox.me/list 列对象。关键坑：Authorization 的 urlsafe base64 必须保留 '=' 填充，去掉填充会 401 BadToken。写权限用 upload_token 上传探针对象后 /delete 回滚验证。适配场景：源码/配置/数据库 sys_config 里露出的 qiniuAccessKey/qiniuSecretKey。

## 用法

```
1) 填 AK/SK 跑 /buckets 判身份；2) /bucket/<name> 看 private 与 uid；3) rsf.qbox.me/list 按租户前缀枚举；4) 需要证明写权限时上传 zz_probe.txt 验证后立即 /delete 回滚。管理凭证签名串 = path[?query] + "\n"，POST 带 body 时再追加 body。
```
