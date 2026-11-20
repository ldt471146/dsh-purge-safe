# GCP API key 只读验活与「服务面/限制类型」判定法（API_KEY_HTTP_REFERRER_BLOCKED vs API_KEY_SERVICE_BLOCKED vs API not activated）

- **code**: gcp-api-key-只读验活与-服务面-限制类型-判定法-api_key_http_referrer_blocked
- **kind**: template
- **category**: methodology
- **component**: Google Cloud / Maps Platform API key
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 在 fanatical.com task#5 实测：AIzaSyBPy…1LgU（GCP project 176949976113）：带 Referer: https://www.fanatical.com/ 打 places.googleapis.com/v1/places:searchText → 403 reason=API_KEY_SERVICE_BLOCKED；同请求去掉 Referer → 403 reason=API_KEY_HTTP_REFERRER_BLOCKED；Referer: https://evil.com/ → 仍 HTTP_REFERRER_BLOCKED（白名单锁定 fanatical.com）；Geocoding/Elevation/Static Maps → "API not activated"；legacy Places → "API keys with referer restrictions cannot be used with this API"；Translate/YouTube/Books/CustomSearch → 403 "Requests to this API … blocked"。maps/api/js loader 对任意/空 Referer 均 200。结论落 fact#640。
- **created_at**: 2026-11-11T14:53:58.083Z
- **engine**: https://www.fanatical.com

## 用法

```
拿到 AIza… key 后按 5 类错误判定真身，全部只读、不产生数据面调用：
1) 身份/项目：任意 Maps 数据端点返回 403 时看 details.metadata.consumer = "projects/<编号>"，即 key 所属 GCP 项目号。
2) 限制类型三判据（同一请求改 Referer 头即可区分）：
   · reason=API_KEY_HTTP_REFERRER_BLOCKED → key 绑 HTTP referer；白名单可用 Referer: https://<目标域>/ 猜/校（换别的域仍 blocked 即锁定该域）。⚠️ referer 校验只看请求头，curl 可伪造 → 限制型 key 在服务端同样可用（对白名单域内的服务面而言）。
   · reason=API_KEY_SERVICE_BLOCKED / message "Requests to this API <svc> … are blocked" → key 的 API 级限制不含该服务（真正封死数据面的一层，伪造 Referer 无用）。
   · message "This API is not activated on your API project" / "has not been used in project … before" → 服务未启用。
   · legacy Maps（maps/api/place/*、geocode 等）遇 referer 限制型 key 一律 REQUEST_DENIED "API keys with referer restrictions cannot be used with this API"。
3) 判定服务面（带伪造 Referer 逐个打）：maps/api/js（loader，免费无数据面）、places.googleapis.com/v1/places:searchText|autocomplete、routes.googleapis.com/directions/v2:computeRoutes、geocode.googleapis.com/v4、translation.googleapis.com、youtube/v3、books/v1、customsearch/v1、drive/v3。
4) 结论口径：只有「服务端可调 且 返回数据」的端点才算可利用；Maps JS loader 命中不算成果。仅当某数据 API 通过 API 级限制并返回数据时，才是有效的云凭据滥用。
常见坑：env 里 key 名（gcp.placesPublicKey）不代表真被授权调 Places；referer 限制 ≠ 服务端不可用；API 级限制才是硬门。
```
