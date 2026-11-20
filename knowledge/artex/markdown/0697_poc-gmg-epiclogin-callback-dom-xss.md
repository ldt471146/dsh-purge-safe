# AngularJS base64Service.decode(UTF-16LE) returnUrl 直接赋值 location 导致 DOM XSS 与开放重定向（GMG EpicLoginCallback）

- **code**: poc-gmg-epiclogin-callback-dom-xss
- **kind**: poc
- **category**: app-audit
- **component**: AngularJS / EPiServer
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 21:23 UTC 真实 Chrome 157 + CDP，注入任务自有账号登录态后打开 base64(UTF-16LE(javascript:...)) 的 returnUrl：title 变为 XSSPWN_gmge4auwupl，XSRF-TOKEN 被读取，GET /api/v2/user_info 200（traffic 1794432204-3055），POST /api/v2/update_dateOfBirth 204（1794432205-3056），账号数据外带到 127.0.0.1:18080 成功。
- **tags**: dom-xss,angularjs,open-redirect,utf-16le,base64,episerver
- **created_at**: 2026-11-11T21:24:53.420Z
- **engine**: https://www.greenmangaming.com/Account/EpicLoginCallback

## 描述

前端把查询参数交给 base64Service.decode（atob 后按 Uint16Array 解释，即 base64(UTF-16LE)），解码结果不做 scheme/origin 校验直接赋给 window.location。javascript: URI 在同源执行；https URL 即开放重定向。边缘对回调 URL 有约 2KB 长度阈值（1999B→200，2259B→404），payload 需压缩。

## 用法

```
1) 定位 controller：grep "base64Service.decode" main.js；2) python: base64.b64encode(js.encode('utf-16-le')) 再 urllib.parse.quote(...,safe='')；3) 受害者登录态浏览器打开 URL；4) JS 内读 document.cookie 的非 HttpOnly XSRF-TOKEN，带 X-XSRF-TOKEN 调 /api/v2/*。复现脚本：/opt/artex/data/sessions/conv-435/{mkurl2.py,xss_final.py}
```
