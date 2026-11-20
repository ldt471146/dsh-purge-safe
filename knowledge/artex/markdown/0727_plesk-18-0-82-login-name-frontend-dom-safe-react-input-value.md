# Plesk 18.0.82.2 登录页 login_name 前端 DOM 消费为安全赋值：React 受控 input value，无 DOM 型 XSS（前端侧封口）

- **code**: plesk-18-0-82-login-name-frontend-dom-safe-react-input-value
- **kind**: poc
- **category**: app-audit
- **component**: Plesk Obsidian 18.0.82.2 (sw-cp-server + @plesk/ui-library 3.4x)
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 直连 mail.goffsgames.co.uk:443（Let's Encrypt CN=YR1, server2.visionhost.co.uk）：live main.js sha256 与本地副本一致；/ui-library/plesk-ui-library.min.js 200/687040B + .map 200/1966702B（281 源文件）。链：Plesk.run data.values → LoginPage values → ui-library FormFieldText `value: getValue('')` → Input `<input {...props}>`，无 innerHTML/dangerouslySetInnerHTML。登录页唯一可达 sink Form.tsx:348（statusMessages）实测仅接收静态文案：AJAX 失败登录 POST 返回 {"status":"error","statusMessages":[{"content":"Incorrect username or password. Try again."}]}，载荷 `"><svg/onload=alert(9)>` 0 次回显。ui-library 全源 sink 仅 Translate(unsafe 选开)/Markdown(登录路径不引用)，Plesk 525 源 unsafe 0 命中。
- **created_at**: 2026-11-11T22:23:52.975Z
- **engine**: https://mail.goffsgames.co.uk/login_up.php

## 用法

```
判据（后人不重复走）：(1) 不要再用“服务端是否转义 <”判断 Plesk 登录页 XSS 面——正确判据是前端消费链：main.js.map 里 LoginPage.js `values={values}` → ui-library FormFieldText `value: getValue('')` → Input 的 React value 属性即安全；(2) 登录页唯一可达 HTML sink 是 components/Form.tsx:348 statusMessages 的 dangerouslySetInnerHTML，其数据只来自服务端 pageData.status 与 AJAX 响应 statusMessages/message，实测为静态英文文案、不反射 login_name；要证伪应构造能让服务端把输入回传进 status/message 的响应（本目标不存在）；(3) 残余线索：同一 sink 的 catch 分支经 jsw/showInternalError.js 会把错误 JSON 的 kbArticleUrl 未转义拼进 <a href>，若某预认证接口能回传攻击者可控 JSON 错误消息则可升级 DOM XSS，可在其它预认证表单页复核。
```
