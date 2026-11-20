# obfuscator.io 字符串数组还原 + 前端 AES 密钥派生还原（Vite/Vue SPA 通用）

- **code**: obfuscator.io-字符串数组还原-前端-aes-密钥派生还原-vite-vue-spa-通用
- **kind**: script
- **category**: frontend-reverse
- **component**: Vite/Vue SPA + obfuscator.io + CryptoJS
- **versions**: obfuscator.io（字符串数组 + RC4 变体 + 数组重排）
- **severity**: high
- **language**: js
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.21（203.0.113.45 的真实后端）上验证：还原出 Xl="thanks,pig4cloud" 并用 AES-ECB 成功解密 https://203.0.113.45/cocos/config_data.json（5464 字节 base64 密文 → 4080 字节明文），解出完整后端基础设施清单（api_domain 7 个、oss/h5/web 域名 15 个、siteCode=1202、阿里云 OSS 加速桶、AWS S3 桶、Telegram botId）。另还原出 EN(token)=md5(token+md5(token))[:16] 密钥派生与 AES-CBC/ZeroPadding 请求加密管线，实测加密 payload 可被 /hall/api/member/* 正常受理（服务端已进入参数校验层，不再 403）。
- **path**: pocs/obfuscator.io-字符串数组还原-前端-aes-密钥派生还原-vite-vue-spa-通用/deobfuscate-io-string-array.js
- **tags**: obfuscator.io,JS混淆还原,RC4,字符串数组,AES,CryptoJS,前端加密,配置解密
- **created_at**: 2026-10-03T13:33:19.335Z
- **found_by**: recon

## 描述

obfuscator.io 字符串数组混淆的还原方法（含 RC4 解码器提取、数组重排 IIFE 必须保留、参数序反推）与目标前端 AES 密钥/算法还原套路；附 AES-ECB 解密配置下发文件的通用做法。

## 用法

```
node deobfuscate-io-string-array.js <bundle.js>
1) 脚本自动切出 [数组重排IIFE] + [function Sa] + [function $d] 生成 _decoder.js
2) 用 Sa(k+768, key) 按数组下标取值；Ht(e,t)=Sa(e+877,t) 对应源码里的调用
3) 若解出乱码 → 数组重排 IIFE 没提取到，或参数序写反（o(a,r)=Sa(r-79,a)）
4) 还原出密钥后：AES-CBC+ZeroPadding (iv 常见为纯数字字符串) 处理 api 请求体；
   AES-ECB 处理 oss 模式的下发配置文件
```

## 正文

```
#!/usr/bin/env node
/*
 * obfuscator.io 字符串数组还原器
 * 原理：bundle 把字符串放进数组 $d()，用 RC4 变体函数 Sa(e,t) 按索引解密，
 *       并由一个 IIFE 重排数组顺序（顺序错则解出乱码）。
 * 正确做法：把 [重排IIFE] + [function Sa] + [function $d] 三段原样提取出来，
 *          在 Node 里 require 执行，让混淆代码自己解自己。
 */
const fs = require("fs");

// —— 第 1 步：定位三个片段的边界 ——
const src = fs.readFileSync(process.argv[2], "utf8");
const i_sa       = src.indexOf("function Sa(e,t)");              // 解码器
const i_shuffle  = src.lastIndexOf("(function(e,t){", i_sa);     // 数组重排 IIFE
const i_d        = src.indexOf("function $d()", i_sa);           // 字符串数组
const i_dend     = src.indexOf("$d()}", i_d) + 4;

const out = [
  src.slice(i_shuffle, i_sa),      // 重排 IIFE（必须包含，否则数组顺序错误）
  src.slice(i_sa, i_d),            // Sa
  src.slice(i_d, i_dend),          // $d
  "module.exports={Sa,$d};",
].join("\n");
fs.writeFileSync("./_decoder.js", out);

// —— 第 2 步：调用约定 ——
// 源码中的包装函数形式各异，先反推出真实调用：
//   Ht(e,t)   => Sa(e+877, t)
//   o(a,r)    => Sa(r-79,  a)     （注意参数序相反！）
//   n(o,a)    => Ht(o-163,a)
// 关键：Sa 内部第一件事是 e = e - 768，所以「想取数组下标 k」= Sa(k+768, key)
const { Sa } = require("./_decoder.js");
function Ht(e, t) { return Sa(e - -877, t); }

// —— 第 3 步：批量还原 ——
// 从目标类/函数的源码片段里正则抓所有 Ht(数字,"key") 调用并解码
const seg = src.slice(src.indexOf("class xN"), src.indexOf("class xN") + 1600);
for (const c of seg.matchAll(/Ht\((-?\d+)\s*,\s*"([^"]*)"\)/g)) {
  console.log(c[0], "=>", JSON.stringify(Ht(parseInt(c[1]), c[2])));
}

/* ================= 实战产出（某博彩平台 lobby 前端） =================
 * 还原出的加密类 xN 全部密钥：
 *   getSK()  mm = "tgJt2ol!^E" + ")E8(%P"                  => tgJt2ol!^E)E8(%P
 *   IV       Ql = "5421698523" + "412578"                   => 5421698523412578
 *   oss 密钥 Xl = atob("dGhhbmtzLHBpZzJjbG91ZA==")          => thanks,pig4cloud
 *   RK       gm = "fc361cdb77"+"0aebc2126c"+"c0dac989c8"+"96"
 * 加密算法：
 *   encrypt(data,key) = AES-CBC + ZeroPadding, iv=Ql, 输出 base64
 *   ossDecrypt(ct)    = AES-ECB, key=Xl       ← 用它解开了 /cocos/config_data.json
 * 密钥派生 gk(token, a, username, keyType)：
 *   k1: EN(token)        = md5(token + md5(token)).slice(0,16)     // md5hex 小写
 *   k2: UN(token,user)   = md5(token + username).slice(0,16)
 * 请求体：{"encryptString":"<base64>"}
 */

/* ================= 附带产出：AES-ECB 解密配置下发文件 =================
 * import base64; from Crypto.Cipher import AES
 * ct = base64.b64decode(open("config_data.json").read().strip())
 * pt = AES.new(b"thanks,pig4cloud", AES.MODE_ECB).decrypt(ct)
 * pt = pt[:-pt[-1]] if 0 < pt[-1] <= 16 else pt
 * // 解出明文含 api_domain / oss_domain / h5_domain / siteCode 等完整基础设施清单
 */

```
