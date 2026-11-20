# 执行式去混淆：伪装运行环境跑混淆脚本，直接读回 window 配置（通用手法）

- **code**: 执行式去混淆-伪装运行环境跑混淆脚本-直接读回-window-配置-通用手法
- **kind**: script
- **category**: info-leak
- **component**: 6686 博彩集团前端（rc4 变体混淆 + Spring Boot 网关 + Cloudflare）
- **versions**: 适用于「字符串表 + _0xXXXX(idx) 索引解密」形态的前端混淆（常见于 obfuscator.io 输出）
- **severity**: high
- **language**: js
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（203.0.113.80:443，openresty 203.0.113.7 + Cloudflare）实测通过：首页 54503 字节，取含 _0x23ce7e 解密表的 32398 字节 script 块，截断到 window[_0x599bf4(0x162)]={...}; 结束，用 new Function 注入假环境执行，一次还原出 window._env_ 全部 90+ 字段——含 24 个后端服务 URL（PLATFORM_API_URL / LOTTERY_API_URL=…/ig-lottery/adminapi / SPORT_API_URL / IM_API_URL / SSO_URL / 3 个 S3 预签名桶）、148 个 Android 包名（AN_IDS）、业务标识（shortBrandName=6686、VENDERID=vd004、DEPLOY_ENV=prod）
- **path**: pocs/执行式去混淆-伪装运行环境跑混淆脚本-直接读回-window-配置-通用手法/run_obfuscated_script.js
- **tags**: 前端混淆,去混淆,rc4,字符串表,node,配置泄露,6686
- **created_at**: 2026-10-05T07:57:47.636Z
- **found_by**: exploit

## 描述

绕过前端字符串表混淆的通用手法：不静态去混淆，而是伪装 window/document/navigator 运行环境、把混淆脚本原样执行一遍，让它自己填充全局配置对象，然后直接读明文。实测在 6686 博彩集团门户上一把还原出 24 个后端服务地址 + 148 个 App 包名。

## 用法

```
node run_obfuscated_script.js
前置：把目标首页保存为 example.com（同目录）
适用：前端用「字符串表 + 索引解密函数」形态混淆、且把配置挂在 window 上的站点
要点：① 挑最长的含解密表的 script 块；② 截断到 window[...]={} 结束；
      ③ 用 new Function 注入假 window/document/navigator；④ 返回 window 读明文
依赖：无需任何 npm 包（纯 Node 内置）
```

## 正文

```
// 在 Node 里执行页面混淆脚本，还原被混淆的 window 全局配置
//
// 【原理】
// 这类前端用「字符串表 + 索引解密函数」形态混淆（_0x599bf4(idx) / _0x232979(idx,'key')），
// 底层是标准 rc4/xxtea 变体。但它们**必须在页面里执行**才能拿到明文 ——
// 所以最省事的做法不是静态去混淆，而是**伪装运行环境、把脚本原样跑一遍**，
// 让它自己把 window 配置对象填好，然后直接读对象。
//
// 【实测】example.com 首页 54503 字节，一次跑通还原出 window._env_ 全部 90+ 字段
//        含 24 个后端服务地址（含彩票 adminapi）、148 个 App 包名、3 个 S3 桶
//
const fs = require('fs');

const html = fs.readFileSync('example.com', 'utf8');

// 1. 抓出所有 <script> 内联块，挑最长的（含解密表与解密函数的那块）
const blocks = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
let code = blocks.filter(b => b.includes('_0x23ce7e') || b.includes('_0x8d4bd5'))
                .sort((a, b) => b.length - a.length)[0]
           || blocks.sort((a, b) => b.length - a.length)[0];

// 2. 只保留到 window[...]={...} 配置对象结束（去掉后面的 DOM 操作，避免报错）
const idx = code.indexOf('window[_0x');
if (idx > -1) {
  const end = code.indexOf('};', idx);
  code = code.slice(0, end > -1 ? end + 2 : code.length);
}

// 3. 造假运行环境，把脚本原样跑一遍，读回 window
const sandbox = {
  window: {}, document: { head: {}, body: {} },
  navigator: { userAgent: 'node' }, console,
};
const fn = new Function('window', 'document', 'navigator', 'console',
                        code + '\n;return window;');
const w = fn(sandbox.window, sandbox.document, sandbox.navigator, console);

// 4. 打印还原结果
for (const [k, v] of Object.entries(w)) {
  if (v && typeof v === 'object') {
    console.log('\n[' + k + ']');
    for (const [k2, v2] of Object.entries(v)) console.log('   ' + k2 + ' = ' + v2);
  } else {
    console.log(k + ' = ' + v);
  }
}

```
