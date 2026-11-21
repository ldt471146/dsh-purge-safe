# Vite + javascript-obfuscator SPA：还原 chunk 映射表 / 字符串表反混淆 / 服务层接口全量提取

- **code**: vite-javascript-obfuscator-spa-还原-chunk-映射表-字符串表反混淆-服务层接口全量提取
- **kind**: script
- **category**: frontend-reverse
- **component**: Vite + javascript-obfuscator SPA
- **versions**: Vite 构建产物（__vite__mapDeps 形态）+ javascript-obfuscator 字符串数组混淆
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.25（CN7 CMS 3.1.5，Vue3+Vite SPA，44 个 chunk、其中 40 个被 javascript-obfuscator 混淆）实测打通：反混淆后 `__vite__mapDeps` 79 项 chunk 清单明文可见（原本只有 18 个包），迭代下载到 44 个 chunk；提取到 347 条接口（27 条为既有清单未覆盖的新增），并从字符串表里读出 3 把硬编码密钥（1024bit RSA 私钥 Tp、2048bit RSA 私钥 ph、CryptoJS AES 口令 Sp="6758725226829023"）；据此对真机验证了 RSA 加密口令可提交、服务端加密返回体可离线解密。全程无需登录态。
- **path**: pocs/vite-javascript-obfuscator-spa-还原-chunk-映射表-字符串表反混淆-服务层接口全量提取/vite_obfuscated_spa_audit.md
- **tags**: vite,webpack,chunk,javascript-obfuscator,反混淆,接口提取,SPA
- **created_at**: 2026-10-05T15:55:02.807Z
- **found_by**: vuln-scan

## 描述

从被 javascript-obfuscator 混淆的 Vite 构建产物里，还原完整 chunk 清单、全量接口表与硬编码密钥的通用方法。适用于任何 Vue3+Vite+obfuscator 的 SPA。

## 用法

```
把 deobf.py / extract_api.py / harvest3.py / probe_unauth.py 放到目标目录下，先 `python deobf.py <bundle>` 确认三段结构能被切出，再批量跑 deobf_all.py；换目标时只需改 BASE / UA / 目标目录常量。参数：DEOBF_OUT 环境变量控制落盘目录。
```

## 正文

```
# 一、还原 Vite chunk 映射表（拿到完整懒加载清单）
# Vite 把懒加载清单塞在 __vite__mapDeps(cD, cj = __vite__mapDeps, cC = cj['f'] || (cj['f'] = [ ... ]))
# 若被 javascript-obfuscator 混淆，数组元素会变成 dA(0xNNN)，必须先反混淆（见第二部分）。
python - <<'PY'
import re, posixpath
t = open('assets/js/index-XXXX.js', encoding='utf-8', errors='ignore').read()
i = t.find('__vite__mapDeps')
j = t.find('))=>', i)                       # 数组结束处
arr = re.findall(r'["\'`]([^"\'`]+\.(?:js|css))["\'`]', t[i:j])
print(len(arr), arr)
PY

# 二、反混淆（javascript-obfuscator 字符串数组）
# 结构固定为三段：旋转 IIFE + 数组函数 + 解码器函数
#   const dA=C;(function(a,b){...}(c,0xKEY));   ← 旋转，末尾 (c,0xKEY) 里的 c 就是数组函数名
#   function c(){const X=[...]; c=function(){return X;}; return c();}
#   function C(U,D){U=U-0x108; ... decodeURIComponent ...}
# 做法：括号配平切出这三段，拼成一个 node 脚本求值，导出 index→明文全表：
#   const out={}; for(let i=OFF;i<OFF+4000;i++){try{const s=C(i); if(s) out[i]=s;}catch(e){}}
#   require('fs').writeFileSync('strmap.json', JSON.stringify(out));
# 再把正文里「标识符(0xNNN)」且 NNN 落在 [OFF, OFF+4000) 的调用原地替换成 JSON 字符串。
# ⚠ 别名不要靠变量名猜（同一文件里 `C3` 既可能是解码器别名也可能是组件名），
#    只用「被调用 + 实参是裸十六进制字面量」这一语法特征筛选。
python runs/js-audit/deobf.py assets/js/index-XXXX.js
node strmap.json.js
python runs/js-audit/deobf_all.py            # 批量：替换 + js-beautify 落盘

# 三、迭代抓全 chunk（关键：相对路径要按该 chunk 的真实部署目录归一化）
# 每个 chunk 自己的 import 是 "./x.js" / "../x.js"，基准目录 = 该 chunk 在 assets/ 下的真实位置。
# 注意 1：不要把 "node_modules/..." 的开发期源码路径当成线上资源去请求（会返回 SPA 兜底 HTML）。
# 注意 2：用文件名前缀判断部署目录（assets_js_chunks_* → assets/js/chunks），
#         不要用「文件名里的 _ 还原成 /」——chunk hash 本身可能含下划线（如 index-BZ_OFUDy.js）。
python runs/js-audit/harvest3.py             # 迭代到没有新 chunk 为止

# 四、从服务层常量表还原接口 + HTTP 方法
# CN7 模式：x(Cls,"name","/api/...")   ← x = Object.defineProperty，Cls 是服务类
#           class X extends pn { foo(t){ return this.requester.post(Cls.name, t) } }
# 两次正则求交集 → 路径 + 动词 + JS 方法名
python runs/js-audit/extract_api.py

# 五、无 token 鉴权探测（401 语义 = 被网关拦；其余码 = 穿过网关直达业务层）
python runs/js-audit/probe_unauth.py

```
