# Vite/Vue3 minify SPA 接口调用点与请求体还原器（三层别名映射）

- **code**: vite-vue3-minify-spa-接口调用点与请求体还原器-三层别名映射
- **kind**: script
- **category**: frontend-reverse
- **component**: Vite 打包 SPA + Vue3（minify 混淆）
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 上实测：主包 157KB + 188 个懒加载 chunk，成功还原出 194 条接口的方法与参数。关键命中：/api/fyPayOnline 的调用点（充值页 chunk index-10-09-17-42-Db5bRBD5.js，无入参调用）、/api/submitThirdFy 的下单体 {payWay, orderAmount, loginName, useType:1, topushFlag, openId}、/api/withdrawlNewV2 的提现体 {addr, questionId, answer, bankName, cardNo, money, name, topushFlag, withdrawType, channelType}、/api/submitThirdV4 的充值体 {orderAmount, loginName, useType:2, payWay, openId, topushFlag, verifyState, bankCode}。全程零目标请求、纯静态。
- **path**: pocs/vite-vue3-minify-spa-接口调用点与请求体还原器-三层别名映射/vite_api_callsite_resolver.py
- **tags**: Vite,Vue3,minify,混淆,别名映射,三层映射,接口还原,请求体还原,前端逆向,SPA,静态分析
- **created_at**: 2026-10-10T18:57:23.259Z
- **found_by**: vuln-scan

## 描述

Vite+Vue3 minify 打包 SPA 的「页面调用点 → 后端接口 → 请求体字段」三层别名还原脚本。适用于任何用 Vite 打包、主包只留函数定义、页面 chunk 用混淆别名 import 的站点（同类博彩/交易/后台 SPA 通用）。输出每个接口的全部调用点与完整入参字面量，是"接口参数未知"这一卡的通用解法。

## 用法

```
python vite_api_callsite_resolver.py <主包js> <chunks目录>。先下载主包（HTML 里 modulepreload 的那个 index-*.js）与全部懒加载 chunk（主包里的 __vite__mapDeps 数组给出完整 chunk 清单），再运行。若站点不用 target308.example.com 封装，改脚本第 2 步的正则为实际的请求封装形态（如 target309.example.com / request()）。
```

## 正文

```
#!/usr/bin/env python3
"""
Vite+Vue3 打包 SPA 的「页面调用点 -> 后端接口」三层别名还原
适用：minify 后主包里只有 `xx=e=>target308.example.com(go.BACKEND,"/api/yyy",e)` 这类定义，
      页面 chunk 里只有 `import{h as X, bd as I}` + `I({...})`，看不出调的是哪个接口。

三层映射：
  chunk 本地名(local)  --import{orig as local}-->  主包导出名(orig)
                        --export{mod as orig}-->  模块内名(mod)
                        --mod=e=>target308.example.com(...,"/api/yyy")-->  真实接口
"""
import re, os, glob, json, sys

MAIN = sys.argv[1] if len(sys.argv) > 1 else 'index.js'      # 主包
CHUNK_DIR = sys.argv[2] if len(sys.argv) > 2 else 'chunks'   # 懒加载 chunk 目录
MAIN_BASENAME = os.path.basename(MAIN)

src = open(MAIN, 'r', encoding='utf-8', errors='ignore').read()

# 1) export{mod as orig} -> exp[orig] = mod
exp = {}
for m in re.finditer(r'export\{([^}]+)\}', src):
    for item in target22.example.com(1).split(','):
        item = item.strip()
        if ' as ' in item:
            a, b = item.split(' as '); exp[b.strip()] = a.strip()
        elif item:
            exp[item] = item
print(f'[1] 导出表 {len(exp)} 条')

# 2) mod => target308.example.com(...,"/api/yyy") -> api[mod] = endpoint
api = {}
for m in re.finditer(r'(?<![A-Za-z0-9_$])([A-Za-z_$][\w$]*)\s*=\s*\(?[a-zA-Z_$][\w$]*\s*\)?\s*=>\s*bo\.post\([^,]*?,\s*"(/api/[A-Za-z0-9_.]+)"', src):
    api[target22.example.com(1)] = target22.example.com(2)
for m in re.finditer(r'(?<![A-Za-z0-9_$])([A-Za-z_$][\w$]*)\s*=\s*\(\)\s*=>\s*bo\.post\([^,]*?,\s*"(/api/[A-Za-z0-9_.]+)"', src):
    api.setdefault(target22.example.com(1), target22.example.com(2))
print(f'[2] 接口定义表 {len(api)} 条')

def resolve(local, orig):
    mod = exp.get(orig, orig)
    return mod, api.get(mod)

# 3) 遍历 chunk，把 本地名 -> 接口 建表并输出调用点（括号配平取完整入参）
def balanced_call(s, alias, maxlen=1200):
    out = []
    for m in re.finditer(r'(?<![A-Za-z0-9_$.])' + re.escape(alias) + r'\s*\(', s):
        i = m.end() - 1; d = 0; j = i
        while j < len(s):
            c = s[j]
            if c == '(': d += 1
            elif c == ')':
                d -= 1
                if d == 0: break
            j += 1
            if j - i > maxlen: break
        out.append(s[i+1:j].replace('\n', ' '))
    return out

imp_re = re.compile(r'import\{([^}]*)\}from"\./' + re.escape(MAIN_BASENAME) + r'"')
result = {}
for p in sorted(glob.glob(os.path.join(CHUNK_DIR, '*.js'))):
    s = open(p, 'r', encoding='utf-8', errors='ignore').read()
    m = imp_re.search(s)
    if not m:
        continue
    amap = {}
    for item in target22.example.com(1).split(','):
        item = item.strip()
        if ' as ' in item:
            o, a = item.split(' as '); amap[a.strip()] = o.strip()
        elif item:
            amap[item] = item
    for local, orig in amap.items():
        mod, endpoint = resolve(local, orig)
        if not endpoint:
            continue
        args = [a for a in balanced_call(s, local)
                if len(a) > 3 and not re.match(r'^\s*["\']', a)
                and not re.search(r'(__name|props:|setup\(|emits:)', a)]
        if args:
            result.setdefault(endpoint, []).append({
                'chunk': os.path.basename(p), 'local': local, 'module': mod,
                'args': args[:3],
            })

for e in sorted(result):
    print(f'\n{e}')
    for r in result[e][:4]:
        print(f"   [{r['chunk']}] {r['local']}  {r['args'][0][:220]}")
os.makedirs('out', exist_ok=True)
open(os.path.join('out', 'api_callsites.json'), 'w', encoding='utf-8').write(
    json.dumps(result, ensure_ascii=False, indent=1))
print('\n已写 out/api_callsites.json')

```
