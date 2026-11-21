# PHPWind 写 PHP 文件 sink 的三面叠加扫描法（数据来源分类 + 变量路径补扫）

- **code**: phpwind-写-php-文件-sink-的三面叠加扫描法-数据来源分类-变量路径补扫
- **kind**: script
- **category**: rce
- **component**: PHPWind 7.3.2 / 7.5SP3
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 PHPWind 7.3.2（runs/pw-admin-sinks/utf8/，492 php）实测：434 处写点，筛出「目标 .php + 内容含变量」97 处，与既有统计完全吻合；7.5SP3 全量独立复扫得 98 处（唯一差异是 lang/up_function.php:350 同源 medals_list），确认扫描面完整。变量路径补扫额外发现 lib/datanalysecache.class.php 一处此前从未评估的 fwrite 逐行拼 PHP 写点。零发包，纯本地源码分析。
- **path**: pocs/phpwind-写-php-文件-sink-的三面叠加扫描法-数据来源分类-变量路径补扫/pw-db-to-php-sink-scan.py
- **tags**: phpwind,白盒审计,sink扫描,写文件,数据来源分类,变量回溯
- **created_at**: 2026-10-06T22:25:20.405Z
- **found_by**: vuln-scan

## 描述

PHPWind 白盒找「DB/远程数据 → 写 .php 文件」sink 的三面叠加扫描法 + 变量赋值链回溯。核心洞察：按「内容含请求变量」分类会漏掉整类「内容含数据库字段/远程响应」的写点；按「路径字面量含 .php」过滤会漏掉 fopen($this->filepath)+fwrite 逐行拼 PHP 的写法。

## 用法

```
python pw-db-to-php-sink-scan.py  # 需按实际源码根目录改 ROOT；三面叠加后对命中项逐个做 audit() 变量回溯，未命中任何 ESCAPERS 的进人工判读
```

## 正文

```
#!/usr/bin/env python3
# 换分类维度：不看「内容是否含请求变量」，看「内容的数据来源」
# 来源A=请求变量(已判死) B=数据库字段/远程响应 ★本轮目标 C=配置缓存回读 D=常量
import os, re, json
ROOT = r"runs/pw-admin-sinks/utf8"
WRITE_FNS = ["writeover","file_put_contents","fwrite","fputs","fopen","rename","copy"]

def extract_calls(text):
    """括号平衡抓取，返回 [(lineno, func, argstring)]"""
    out = []
    for m in re.finditer(r'\b(' + '|'.join(WRITE_FNS) + r')\s*\(', text, re.I):
        i = m.end(); depth = 1; start = i; n = len(text); in_s = None
        while i < n and depth > 0:
            c = text[i]
            if in_s:
                if c == '\\': i += 2; continue
                if c == in_s: in_s = None
            else:
                if c in ('"',"'"): in_s = c
                elif c == '(': depth += 1
                elif c == ')':
                    depth -= 1
                    if depth == 0: break
            i += 1
        out.append((text.count('\n',0,m.start())+1, m.group(1), text[start:i]))
    return out

# 三个扫描面必须叠加，缺一漏类：
# ① writeover/file_put_contents 的路径参数【字面量】含 .php
# ② fopen+fwrite/fputs 的路径是【变量或方法调用】—— 例 $this->filepath、$this->getCacheFileName()
#    这类逃过所有「路径含 .php」的正则，是最大的盲区
# ③ rename/copy 顺带核对

# 变量赋值链回溯（递归 2-3 层），自动判定是否有转义函数
ESCAPERS = ['pw_var_export','db_cv','addslashes','addcslashes','key_cv',
            'pwEscape','intval','htmlspecialchars','preg_quote','strip_tags']
def audit(rel, expr, depth=0, seen=None, before_line=None, root=""):
    if seen is None: seen = set()
    if depth > 3: return set()
    found = set()
    lines = open(os.path.join(root, rel), encoding='utf-8', errors='replace').read().split('\n')
    for v in set(re.findall(r'\$([A-Za-z_]\w*)', expr)):
        if (rel, v) in seen: continue
        seen.add((rel, v))
        pat = re.compile(r'\$' + re.escape(v) + r'\s*\.?=\s*(?!=)')
        for i, ln in enumerate(lines):
            if before_line and i+1 > before_line: continue
            if pat.search(ln):
                found |= {e for e in ESCAPERS if e in ln}
                found |= audit(rel, ln.split('=',1)[-1], depth+1, seen, i+1, root)
    return found

```
