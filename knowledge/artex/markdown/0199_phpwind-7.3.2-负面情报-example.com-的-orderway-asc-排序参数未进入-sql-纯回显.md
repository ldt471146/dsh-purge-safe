# PHPWind 7.3.2 负面情报：example.com 的 orderway/asc 排序参数未进入 SQL（纯回显）

- **code**: phpwind-7.3.2-负面情报-example.com-的-orderway-asc-排序参数未进入-sql-纯回显
- **kind**: template
- **category**: app-audit
- **component**: PHPWind 7.3.2
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-06 在 example.com（PHPWind 7.3.2 / GBK / PHP 5.5.38 / nginx）带登录态实测，共 6 包，全部走代理、1 req/2s：

| 请求 | 响应大小 | 首行用户名 |
|---|---|---|
| example.com（无参基线） | 118054B | weide |
| example.com?orderway=uid&asc=asc | 118138B | weide |
| example.com?orderway=zznotexistk7（不存在列名） | 118264B | weide |
| example.com?orderway=uid'（裸单引号） | 118222B | weide |
| example.com?orderway=uid&asc=desc | 118152B | weide |
| example.com?orderway=uid&asc=zznotexistk7 | 118264B | weide |

■ 为什么"大小变了"却不是注入（关键判据，别被骗）
诊断 ow-bad（118264B）：`zznotexistk7` 在响应中出现 **14 次，且全部位于分页链接里** —— `example.com?orderway=zznotexistk7&asc=asc&page=N`，以及 Go 跳转的 `location='example.com?orderway=zznotexistk7&asc=asc&page='+this.value`。即 GET 参数被原样拼回分页栏，**这才是页面变大 210B 的唯一来源**。
base 与 ow-bad 做行级 diff，**差异只有 2 行，且这 2 行都是分页栏本身**。

■ 三条排除性证据
1. 响应中**零 SQL 报错**：Query Error / mysql / Unknown column / syntax / SELECT 关键词命中数全为 0（GBK 站关错误显示亦无法解释"传非法列名却毫无异常"）。
2. **asc=desc 首行用户仍为 weide**（默认序），若参数真进入 `ORDER BY ... $asc` 应反转为 admin(uid=1) 在最前。
3. **orderway=uid&asc=asc 也未按 uid 升序**（首行仍是最新注册的 weide/uid=8942，而非 admin/uid=1）。
⇒ 结论：orderway/asc 被白名单映射为固定值或压根未用于 SQL，**页面长度差异 100% 来自参数回显**，不构成注入点。

■ 复用提示
同款 phpwind 7.x 站若要在 example.com 上找注入，不要用"响应大小变化"做判据（分页栏回显参数必然导致大小变化，会假阳性）；必须用"排序结果是否真的改变（首行用户是否变化）+ 是否出现 SQL 报错"双判据。
- **tags**: phpwind,7.3.2,负面情报,orderway,member.php,注入,判据,假阳性
- **created_at**: 2026-10-06T11:36:29.156Z
- **found_by**: exploit

## 描述

在 example.com（PHPWind 7.3.2 / GBK / nginx）实测否定：example.com 的 orderway / asc 参数仅被回显到分页栏，未进入 SQL 排序。后续同版本靶标勿再重复投入。

## 用法

```
判据：① 首行用户是否随 asc/desc 反转；② 响应中是否出现 SQL 报错；③ 参数是否只出现在分页链接里（用 grep 统计出现次数与位置）。三条都指向"纯回显"即否定。
```
