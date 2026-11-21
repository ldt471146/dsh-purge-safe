# 自研 App 网关 46750 只读路由门禁分类的两条 ret=1 误判成因（盐字段名≠盐字面量 / wallet·currency 触发参数校验）

- **code**: 自研-app-网关-46750-只读路由门禁分类的两条-ret-1-误判成因-盐字段名-盐字面量-wallet-cu
- **kind**: payload
- **category**: unauthorized
- **component**: 自研 App 后端网关（IIS+.NET JSON，POST 根路径，静态盐 private_&lt;route&gt;）
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-05 在 43.139.167.210:46750 实测 18 发：/matchresult 用盐 private_matchdetails(字段名) 回 200/39B ret=1(sha16=28C525732CCC2EFD)，仅改成字面量 private_matchresult 即回 200/39B ret=2(sha16=9A8967379A845835)；/playingrecords 带 wallet='0'/currency='0' 回 ret=1，去掉这两个 body-only 字段、键集与 verify 不变即回 ret=2；同批 /tableresult、/tablerecords、/accountdata、/statement、/bethistories、/clubmember、/socialdata、/userstock 均 ret=2 同 sha16，零 data。
- **path**: pocs/自研-app-网关-46750-只读路由门禁分类的两条-ret-1-误判成因-盐字段名-盐字面量-wallet-cu/poc.md
- **tags**: 46750,verify签名,ret=1,参数检查失败,盐字面量,wallet,currency,negative
- **created_at**: 2026-11-04T18:09:49.535Z
- **engine**: https://43.139.167.210:46750

## 描述

打同族 46750 网关（verify=按键名升序裸拼 key+value + 盐 + UPPER(MD5)）时，ret=1「参数检查失败」有两种典型成因，容易被误读成「形状不符、需继续试」，白白烧预算。判据与修法见正文。

## 用法

```
1) 先算阳性对照 /notices（version=1.0.0.9,token=123,type=1,userid=10000,盐 private_notices）确认 71F92ABA6D7A935CCAADBB9AFE42E45E→ret=2；2) 逐路由按字面量盐+键集升序裸拼算 verify；3) ret=1 时先比较「字段名 vs 字面量」的盐，再尝试删掉不参与签名的 wallet/currency；4) 仍 ret=1 记未证并说明所试形状。
```

## 正文

```
## 结论
ret=1（39B `{"ret":1,"msg":"参数检查失败！"}`，sha16=28C525732CCC2EFD）≠ 签名公式推导错误。实测两类成因：

### 1) 盐用错了：IL 字段名 ≠ 盐字面量
客户端 IL 里是 `ldsfld F:HttpHelper.private_matchdetails`，但该静态字段的**字面量值是 `private_matchresult`**。
同体同算法只换盐：
- 盐=private_matchdetails → ret=1
- 盐=private_matchresult → ret=2（门禁）

**补救**：直接抽二进制 #US 字符串堆里的 UTF-16LE 字面量，取全部 `private_*`（本目标共 76 条），以字面量为准，不要用字段名拼接。

```python
import re
b=open(r"...Unity.Hotfix.dll.dec.bin","rb").read()
s={m.group().decode("utf-16le") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}",b)}
print(sorted(x for x in s if x.startswith("private_")))
```

### 2) body-only 字段触发服务端参数校验
`wallet` / `currency` 不参与客户端签名（IL 只签 version/token/type/userid/collection/page/gameid），但服务端会在参数校验层校验它们的取值/存在性：带 `wallet="0",currency="0"` → ret=1；**去掉这两个字段、其余键集与 verify 完全不变** → ret=2。
命中该特征的路由：/playingrecords、/userbattle、/userdeck、/userprofit（Req_BrandSpectrumInfo / Req_Userbattle / Req_Userdeck / Req_Userprofit）。

### 3) 仍然 ret=1 的残例
/userbattle 去掉 wallet/currency 后仍 ret=1（IL 里它只 set_wallet、不 set_currency，wallet 很可能是必填真实钱包串）；/searchplayingrecord 全键集仍 ret=1、成因未定位。这两条不能当门禁阴性，只能记「未证」。

## 判据速查
| 现象 | 结论 |
|---|---|
| 200/39B ret=2，sha16=9A8967379A845835 | 已过签名，卡在 token→账号门禁（阴性，不重派） |
| 200/39B ret=1，sha16=28C525732CCC2EFD | 参数/签名校验层，先查盐字面量与 body-only 字段，不要盲发改值 |
| 200/38B「接口不存在」 | 该后端未注册此路由 |

## 实战口径
20 万级预算内，14 条只读路由 18 发即可完成门禁分类：阳性对照 1 发 + 每路由 1 发 + 至多 3 发定向修正。凡 ret=1 必须能说清「改的是哪一处」，改不动就记未测，不要同轴盲发。
```
