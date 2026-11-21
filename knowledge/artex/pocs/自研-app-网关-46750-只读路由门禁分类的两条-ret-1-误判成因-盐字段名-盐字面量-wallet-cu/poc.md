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