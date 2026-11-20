# shopto.net DcCMS /dc/ 与 /pp/ 后台对 EWS/Exchequer 身份材料不可复用（86 次受控喷洒全阴性）

- **code**: shopto.net-dccms-dc-与-pp-后台对-ews-exchequer-身份材料不可复用-86-次
- **kind**: poc
- **category**: weak-password
- **component**: DcCMS 2015 (dcshop) 后台登录 /dc/、/pp/
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 ARTEX 执行机直连 3.8.196.174（curl -k --http1.0 --noproxy '*'，Host: cp.shopto.net）：86 次 POST /dc/?action=admin_login 与 /pp/?action=admin_login（9 组 EWS 明文口令原配 + 交叉 + 26 员工邮箱形态）全部 302→/dc/ 或 /pp/、跟随后 2498B/2507B、title=Login、固定 role=alert「The login details or verification code are not valid.」；curl 独立复核 3 组同样。无 429/无锁定/无时延增长；归一化内嵌 sidcms 与 ?t= 后不同账号失败页 diff 为空（无用户名 oracle）。
- **path**: pocs/shopto.net-dccms-dc-与-pp-后台对-ews-exchequer-身份材料不可复用-86-次/poc.md
- **tags**: shopto,dccms,weak-password,negative,credential-reuse,ews,exchequer,admin-login
- **created_at**: 2026-11-11T21:10:41.151Z
- **engine**: https://3.8.196.174/dc/ 与 https://3.8.196.174/pp/（Host: cp.shopto.net）

## 描述

阴性情报：从 90.152.8.56 匿名 NFS /ENTERPRISE 导出的 EWS 主库（EWS.mdb Users 表 9 组明文口令 MANAGER/IGOR、ROB/ROB、LEE/LEE、MARTIN/MARTIN、JDW/JDW、WIFI/WIFI、station3/station3、STATION1/ROB、STATION2/ROB）+ UpgradeInfo.INI 30+ Windows 用户名 + DocMastr 26 员工邮箱，对 DcCMS 后台 /dc/ 与伙伴门户 /pp/ 做受控复用全部无效。ERP 身份体系与 DcCMS 后台凭据不重合，别再在这条线上投入。

## 用法

```
前置：直连 3.8.196.174:443（--noproxy '*'，Host: cp.shopto.net 免 Basic）。本条目只说明「EWS/ERP 身份材料对该后台无效」，不要再用 9 组 EWS 明文口令或 26 员工邮箱喷洒 /dc//pp/；若拿到 DcCMS 自身泄露凭据，可用上表 2498B/2507B+固定 errorbox 基线区分成功与失败。
```

## 正文

```
# shopto.net DcCMS 后台凭据复用阴性结论（2026-11-11）

## 结论
EWS/Exchequer ERP 侧的全部身份材料（9 组明文口令 + 30+ Windows 用户名 + 26 员工邮箱）在 DcCMS `/dc/`（德语管理后台）与 `/pp/`（Partner 门户）上全部无效；86 次受控尝试零命中、无差异化回显、无锁定迹象。**该凭据复用路径封死**，除非取得 DcCMS 自身凭据（config/DB 导出/安装初始口令）。

## 精确失败基线（可复用判据）
| 入口 | GET 登录页 | POST 错误口令 |
|---|---|---|
| `/dc/` | 200 / 2367B / title=Login / `sidcms`+`sidcms_last_action` | 302 `Location: /dc/` → 跟随 200 / **2498B** / title=Login / `role="alert">The login details or verification code are not valid.` |
| `/pp/` | 200 / 2376B / title=Login / `sidcms`+`sidcms_last_action_pp` | 302 `Location: /pp/` → 跟随 200 / **2507B** / 同上文案 |
| 生产 www.shopto.net | 2367 / 2376B（维护门豁免，fact#2797） | 同上语义 |

- 表单：`POST ?action=admin_login`，字段仅 `input_login` / `input_password`（无 CSRF 隐藏域、无验证码字段）。
- 失败时 `Set-Cookie: sidcms` 与 GET 阶段值逐字相同（会话固定延续）。
- 归一化页面内嵌的 28 位 `sidcms` 与 CSS `?t=<unix>` 后，**不同账号（含不存在用户）的失败页 diff 为空** → 无用户名 oracle。
- 全程无 429 / 无延迟增长（0.17–0.22s）/ 无锁定。

## 已试组合（勿重复）
- 9 组原值原配 × 两入口各 1 次：MANAGER/IGOR、ROB/ROB、LEE/LEE、MARTIN/MARTIN、JDW/JDW、WIFI/WIFI、station3/station3、STATION1/ROB、STATION2/ROB。
- 口令池 IGOR/ROB/station3 交叉：admin、administrator、MANAGER、IGOR、WAREHOUSE、WAREHOUSE1/3/5、RETURNS、GOODS-IN、SHOPTO、22 个 DocMastr 名（ALISON/MAGGIE/MAT/GARY/JAMES/DAVID/ADRIAN/ANDY/BEN/DALE/DENISE/JASON/JON/NAEEM/STEFAN/RAFAL/CRAIG/MANISH/HARVEY/JADE 等）。
- 邮箱形态：igor@shopto.net/IGOR、rob@skream.com/ROB、martin@skream.com/MARTIN、ahalford|alison|gary|james|jessica|kgiga@shopto.net/ROB。
- 另：`#1015` 160 组默认口令、`#1283` 267 邮箱前缀、`#1327` 43 组默认/弱口令、`#2404` 的 SSH/dc/pp 均已有阴性记录，不属本条。

## 复现命令
```bash
UA="$ARTEX_UA"
curl -sk --http1.0 --noproxy '*' -A "$UA" -H 'Host: cp.shopto.net' \
  -c /tmp/cj -b /tmp/cj 'https://3.8.196.174/dc/' -o /dev/null
curl -sk --http1.0 --noproxy '*' -A "$UA" -H 'Host: cp.shopto.net' \
  -c /tmp/cj -b /tmp/cj -D - -o /dev/null -X POST \
  --data 'input_login=MANAGER&input_password=IGOR' \
  'https://3.8.196.174/dc/?action=admin_login'
# 期望：302 Location: /dc/ + Set-Cookie sidcms 不变
curl -sk --http1.0 --noproxy '*' -A "$UA" -H 'Host: cp.shopto.net' \
  -b /tmp/cj 'https://3.8.196.174/dc/' | grep -oE 'role="alert">[^<]*'
# 期望：role="alert">The login details or verification code are not valid.
```
```
