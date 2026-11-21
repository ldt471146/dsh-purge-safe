## 帧格式
16B 头：rsv u32=0 / type u32 / len i32 / seq i32 + protobuf body。
先 0x1000 HEARTBEAT(fv(1,ts)) 并校验回显==自身 ts；帧间 ≥6s；直连不走代理。

## 0x2001 登录（body 权威帧）
fv(1,2) + fv(2,certType) + fs(3,cert) + fs(4,"vip_1") + fs(5,email) + fs(8,email)
+ fs(9, kv(0,"1.0.0.9")) + fs(9, kv(1,deviceid)) + fs(9, kv(4,"com.pksj.poker")) + fs(10,through)
kv(k,v)=fv(1,k)+fs(3,v)。

## 认证因子矩阵实测（2026-11-05，自建 uid=496835）
| certType | cert | Result | 备注 |
|---|---|---|---|
| 10 | GetPWD(正确口令) | 0 | uid/state=2/token，阳性对照 |
| 10 | 随机20位错值 | 2 | 口令校验失败 |
| 1 | 空串 / 随机错值 | 3 | 两形态逐字段同型 |
| 0 | 空串 / 随机错值 | 99 | 不支持类型 |
| 2 | 空串 / 随机错值 | 99 | 不支持类型 |
| 3 | 空串 / 随机错值 | 99 | 不支持类型 |
全部 dt≈0.06s，除 certType=10 正确口令外均无 uid/state/token → 无认证绕过。

## 0x200C 重复注册（对已存在邮箱）
| 验证码形态 | Result |
|---|---|
| 空串 | 9 |
| 000000 错码 | 3 |
| useType=2（改密用途）真码 | 4 |
均非 0、无 uid；事后 0x2001 旧口令 Result=0/uid 不变 → 未覆盖口令。
注意 confound：0x2000 useType=1 对已注册邮箱恒 Result=3（0.067s、不发码），拿不到注册用途真码；若服务端按 useType 绑码，Result=4 也可能表示「用途不符」，但不存在 Result=0 路径。

## 0x2000 注册（新邮箱）
useType=1 → Result=0、2.5–6.2s、真发 6 位码；0x200C{1:2,2:0,3:email,4:code,5:"vip_1",6:"GLHYST4SRU",7:GetPWD(明文),9:sAttach} → Result=0、uid 在 field6、state 在 field7(=-1)。
GetPWD(pwd)=MD5(base64(AES-ECB(SHA256((pwd+reverse(MD5(pwd))).upper()))))[:20]，AES KEY=1122334455667788990099887766smzy。