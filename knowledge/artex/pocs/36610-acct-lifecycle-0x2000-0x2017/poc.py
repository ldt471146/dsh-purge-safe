## 帧格式
16 字节头：struct.pack("<I",0) + struct.pack("<I",type) + struct.pack("<i",len(body)) + struct.pack("<i",seq) + body
protobuf: 字段号按 wire type 0(varint)/2(len-delim) 编码。

## 账号存在性 oracle（low，未认证）
REQ 0x2000: fv(1,0) + fs(2,email) + fs(3,"vip_1") + fv(4,2) + fs(6,"")
未注册: resp pb=[[1,0,4],[3,2,email],[4,2,"vip_1"],[5,0,2]]  (~0.06s)
已注册: resp pb=[[3,2,email],[4,2,"vip_1"],[5,0,2]]        (~5.5s, 触发验证码邮件)
判据双重差分：Result 0/4 + 耗时 5.5s/0.06s。
（2026-11-05 四样本：未注册 C/D = Result 4 / 0.060~0.062s / 90s 无邮件；已注册 A uid=526051、B uid=631978 = Result 0 / 5.514~5.874s / 真收码）

## 同族端点
uips.pmcqef.com:12984 记录为同族预登录接口（来源材料标注，本条未独立复测）；换目标时先做 HEARTBEAT 与未注册/已注册双样本差分再下结论。

## 注册（自建账号）
0x2000 useType=1 取码: fv(1,0)+fs(2,email)+fs(3,"vip_1")+fv(4,1)+fs(6,"")
0x200C: fv(1,2)+fv(2,0)+fs(3,email)+fs(4,code)+fs(5,"vip_1")+fs(6,"GLHYST4SRU")+fs(7,GetPWD(pwd))+fs(9,email)
响应 uid 在 field6，state 在 field7（=-1），Result 成功时 field1 省略。

## 改密（正常功能，未发现绕过）
0x2000 useType=2: fv(1,0)+fs(2,email)+fs(3,"vip_1")+fv(4,2)+fs(6,"")  -> 真发码
0x2017: fv(1,0)+fs(2,email)+fs(3,"vip_1")+fs(4,code)+fv(5,1)+fs(6,GetPWD(newpwd))
  真码 -> Result=0；错码 000000 -> 2；空码 -> 1；已用码重放 -> 2；跨账号码 -> 2
0x2001 登录: fv(1,2)+fv(2,10)+fs(3,GetPWD(pwd))+fs(4,"vip_1")+fs(5,email)+fs(8,email)+fs(9,kv(0,"1.0.0.9"))+fs(9,kv(1,deviceid))+fs(9,kv(4,"com.pksj.poker"))+fs(10,through)
  kv(k,v)=fv(1,k)+fs(3,v)；成功返回 field2=uid, field3=state, field9 内 key=-99 的 value 为 token。

## 实测样本
A artex9434wkrycqrql0vm@fldubai.com uid=526051；B artex9434q1jx624iz1wr@fldubai.com uid=631978。
