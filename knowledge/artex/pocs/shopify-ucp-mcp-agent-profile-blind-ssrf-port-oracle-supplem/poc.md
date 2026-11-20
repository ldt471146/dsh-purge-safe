# UI/观测口径补充（在 KB#541 五类分类之上）

## 新增可区分错误形态（KB#541 未记录）
| 回显 content | data.code | HTTP | 含义 |
|---|---|---|---|
| `Invalid content type` | profile_malformed | 422 | 连通，响应非 JSON |
| `Http error` | profile_unreachable | 422 | 连通，HTTP 层错误（含 4xx/5xx 与 3xx 未跟随） |
| `Network error` | profile_unreachable | 422 | 连接快速失败（RST / DNS 失败 / 地址不可用），约 1–3s |
| **`Connection timeout`** | profile_unreachable | 422 | 连接/DROP 型超时，约 10–16s；**端口不通的关键指纹** |
| `Https required` | invalid_profile_url | 422 | URL 层拒非 https scheme |
| **`Invalid uri format`** | invalid_profile_url | 422 | URL 解析层拒绝（前导空白、反斜杠等） |

## 端口存活 oracle 的正确用法（必须做已知答案对照）
同一台**已知开放/关闭端口**各测一次，先标定：
```
profile=https://<已知开放端口主机>:8443/   -> "Http error"        (0.3–0.5s)  ← 有服务响应
profile=https://<同一主机>:9999/           -> "Connection timeout" (15s)       ← 无服务
```
标定后，对目标 host:port 的判定：
- `Http error` / `Invalid content type` → **端口开放**
- `Connection timeout` → **端口无服务或被 DROP**
- `Network error`（1–3s）→ 连接快速失败；**与「端口关闭但 RST」不可区分**
- 时延不可作精细判据（同一 127.0.0.1 在不同 URL 形态下 1.1s / 6.3s 波动）

## 实测绕过矩阵（该客户端，全部阴性）
- `https://shop@127.0.0.1/`（userinfo）→ Network error：按 @ 后主机解析，不是前缀校验
- `HTTPS://127.0.0.1/`（大写 scheme）→ Network error：scheme 大小写被接受但仍连回环
- `https://127.0.0.1\@host/`、`" https://127.0.0.1/"` → Invalid uri format（解析层拒绝）
- `https://127.0.0.1.nip.io/`（DNS 重绑定）→ Network error：与直连 127.0.0.1 同形，未见绕过
- `https://[::1]/` → Network error
- 302 降级：门店自身开放重定向（302 → https://shop/.well-known/ucp）→ Http error，**不跟随 301/302**

## 能力上限（别夸大）
- 只收 https；不回显响应体；不跟随跳转 → 只能判「公网可达主机的存活 + 端口 + 是否 JSON」，读不到任何内网内容
- loopback / RFC1918 / 169.254.169.254 全部 Connection timeout 或 Network error，与「端口关闭」不可区分 → **不具备内网端口发现能力**
- 这是功能设计（抓取 agent profile），不是可提权入口；severity 维持 low