# 博彩 CMS「构建哈希」指纹：body="&lt;buildhash&gt;" 在 FOFA 一键枚举同产品同构建部署舰队（含每租户一端口划分）

- **code**: cn7-gameplat-构建哈希指纹-前端bundle-hash-fofa枚举同构建舰队
- **kind**: poc
- **category**: info-leak
- **component**: CN7 CMS / gameplat（前端 webpack/Next.js 静态 SPA + Spring Boot）
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-10 在 203.0.113.16:10666 实测：首页引用 js/*.1787221950252.*.js，FOFA body="1787221950252"&&status_code=200 命中 2424 host；对同段 203.0.113.26/.69/.70/.71/.72/.73/.99/.101/.102/.108/.109 的 :443 与 :43135 打 /api/version 全部返回同一 5.3.0-RELEASE/builder 2026-10-06/profile prod/license 375，逐字节同构（同 92709B SPA 兜底、同 86B 401 JSON），无更弱节点。对照 body="configPage.js" 命中 34720、body="themeH5" 命中 21359（跨 kbo/mc/blb/bailebo 等多厂商，非本产品专属）。
- **tags**: 指纹,FOFA,构建哈希,博彩CMS,资产测绘,CN7,gameplat
- **created_at**: 2026-10-09T18:42:51.644Z

## 描述

用前端 SPA 引用的构建哈希（bundle 文件名形如 js/&lt;name&gt;.&lt;buildhash&gt;.&lt;chunkhash&gt;.js）作指纹，可在 FOFA 一次性枚举出某博彩 CMS 的整支部署舰队——比产品名/关键词精准得多（body="gameplat" 会误匹配 gameplay，body="configPage.js"/"themeH5" 跨多厂商）。适合在「同产品同版本实例枚举/找更弱节点」类意图中快速铺开资产面。

## 用法

```
1) 抓目标首页，提取 SPA 引用的 bundle 名里的构建哈希：`curl -sk https://TARGET/ | grep -oE '[a-z0-9]+\.[0-9]{13}\.[a-f0-9]+\.js'`（例：js/chunk-common.1787221950252.335f829e.js → 构建哈希 1787221950252）。
2) `fofa: body="<buildhash>" && status_code=200` → 得到同产品同构建的整支舰队（本目标命中 2424 个 host）。
3) 舰队常按「每租户一端口」部署：同一 /24 内不同 IP 用不同高位端口（本目标段：:43135、段外 :43119/:43149/:43352/:43181/:42187），同段/同 IP 的 :80/:443 也常是同一实例。
4) 逐节点取指纹对比版本：`curl -sk https://IP:PORT/api/version`（无鉴权）→ 看 version/builder 是否出现更老的构建（更老=可能有 Nday 可打）。
5) 注意授权范围：同 C 段(如 203.0.113.24/24)通常在范围内，跨段舰队需先确认再打。
坑：body="configPage.js"(34720)、body="themeH5"(21359) 是通用博彩模板特征、跨厂商，勿用它定位单一产品；只有「构建哈希」是本产品本版本的唯一指纹。
```
