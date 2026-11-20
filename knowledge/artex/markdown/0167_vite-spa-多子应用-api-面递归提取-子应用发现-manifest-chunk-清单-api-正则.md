# Vite SPA 多子应用 API 面递归提取（子应用发现 + manifest chunk 清单 + API 正则）

- **code**: vite-spa-多子应用-api-面递归提取-子应用发现-manifest-chunk-清单-api-正则
- **kind**: script
- **category**: info-leak
- **component**: Vite / Vue SPA 多子应用架构
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.45 实测：发现 /agent 代理后台等 4 个独立子应用，解析 manifest.be2a1d70.json（531 资源/322 chunk）并通过业务关键字筛选提取出 24 个此前未知的代理后台 API（含批量建号 batchCreateAccount、费率修改 editUserRate、数据导出 export/directFin 等高危功能）。同时验证了判定纪律：这些接口未鉴权返回 200 但为加密错误信封（无鉴权与有鉴权响应长度逐字节相同），不构成数据泄露。
- **path**: pocs/vite-spa-多子应用-api-面递归提取-子应用发现-manifest-chunk-清单-api-正则/vite-subapp-api-extract.py
- **tags**: Vite,SPA,子应用,manifest,API提取,前端逆向,攻击面发现
- **created_at**: 2026-10-03T14:08:28.591Z
- **found_by**: recon

## 描述

一个域名下挂多个独立构建的前端 SPA 时，通过构建哈希差异识别子应用、解析 manifest 获取完整功能 chunk 清单、按业务关键字筛选下载并提取 API 的通用方法。含"未鉴权返回加密密文不等于数据泄露"的判定纪律。

## 用法

```
python vite-subapp-api-extract.py
改 HOST 为目标 IP/域名；tops 列表可从主 bundle 的顶层路径正则自动生成。
输出：每个子应用的 chunk 数量 + 提取到的全部 /api/ 路径。
```

## 正文

```
# Vite SPA 多子应用 API 面递归提取

## 适用场景
一个域名/IP 下挂多个**独立构建**的前端子应用（主站 + 代理后台 + 活动站等），
每个子应用有各自的 API 面。只分析主站 bundle 会漏掉大量接口。

## 识别独立子应用的三个信号
1. **构建产物哈希不同**：`/agent` 用 `commonChunk.GQwXmA27.css`，
   `/gossip` 用 `commonChunk.CDp6Q3sH.css`，主站用 `commonChunk.CMoJwNYm.js`
   → 哈希不同 = 独立打包 = 独立的懒加载 chunk 集合
2. **入口 chunk 命名带业务语义**：`index.admin-agent.WOmu9FLX.js`
3. **引用不同的 manifest**：读入口 chunk 里的
   `window.__MANIFEST_ASSETS = 'assets/theme-0/manifest.be2a1d70.json'`

## 核心步骤

### 1) 从主 bundle 提取顶层路由
```python
tops = set(re.findall(r'["\'`](/(?!api/)[A-Za-z][A-Za-z0-9_\-/]{1,60})["\'`]', main_bundle))
```
逐个 GET，返回 200 且带 `<title>` 的就是真实子应用入口。

### 2) 读入口 chunk 拿 manifest
```python
entry = re.search(r'import"\./(index\.[A-Za-z0-9_\-]+\.js)"', html)
entry_js = GET("/assets/theme-0/" + target163.example.com(1))
mf = re.search(r"__MANIFEST_ASSETS\s*=\s*'([^']+)'", entry_js)
manifest = json.loads(GET("/" + target164.example.com(1)))
```

### 3) **manifest 里的 chunk 名本身就是功能清单**
这是最大价值点 —— 不用下载就能知道后台有哪些功能：
```
AgentApplication / CommissionIndex / ExportIndex
ClubAgentCommissionIndex / ClubAgentPerformanceIndex
DirectBettingIndex / DirectDataIndex / DirectFinanceIndex / DirectTransferIndex
ExportIndex / ExportButtonIndex / EffectiveBetIndex
Devtools / DevtoolsIndex          ← 后台里的开发者工具
DiscountCodeIndex / DepositRewardsIndex / DistributionDetailsIndex
```

### 4) 按业务关键字筛 chunk 下载，正则提 API
```python
BIZ_KW = ["Agent","Commission","Export","Finance","Data","Transfer","Bet",
          "Withdraw","Deposit","Member","User","Report","Club","Distribution"]
apis = re.findall(r'["\'`](/api/[A-Za-z0-9_\-/]{2,90})["\'`]', chunk_src)
```

## 实测产出（203.0.113.45）
- 发现 4 个子应用：`/agent`（代理后台）、`/gossip`、`/promote-game`、`/pc`
- `/agent` manifest：**531 项资源 / 322 个功能 chunk**
- 提取出 **24 个主站清单外的 API**，含高危功能：
  - `/api/agent/promote/batchCreateAccount`（批量建号）
  - `/api/agent/promote/editUserRate` / `setDefaultUserRate`（改代理费率）
  - `/api/agent/promote/reportPc/export/{directInfo,directFin,directOrder,transfer}`（数据导出）
  - `/api/agent/promote/reportPc/{directReportPcV1,directFinV1,userDayDepositList,userDayWithdrawList}`（会员充值/提现/业绩报表）

## 踩坑提醒
- **"未鉴权返回 200 + 加密密文" ≠ 数据泄露**。必须做「无鉴权 vs 携带有效会话」的
  **响应长度对照**：若两者逐字节相同且 raw 长度为 16 的倍数，说明返回的是
  「无权限」的加密错误信封，**没有实际数据**，不能当成果记分。
- 写/导出类接口常返回 `41060 参数异常/解析包异常`（参数层拒绝），需构造加密请求体。
```
