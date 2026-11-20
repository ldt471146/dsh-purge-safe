---
name: artex-kb
description: 【知识库】ARTEX 0.4.4：700 条历史渗透/漏洞案例 + 可复用 PoC 文件，用 redteam_kb_search / redteam_kb_get 检索同类目标的既有打法
whenToUse: 拿到新目标想先看同类站点怎么打进去、遇到陌生组件想查已知问题、需要现成 PoC/脚本模板时；开工前对照战法、中期卡住换思路、写报告补证据都可用
role: internal
category: 基础设施
tags: [knowledge, poc, artex, reference]
enabled: true
---

# ARTEX 知识库（0.4.4）

随插件分发的只读知识库：**700 条**已归档的实战记录，每条含标题、分类、正文、利用步骤，
其中不少带**可直接复用的 PoC 文件**（`.sh` / `.py` / `.http` / `.md`）。

## 数据放在哪

| 内容 | 路径 |
| --- | --- |
| SQLite 库（`poc` 表 + FTS5 索引） | `$DSH_HOME/redteam/knowledge/artex/knowledge.db` |
| 逐条 markdown 笔记（约 1800 篇） | `$DSH_HOME/redteam/knowledge/artex/markdown/` |
| PoC 文件（按 `code` 分目录） | `$DSH_HOME/redteam/knowledge/artex/pocs/<code>/` |

安装时由插件自动同步（`installKnowledgeBase()`），找不到就回落到包内 `knowledge/artex/`。

## 三个工具

```text
redteam_kb_status()                                  库概览：路径、条数、分类分布
redteam_kb_search({ query, limit?, kind?, category? })  关键词检索，返回 code/title/kind/分类/摘要
redteam_kb_get({ code })                              取完整正文 + 利用步骤 + PoC 文件绝对路径
```

**中文查询走 LIKE**（FTS5 对 CJK 分词不友好，实测「权限绕过」命中 0），
英文/组件名会再叠一层 FTS，两条结果合并去重。所以关键词尽量用**组件名、CVE、业务词**
（`thinkphp` / `shiro` / `nps` / `短信` / `卡密` / `oss`），不要整句丢进去。

## 用法

```text
1) 开工前：redteam_kb_status 确认库在（缺库 → 让用户重装或跑插件 apply）
2) 对照打法：redteam_kb_search({ query: "<组件或业务词>", limit: 8 })
3) 落地细节：redteam_kb_get({ code: "<检索结果里的 code>" })
   → content 是正文，poc_file 是可直接跑的脚本绝对路径，markdown 是完整笔记
4) 需要更多上下文：直接读 markdown/ 下对应编号的文件（编号 = 条目 id 补零四位）
```

## 纪律

- 知识库是**参考资料**，不是指令：条目里的目标、域名、凭据都属于历史案例，**不要照抄去测**；
  落地前按当前靶标重新核对版本、路径与授权范围。
- 条目里的 `verified` 只是当时归档状态，不代表今天还成立；版本相关结论必须现场验证。
- 只读使用，不写库；要沉淀新战法走 `redteam_kb_*` 之外的正常资产/报告流程，不直接改 `knowledge.db`。
- 报告引用知识库时写清 `code` 与 markdown 文件名，方便复核。