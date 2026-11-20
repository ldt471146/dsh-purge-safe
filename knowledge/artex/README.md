# ARTEX 0.4.4 武器库（知识库）导出

导出时间: 2026-11-15 18:53:54 CST
来源: /opt/artex/redteam/knowledge.db (sqlite) + PostgreSQL artex.kb_entry_meta

## 内容清单

| 文件/目录 | 说明 |
|---|---|
| `poc.jsonl` | 全部 700 条记录，一行一条 JSON，字段最全（含 content/usage/path/verified 等） |
| `poc-index.csv` | 700 条索引（id/code/标题/类型/分类/CVE/组件/严重度/语言/来源/验证状态/命中次数/创建时间） |
| `markdown/` | 700 个 Markdown 单条文档，含描述/用法/正文代码块 |
| `pocs/` | 原始落盘文件（550 个目录），脚本/模板/请求原文 |
| `knowledge.db` | 原始 sqlite 库整包备份（可直接用 sqlite3 打开查询） |
| `kb_entry_meta.csv` | 另一套知识条目表（175 行，含表头），正/负极性经验条目 |

## 分类分布

| 分类 | 数量 |
|---|---|

## 类型分布


## 用法

```bash
# 查全部 CVE 类
grep -i 'cve' poc-index.csv
# 按分类筛
python -c "import json;[print(json.loads(l)['code'],json.loads(l)['title']) for l in open('poc.jsonl',encoding='utf-8') if json.loads(l)['category']=='rce']"
# 直接查库
sqlite3 knowledge.db "select code,title from poc where category=\"unauthorized\" limit 20"
```
