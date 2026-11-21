# ARTEX 0.4.5 武器库（知识库）导出

导出时间: 2026-11-11 19:25 CST（UTC+8；服务端文件最后写入 11:25 UTC）
来源: 186.244.201.53:/opt/artex（`redteam/knowledge.db` sqlite + `redteam/pocs` + `redteam/skills`）
合并方式: 0.4.5 库 575 条 ∪ 本包 0.4.4 库 700 条，同 code（或同一 poc.id 换名）以 0.4.5 为准 → 最终 720 条

## 内容清单

| 文件/目录 | 说明 |
|---|---|
| `knowledge.db` | 合并后 720 条记录（sqlite，schema 与 0.4.4 完全一致）；`poc_fts` 已重建，720 行，与 `poc` 一一对应 |
| `poc-index.csv` | 720 条索引（id/code/标题/类型/分类/CVE/组件/版本/严重度/语言/来源/验证状态/命中次数/创建时间） |
| `markdown/` | 720 个 Markdown 单条文档（597 个含正文代码块，123 个仅元数据 + 描述/用法） |
| `pocs/` | 原始落盘文件（679 个目录，脚本/模板/请求原文；396 个同名目录以 0.4.5 覆盖，新增 129 个） |
| `kb_entry_meta.csv` | 沿用 0.4.4 导出（175 行含表头，正/负极性经验条目），本次未随 0.4.5 重新导出 |
| `knowledge.db.044bak` | 合并前 0.4.4 原库备份（700 条），用于比对与回滚 |

## 分类分布

| 分类 | 数量 |
|---|---|
| info-leak | 153 |
| auth-bypass | 150 |
| unauthorized | 100 |
| recon | 50 |
| rce | 47 |
| weak-password | 30 |
| methodology | 28 |
| file-upload | 24 |
| frontend-reverse | 21 |
| ssrf | 20 |
| app-audit | 19 |
| env | 12 |
| protocol | 12 |
| waf | 12 |
| path-traversal | 11 |
| sqli | 10 |
| tunnel | 8 |
| privesc | 7 |
| deserialization | 5 |
| xxe | 1 |
| **合计** | **720** |

## 类型分布

| 类型 | 数量 |
|---|---|
| poc | 345 |
| script | 232 |
| exp | 58 |
| template | 55 |
| payload | 20 |
| markdown | 5 |
| methodology | 3 |
| http | 1 |
| manual | 1 |
| **合计** | **720** |

## 用法

```bash
# 查全部 CVE 类
grep -i 'cve' poc-index.csv

# 按分类筛（本环境没有 sqlite3 命令行，用 node 22 的 node:sqlite）
node --experimental-sqlite --input-type=module -e "import {DatabaseSync} from 'node:sqlite'; const db=new DatabaseSync('knowledge.db',{readOnly:true}); console.table(db.prepare('select code,title,hit_count from poc where category=? order by hit_count desc limit 20').all('unauthorized'))"

# 英文关键词（走 FTS5，poc_fts 与 poc 按 poc_id 关联）
node --experimental-sqlite --input-type=module -e "import {DatabaseSync} from 'node:sqlite'; const db=new DatabaseSync('knowledge.db',{readOnly:true}); console.log(db.prepare(\"select p.code,p.title from poc_fts f join poc p on p.id=f.poc_id where poc_fts match '\\\"thinkphp\\\"' limit 10\").all())"

# 中文关键词（中文不分词，走 LIKE；插件里的 redteam_kb_search 也是这么做的）
node --experimental-sqlite --input-type=module -e "import {DatabaseSync} from 'node:sqlite'; const db=new DatabaseSync('knowledge.db',{readOnly:true}); console.log(db.prepare(\"select code,title from poc where title like ? or tags like ? limit 10\").all('%验证码%','%验证码%'))"

# 拿 code 找 markdown 笔记与 PoC 落盘文件
ls markdown | grep '_thinkphp-精确版本与绝对路径识别-异常页法.md'
ls pocs/thinkphp-精确版本与绝对路径识别-异常页法/
```