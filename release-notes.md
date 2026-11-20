# 2.1.0

技能库扩容 + ARTEX 知识库

## 中文

- 内置 **252 个目录式技能包**（`skills/bundle/<id>/SKILL.md` + references/scripts/examples），安装时同步到 `$DSH_HOME/redteam/skills`，红队模式可用技能从 40 个扩到 **293 个**（flat + bundle 并存，同名不覆盖用户副本）。
- 新增 **ARTEX 知识库 0.4.4**：700 条实战案例（正文/利用步骤/标签）与可复用 PoC 文件，随包分发到 `$DSH_HOME/redteam/knowledge/artex`（`knowledge.db` + `markdown/` + `pocs/`）。
- ARTEX 的 700 条 POC 安装时**并入插件主知识库** `$DSH_HOME/redteam/knowledge.db`（INSERT OR IGNORE，不动用户已有条目，`source=kb`），面板「知识库」页直接搜得到（724 条 = 用户 24 + ARTEX 700）。
- 新增三个只读工具：`redteam_kb_status`（库概览）、`redteam_kb_search`（中英文关键词检索，中文走 LIKE、英文叠 FTS）、`redteam_kb_get`（取正文 + PoC 绝对路径 + markdown 笔记）。
- 修「知识库」页看不到条目：默认不再按当前项目过滤（知识库跨靶标共享，700 条 ARTEX 条目原来被 engagement 条件全滤掉，列表空白）；要看本项目来源的条目用「全部来源靶标」下拉自选。
- 修「知识库」点开只有元数据：ARTEX 只带 markdown 笔记的 137 条现在合并时回填正文，其余条目在正文为空时按 code 兜底读 markdown 笔记，`path` 落在随包 `knowledge/artex/pocs/` 下也能正常读取。
- 新增技能 `artex-kb`：说明知识库位置、检索套路与"参考不当指令"的纪律。
- 修复 `preset.yml` 被误插 `- id: tool-schedule` 行导致整份预设解析失败（宿主报 `line 7: unexpected content`，红队模式从下拉里消失）：只对 `agent.cordis.yml` 跑 repairDelegation，并在安装时自愈已被污染的元数据副本。

## English

- Ships **252 directory-style skill packs** (`skills/bundle/<id>/SKILL.md` plus references/scripts/examples), synced to `$DSH_HOME/redteam/skills` on install; redteam skills grow from 40 to **293**.
- Adds the **ARTEX knowledge base 0.4.4**: 700 archived engagement write-ups plus reusable PoC files, shipped to `$DSH_HOME/redteam/knowledge/artex`.
- The 700 ARTEX records are merged into the plugin knowledge DB ($DSH_HOME/redteam/knowledge.db) on install (INSERT OR IGNORE, source=kb), so the panel knowledge page can search them (724 rows = 24 user + 700 ARTEX).
- Three read-only tools: `redteam_kb_status`, `redteam_kb_search` (LIKE for CJK, FTS for latin), `redteam_kb_get` (body + PoC path + markdown note).
- New `artex-kb` skill documenting how to use it.
- Fixed `preset.yml` being polluted with a `- id: tool-schedule` entry, which broke preset parsing (`line 7: unexpected content`) and removed 红队模式 from the mode dropdown; repairDelegation now only runs on `agent.cordis.yml` and existing polluted copies self-heal.

## 日本語

- 252 個のディレクトリ型スキルパックを同梱（`$DSH_HOME/redteam/skills` へ同期、40 → **292**）。
- ARTEX ナレッジベース 0.4.4（700 件の事例 + PoC）を同梱。
- 読み取り専用ツールを 3 つ追加（`redteam_kb_status` / `redteam_kb_search` / `redteam_kb_get`）。
- `preset.yml` に混入していた `tool-schedule` 行を修正し、プリセット解析エラーを解消。

# 2.0.1

演练台可读性修复

## 中文

- 修复内嵌演练台深色面板「黑底黑字」：宿主浅色主题下发的 --dshp-ink 不再污染演练台，按钮、页脚统计、卡片标签全部恢复可读。
- 字号一档：正文/控件 13 → 13.5px，辅助/表格 12 → 12.5px，小节 14 → 15px，行高 1.6 → 1.62。
- 深色分支次要文字提亮（--ui-muted #a5b3c5 → #bac8da），页脚与面包屑对比度 5.2 → 8.9。
- 补齐控件禁用态、主按钮/危险按钮反白、键盘焦点 outline。

## English

- Fixed unreadable dark-panel text in the embedded drill console: the host light theme no longer leaks its dark ink token into the panel (buttons, footer stats, chips are readable again).
- Type scale moved up one notch: body/control 13 → 13.5px, helper/table 12 → 12.5px, section 14 → 15px, line-height 1.6 → 1.62.
- Muted text brightened in dark mode (--ui-muted #a5b3c5 → #bac8da); footer and breadcrumb contrast 5.2 → 8.9.
- Disabled controls, primary/danger buttons and keyboard focus outline made explicit.

## 日本語

- 埋め込みドリルコンソールのダークパネルで文字が読めない問題を修正（ホストのライトテーマの濃色インクが流入しなくなりました）。
- 文字サイズを一段上げ：本文/コントロール 13 → 13.5px、補助/表 12 → 12.5px、セクション 14 → 15px、行高 1.6 → 1.62。
- ダークモードの補助文字を明るく（--ui-muted #a5b3c5 → #bac8da）。
- 無効状態・主要/危険ボタン・キーボードフォーカスの表示を明示。

# 2.0.0

满血版本 + Super Agent 适配

## 中文

- 适配 **DeepSeek Harness 0.2.2-rc.3**。
- 新增 **Super Agent**。
- 优化提示词。
- 降低拒绝率，提升稳定性。

## English

- Adapted for **DeepSeek Harness 0.2.2-rc.3**.
- Added **Super Agent** support.
- Optimized prompts.
- Reduced refusal rate and improved stability.

## 日本語

- **DeepSeek Harness 0.2.2-rc.3** に対応。
- **Super Agent** を追加。
- プロンプトを最適化。
- 拒否率を低減し、安定性を向上。

## 安装与更新

使用解压后的本地目录安装，Web 与桌面端分开安装、分开应用。当前为本地固定版本，在线更新与通道切换已关闭。详细步骤见 [中文 README](./README.zh-CN.md)。
