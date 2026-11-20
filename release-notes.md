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
