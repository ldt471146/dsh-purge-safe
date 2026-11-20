---
name: ai-tool-cyberstrikeai
description: CyberStrikeAI —— 面向攻击面的 AI Agent 框架（AIPentest），带 runbook 体系与 skill 库，可按 MITRE ATT&CK 编排原子测试。用于把「一堆工具」组织成可复用的攻击剧本。
---
# CyberStrikeAI

- 仓库：https://github.com/AIPentest/CyberStrikeAI ｜ 文档：https://docs.cyberstrike.io/docs/getting-started/
- 同族项目：https://github.com/CyberStrikeus/CyberStrike（宣称 7300+ 可执行 skill、2000+ Atomic Test、1500+ CIS 控制项，lazy-loading 避免上下文污染）

## 关键设计（值得抄的部分）

1. **Runbook 化**：每个攻击动作写成 runbook（前置条件 / 命令 / 判定标准 / 产出），agent 只负责选 runbook + 填参数；
2. **Skill 懒加载**：不是把所有能力塞进 system prompt，而是按需拉取，控制 context；
3. **证据链**：runbook 产出结构化结果，便于后续复现与报告。

```
docs/zh-CN/         中文文档
docs/en-US/runbooks.md   ← 想看它怎么编排，直接读这个
```

## 起服务

```bash
git clone https://github.com/AIPentest/CyberStrikeAI && cd CyberStrikeAI
# 按 docs/getting-started 配 LLM key 与工具路径
```

## 我怎么用它

- 当**攻击剧本模板库**：把它的 runbook 结构套到我们自己的靶标流程（recon → assess → vuln-scan → exploit → internal）；
- 当**对照组**：同一目标用它的 agent 跑一遍，和我们手写流程比对漏项；
- 结论同样要人工复现，不能直接写进报告。

## 注意

这类「通用 Agent + 大量 skill」的项目，**上下文管理**是命门：skill 一多，模型容易在选工具上打转。
真要用于实战，务必限定 scope（单目标/单资产），并把 runbook 输出落盘。
