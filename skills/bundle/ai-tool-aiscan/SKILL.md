---
name: ai-tool-aiscan
description: aiscan —— chainreactors（404 团队）出的通用安全 Agent（Go 单文件），把资产发现 → 指纹 → 漏洞验证串成一条 agent 流水线。用于「给个域名/IP，让它自己跑」，产出可能是候选漏洞清单而不是原始扫描结果。
---
# aiscan（chainreactors 通用安全 Agent）

- 仓库：https://github.com/chainreactors/aiscan ｜ Go ｜ `go install github.com/chainreactors/aiscan@latest`
- 定位：**通用安全 Agent**，输出的是「判断 + 下一步」，不是裸端口表。

## 为什么值得学

chainreactors 是 404 团队的公开仓库组织（gogo / zombies / neutron 同一批人）。aiscan 的取向是：
把 **gogo 的资产面**、**neutron 的 PoC 引擎**、**LLM 的编排** 拼成一条链——
所以它不像「AI 套壳 nmap」，而是把已成熟的 Go 扫描内核交给模型调度。

## 典型用法（装好后）

```bash
# 单目标
aiscan -t https://target.example.com

# 网段/域名面
aiscan -t target.example.com -o runs/aiscan-target
```

配 LLM（OpenAI 兼容即可）：

```bash
export OPENAI_API_KEY=sk-xxx
export OPENAI_BASE_URL=https://api.deepseek.com/v1
```

## 我怎么用它

1. **只当侦察编排器**：让它跑资产面 → 我要的是它筛出来的「可疑接口/组件版本」，再用 `nuclei-scan` / `vuln-research` 精确验证；
2. **对照实验**：同一目标分别用 gogo（纯扫描）和 aiscan（agent）跑，差集就是 LLM 的判断价值所在；
3. **别信结论**：agent 给的漏洞必须手工复现，落 `redteam_evidence_record` 时 confidence 只能先 `claimed`。

## 风险

- 会**自动发包**，无授权目标绝对不要指；
- 速率不可控时容易触发 WAF 封 IP（我们踩过：单 IP 打满后整段 456）。
