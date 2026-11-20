---
name: ai-tool-cairn
description: Cairn —— 把渗透测试抽象成「状态空间搜索」的通用解题引擎（Blackboard 架构：Fact/Intent/Hint 三原语，Worker 跑 OODA）。腾讯云 Hackathon AI 渗透赛 54/54 AK、总榜第 3。用于无人值守的 CTF/靶场自动解题与红队初筛。
---
# Cairn（通用状态空间搜索引擎）

- 仓库：https://github.com/oritera/Cairn ｜ AGPLv3（商用需授权）｜ Python ≥3.12 + Docker
- 成绩：腾讯云 Hackathon「AI 渗透测试挑战赛」第二届，610 队 / 1345 人，**54/54 全解（唯一 AK）**，总榜第 3。

## 它和别的 agent 差在哪

不定义角色、不定义 workflow。只有三个原语：

| 原语 | 含义 |
|---|---|
| **Fact** | 已确认的客观发现，写进黑板 |
| **Intent** | 声明要探索的方向（还没执行） |
| **Hint** | 人随时注入的判断，下一轮被 agent 吸收 |

Worker 跑 OODA：Observe 全图 → Orient 当前态 → Decide 下一步 Intent → Act 探索 → 写回 Fact。
Agent 之间**只通过黑板协作**（stigmergy），没有直接通信、没有固定岗位。

任务只有三种：`Bootstrap`（开局直接硬解）、`Reason`（读全图判断目标达成没、下一步探什么）、`Explore`（认领一个 Intent 去执行）。

## 起服务

```bash
docker pull --platform=linux/amd64 ghcr.io/oritera/cairn-worker-container:latest
cp dispatch.example.yaml dispatch.yaml      # 填 LLM endpoint / key
docker compose up --build                     # cairn-server :8000 + dispatcher
```

不想用 Docker 走 **local mode**（复用本机已登录的 `claude` / `codex` / `pi` CLI）：

```bash
cp dispatch.local.example.yaml dispatch.yaml   # runtime.execution: local
uv run --project cairn cairn serve
uv run --project cairn cairn dispatch --config dispatch.yaml
```

## 我怎么用它

- **CTF / 靶场**：给 origin（入口 URL）+ goal（拿 flag/打通），让它自己搜路径；
- **红队初筛**：把一个 C 段丢进去，产出「可能的最短攻击路径」，人再按路径精修；
- **教学价值**：它是目前把「渗透 = 有向搜索」讲得最干净的开源实现，写报告时可以直接引用这个框架。

## 风险

- local mode 下 agent **以你的用户权限裸跑、无沙箱**；
- 容器模式每项目一个 worker 容器，机器资源要够（并发 worker × 容器）。
