# 得分系统 G1 去重陷阱：同档位重复记分会被累加，禁止为补 step_id 关联而重记得分

- **code**: 得分系统-g1-去重陷阱-同档位重复记分会被累加-禁止为补-step_id-关联而重记得分
- **kind**: template
- **category**: methodology
- **component**: 得分系统/台账纪律
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 【2026-10-06 在 example.com 演练中实测踩坑，事故已发生并留证】

■ 事故经过
`web-app` 得分点原本为 **100 分**（1 次命中）。为了给报告补上"得分与攻击链步骤的关联"，按指令用 `redteam_score_hit` 重记了一次同样的成果（`code=web-app`、`points=100`、同 target、带 `step_id=3`、`vuln_id=2`、evidence 为同一件事的另一种措辞）。预期是"同系统同条目被 G1 去重、不重复计分、只补关联"，**实际结果是分数被重复累加**。

■ 实测结果（`redteam_score_list` 真实回显）
```
web-app: points=100, hits=2, counted=2, earned=200, capped=0
summary: achievedPoints=200（原为 100）, countedHits=2, cappedByDedup=0
evidence: [ "...管理员账号 admin / 123456（浏览器实测登录成功...）",
            "...管理员账号 admin / 密码 123456（浏览器实测登录成功...即 PHPWind 创始人 uid=1...）" ]
```
两条 evidence 是同一次成果的两种措辞，`cappedByDedup: 0` 证明去重规则**根本没有触发**。

■ 机制结论（本次事故的核心教训）
G1 的文档描述是"先记普通档、后来提权到管理员档，再记一条管理员档，系统会自动**顶掉**普通档那条" —— **它只在"档位不同"时做顶替（如 10 分档 → 50 分档）**。**同档位（100 → 100）重复记同一系统同一 `code`，会被当作两次独立命中直接累加**，`dedup_scope=system` 的 `scope_label` 虽写着"同一系统只算最高权限一次"，但实现层**没有对同档位做去重**，且**不报错、不警告**。
⇒ **为了"补 step_id 关联"而重记得分点，会直接虚增分数。**

■ 连带发现（同一陷阱的第二种触发方式）
`redteam_chain_add` 若带 `point_code` + `evidence`，按工具说明**服务端会自动记一次分并把步骤与得分互相挂上** —— 因此"用 chain_add 补关联"与"用 score_hit 重记"**毒性相同**，同样会造成同档位重复计分。**补步骤时不要带 `point_code`/`evidence`。**

■ 正确做法（后续所有角色请照此执行）
1. 一个成果**只记一次分**。
2. 得分点缺 step_id/vuln_id 关联时：**只补 `redteam_chain_add` 普通步骤**（不带 point_code），关联缺失只是报告的次要瑕疵，**不值得用污染台账来换**。
3. 确需修正档位时，再记一次并填**高档** `points`（系统会顶掉低档）。
4. 台账已被污染：`redteam_score_hit` **无删除/回退参数**（`demoted_hits` 返回空），**只能人工去控制台「得分」页删除重复命中**。

■ 本次实际损失与处置
`example.com` 的 `web-app` 面板显示 **200 分**，**真实得分是 100 分**；已报告指挥层，需人工删掉其中一条重复命中（两条等价，保留任意一条）。此后本会话已停止一切得分写入。
- **tags**: 得分系统,G1,去重陷阱,台账纪律,负面情报,禁止重记,step关联
- **created_at**: 2026-10-06T12:39:12.905Z
- **found_by**: exploit

## 描述

redteam_score_hit 的 G1 去重只在"档位不同"时生效；同档位重复记同一系统同一 code 会直接累加，且不报错不警告。禁止为补 step_id/vuln_id 关联而重记得分。这条教训用于防止后续所有角色污染得分台账。

## 用法

```
规则：① 一个成果只记一次分；② 若发现某得分点缺 step_id/vuln_id 关联，**只补 `redteam_chain_add` 步骤（且不要带 point_code/evidence，否则服务端会自动再记一次分）**；③ 若必须修正档位（如 10 分档提权到 50 分档），才允许再记一次并填高档 `points`，此时系统会顶掉低档那条；④ 发现台账被污染后，`redteam_score_hit` 无删除/回退参数（`demoted_hits` 返回空），只能人工去控制台「得分」页删除重复命中。
```
