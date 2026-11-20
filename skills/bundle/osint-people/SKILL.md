---
name: osint-people
description: '人员与资产开源情报（OSINT）+ 本地离线泄露库检索：从公开源（企业公示、证书透明、GitHub、领英/招聘、公众号、备案、WHOIS）拼出"这个人是哪个单位的、用什么邮箱、有哪些账号"，再用手上的离线 sqlite/csv 库做字段命中（邮箱/手机/QQ/微博/GitHub/公司域名），输出实体关系图与可溯源台账。用于授权演练中的人员维度画像、账号归属确认、凭据暴露关联、钓鱼目标筛选；也可做企业域名下的泄露自查。'
---

# 人员与资产情报（OSINT + 离线库）

两条腿走路：**公开源做主干（永远可溯源）**，**离线库只做补充命中（数据在你手上，不出网）**。

## 一、三条数据层，别混用

| 层 | 数据从哪来 | 是否出网 | 能写进报告吗 |
|---|---|---|---|
| A 公开源 | 企业公示、crt.sh、FOFA、GitHub、领英/招聘、公众号、备案、WHOIS | 是 | 能，每条带 URL |
| B 自查型 | HIBP（按域名）、DeHashed（查自己）、GitHub secret scanning | 是 | 能，注意别把库原文抄进报告 |
| C 离线库 | 使用者自备 sqlite/csv（字段：email/phone/qq/weibo/github/company/pass_hash） | **否** | 只写"命中 N 条 + 字段类型"，不落地明文 |

> C 层查询一律本地跑：`--db` 只指向本机文件，脚本不发任何网络请求。

## 二、公开源主干（先跑这四条，通常够用）

```bash
# 1) 域名 → 子域 → 证书（不碰目标）
subfinder -d DOMAIN -all -silent | dnsx -silent -a -resp
curl -s "https://crt.sh/?q=%25.DOMAIN&output=json" | jq -r '.[].name_value' | sort -u

# 2) 邮箱格式与人员（招聘页/领英公开页/公众号）
#    搜索式：site:linkedin.com/in "公司名" 职位
#    site:zhipin.com "公司名" 技术
#    GitHub：org 成员、commit author 邮箱
curl -s "https://api.github.com/orgs/ORG/members" | jq -r '.[].login'
curl -s "https://api.github.com/repos/ORG/REPO/commits?per_page=100" | jq -r '.[].commit.author.email' | sort -u

# 3) 企业/法人/股权（公开）
#    国家企业信用信息公示系统 / 天眼查公开页 手工核，别爬

# 4) 泄露自查（自己的域名）
#    HIBP: https://haveibeenpwned.com/DomainSearch
```

产出：`邮箱候选集` + `账号候选集` + `人员-单位映射`，全部带出处。

## 三、离线库查询（本地，离线）

```bash
python scripts/shegong_query.py --db SHEGONG_DB --field email  --value user@corp.com
python scripts/shegong_query.py --db SHEGONG_DB --field phone  --value 13800000000
python scripts/shegong_query.py --db SHEGONG_DB --field domain --value corp.com --limit 200
```

- 支持 `.sqlite/.db`（自动定位表与字段）和 `.csv/.txt`（冒号或制表符分隔）。
- 每次查询自动写 `ledger.jsonl`：时间、字段、值、命中条数、库指纹（不写明文结果）。
- `--limit` 默认 200，防止一次拉出成千上万条（台账里会显示实际命中）。
- `--dry-run` 只回表结构与字段名，不查值——第一次摸底用。

## 四、实体关联与输出

字段关系：

```
email ──┬─ phone ──┬─ qq
        │           └─ weibo/wechat
        ├─ github ── commit email
        └─ company ── domain ── subdomain ── cert ── ip
```

输出模板（可直接贴报告）：

```json
{
  "entity": "user@corp.com",
  "sources": [
    {"layer":"A","url":"https://crt.sh/?q=corp.com","fact":"域名下 37 个子域"},
    {"layer":"A","url":"https://github.com/ORG","fact":"3 个成员的 commit 邮箱同域"},
    {"layer":"C","db":"SHEGONG_DB","matched_fields":["email","phone"],"count":4}
  ],
  "links": [["user@corp.com","phone:138****"],["user@corp.com","github:login"]]
}
```
口诀：**A 层给事实，C 层给数量**；报告里不抄库原文，只写命中字段与条数。

## 五、坑（都踩过）

- 库越旧越错：2021 年前的手机号/身份证错配率很高，别拿它做"精准"判断。
- 错配会连带：一个邮箱命中别人手机号，追下去整条链都歪。
- 免费查询站多是钓鱼/收号：要登录、要充值的站点一律不碰。
- 查询留痕：付费记录、IP、客户端指纹全链条留存，比自己以为的清楚。
- 命中量要记账：行踪/通信/征信/财产类 50 条、住宿/健康/交易类 500 条、其它 5000 条就是量刑分档线，台账里必须能看到累计数。

## 六、跟其它技能怎么串

- 子域与端口 → `recon-pipeline`、`active-scan`
- 泄露 token/口令 → `credential-attack`（离线哈希部分）、`gitleaks`/`trufflehog`
- 人员目标筛选后打钓鱼 → `hfh-social-engineering`（GoPhish 模板）
- 报告输出 → `cyberskills-osint-recon` 的 evidence 结构
