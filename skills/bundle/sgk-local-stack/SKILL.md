---
name: sgk-local-stack
description: '本地离线社工库查询站两套可跑实现：① PHP（Sky_Sgk，Smarty 模板 + 验证码 + 邀请码 + 后台 + Sphinx 查询接口）；② Django 2.0（SocialRelations_Web，单表 Socialusers + 关系图谱页）。含字段模型、部署步骤、CSV→SQLite 导入脚本、查询接口与改造点。用于把离线数据做成可查询的本地检索台（命中台账、按字段反查、关系图），而不是依赖第三方机器人。'
---

# 本地查询站（PHP Sky_Sgk / Django SocialRelations）

素材：
```
C:\Users\Administrator\.dsh\skills-src\CplusHua01__cms\cms-master\                    697 文件
C:\Users\Administrator\.dsh\skills-src\J-R-hacker__SocialRelations_Web\SocialRelations_Web-master\   24 文件
```

## 一、两套栈怎么选

| | PHP Sky_Sgk | Django SocialRelations |
|---|---|---|
| 年代 / 栈 | 2015，PHP5.6+Smarty+Sphinx | 2018，Python3 + Django 2.0 |
| 强项 | 验证码/邀请码/后台/分页，像"对外服务"的站点 | 单表查询快，自带**关系图谱**页 |
| 数据层 | MySQL + Sphinx 索引（`source/sgk/sgk.api.php`） | SQLite（`db/ScocialEngineer.db`），单表 `Socialusers` |
| 起量成本 | 高（Sphinx 要建索引） | 低（一条 `manage.py runserver`） |
| 适合 | 多人共用、要权限控制 | 单机查、要关系图 |

先跑 Django 那套摸底，需要"像产品"再上 PHP。

## 二、Django 版（分钟级可用）

```bash
cd SocialRelations_Web-master
python -m venv .venv && . .venv/Scripts/activate      # Windows: .venv\Scripts\activate
pip install "django==2.0.13"                          # 原项目锁 2.0.x
python manage.py migrate
python manage.py runserver 0.0.0.0:8000               # 打开 http://127.0.0.1:8000
```

> Python 3.10+ 装 Django 2.0 会报 `ImportError: cannot import name 'Iterator'`（collections 变更）。两条路：
> ① 用 Python 3.8/3.9 跑原版；② 换 `django==3.2`，把 `urls.py` 的 `url()` 改 `re_path()`，其余基本不动。

数据模型（`socialdb/models.py`，单表 `Socialusers`）：

```
username password chinesename(email字段映射到 chineseName) email
qq(QQ) weibo identity_number cell_phone ip_address college living_place source remarks
```

导入自己的 CSV（`scripts/import_csv.py`，见本技能同目录）：

```bash
python scripts/import_csv.py --db db/ScocialEngineer.db --csv DATA.csv --table Socialusers
python scripts/import_csv.py --db db/ScocialEngineer.db --csv DATA.csv --dry-run   # 只看列映射
```

查询与关系：
- 首页 `''` → `views.index`：按字段查；`views.py` 13 KB，含分页与"关联人"逻辑。
- 关系图：同一 `cell_phone` / `email` / `identity_number` 命中的多条记录聚成一个节点簇，前端渲染力导图。

## 三、PHP 版（要权限与对外形态时）

```
config.php              数据库/站点配置
init.php                初始化
captcha.php             验证码
source/admin.php        后台
source/sgk/sgk.api.php  Sphinx 查询接口（核心）
source/sgk/sgk.inc.php  连接配置
themes/default/         Smarty 模板
install/                安装与 rewrite 规则
```

部署：

```bash
# 1) PHP 7.4 + MySQL 5.7 + Sphinx 2.2（或 3.x）
# 2) 建库导表，改 config.php 里的 db host/user/pass
# 3) Sphinx 索引（示例）
index socialusers
{
    source           = socialusers_src
    path             = /var/lib/sphinx/socialusers
    sql_query        = SELECT id, username, email, cell_phone, identity_number, source FROM Socialusers
    sql_field_string = username
    sql_field_string = email
    sql_field_string = cell_phone
}
# 4) searchd 起服务，改 sgk.inc.php 指向 127.0.0.1:9312
# 5) 站点根指到 cms-master，跑 install/，设置邀请码与管理员
```

查询接口形态（改造时保持这个约定，前端不用动）：

```
GET sgk.api.php?q=KEYWORD&field=email|phone|qq|name&page=1&size=20
→ {"total":123,"page":1,"items":[{"id":1,"email":"a***@corp.com","phone":"138****0001","source":"SRC_A"}]}
```

## 四、必做的三个改造（原版都不带）

1. **脱敏输出**：默认只回 `a***@corp.com` / `138****0001`，要全量必须显式 `--full` 且写台账。
2. **命中台账**：每次查询落一行（时间、字段、值哈希、命中数、操作者），格式同 `osint-people` 的 `ledger.jsonl`。
3. **限速与鉴权**：单 IP 每分钟 N 次、邀请码/账号登录，防止被当成公开服务打。

## 五、坑

- Django 2.0 的 `views.py` 用了 `request.is_ajax()`，Django 4 已移除 → 升 3.2 时改成 `request.headers.get('x-requested-with') == 'XMLHttpRequest'`。
- SQLite 单文件并发差：多人用换 MySQL/PostgreSQL，`settings.py` 改 `DATABASES`。
- PHP 那套依赖 `mod_rewrite` 与 `install/rewrite.txt`，Apache 直接照抄；Nginx 要自己写 `try_files`。
- 索引与表字段必须同名同序，否则 Sphinx 查出来字段错位（`sql_field_string` 少一个就少一列）。
- 老代码没做 SQL 注入防护：`source/class/DB.class.php` 里的拼接查询要先过一遍参数化再上线。

## 六、和别的技能怎么串

- 数据来源与字段甄别 → `sgk-catalog`
- 公开源补全（企业/域名/邮箱规则）→ `osint-people`
- 报告与台账口径 → `cyberskills-osint-recon`
