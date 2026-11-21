# 自研 App 网关 46750 /notices 的 token 字段 SQLi 阴性（引号/布尔/无引号三组 10 发逐字节同一 ret=2，且 token 门禁先于其它参数）

- **code**: 自研-app-网关-46750-notices-的-token-字段-sqli-阴性-引号-布尔-无引号三组-10-发
- **kind**: poc
- **category**: sqli
- **component**: 自研 App 后端网关（POST /notices、/userid、/notarialdata，IIS+.NET JSON，静态盐 private_* 可离线伪造 verify）
- **source**: self
- **verified**: 1
- **verified_note**: task#614（2026-11-04）。两台生产 accessurl 共 10 发只读 POST，每发 verify 按注入值离线重算且全部被服务端接受（无任何一发退回 ret=1）：token="123"(基线)/123'/123' OR '1'='1/123' OR '1'='2/123 OR 1=1/123 OR 1=2 全部 HTTP 200 / 39B / {"ret":2,"msg":"账号认证失败！"} 逐字节一致，耗时 cbob 1.83–2.10s、110.41.227.204 0.39–0.41s，差 <0.5s；/userid 的 account="testcc'"、/notarialdata 的 tableid="999999'" 同样只回同一 ret=2，说明 token→账号门禁先于其它参数查询。
- **tags**: sqli-negative, 签名伪造, 静态盐, verify, token门禁, IIS, dotnet, 有界只读, 决策判据, 46750, accessurl
- **created_at**: 2026-11-04T15:50:52.825Z
- **engine**: https://cbob.evuzp9.com:46750, https://110.41.227.204:46750

## 描述

该网关的 verify 可离线伪造（静态盐 private_notices/private_queryuserid/private_notarialdata），因此 token 等字段可承载任意注入串且签名仍合法；但在两台生产主机上引号、布尔真假、无引号数字三组形态共 10 发全部与基线逐字节一致（200/39B ret=2），不构成 SQL 注入，且 token 校验先于其它参数处理。

## 用法

```
遇到同族网关（verify=UPPER(MD5(排序裸拼+静态盐 private_&lt;route&gt;))，盐与字段集客户端可读）想打 SQLi 时，可直接跳过 token 字段的注入尝试：先把基线发一次（正确签名 + token=123 → 200/39B ret=2），再发 token="123'" 与 "123' OR '1'='1"/"123' OR '1'='2"，若三者逐字节一致即判注入面在 token 层封闭。注意两点：①真布尔对用 OR 而不是 AND——token 值本身不存在于库中，AND 对两种形态都返回空集，无法分叉；②非 token 字段（account/tableid/userid）带引号仍只回 ret=2，说明它们在 token 门禁前不可达，别在这些字段上浪费帧。下一步应转协议层（36610 登录帧，wire type 0x2001/8193）而不是继续加注入 payload。
```
