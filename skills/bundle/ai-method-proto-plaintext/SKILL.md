---
name: ai-method-proto-plaintext
description: 方法：用 AI 自动化还原 protobuf 流量（.proto 缺失时的字段推断与明文化）。来源：奇安信攻防社区《利用AI一键开启proto全自动明文时代》。用于 App/小程序 gRPC 或 protobuf 协议抓包后「看得懂、改得动」。
---
# protobuf 流量明文化（AI 自动化）

- 原文：https://forum.butian.net/ai_security/90 《利用AI一键开启 proto 全自动明文时代》
- 适用：App / 小程序 / gRPC-Web 走 `application/grpc`、`application/x-protobuf`，抓包只看到二进制。

## 为什么以前难

protobuf 是**按 .proto 定义解释字节**的：字段号 + wire type 决定含义，
没有 `.proto` 时，一串 `08 96 01 12 03 61 62 63` 只能靠人工猜字段语义。

## 现在的套路（原文思路 + 我的落地）

1. **拿样本**：Burp/mitmproxy 抓同一接口的**多条**请求/响应（同接口不同参数值，字段边界才能推断）；
2. **反推结构**：
   - 先用通用脚本解 wire format（varint / length-delimited / fixed32/64），列出 `字段号 → 类型 → 取值分布`；
   - 把「字段号 + 类型 + 同接口多次取值 + 相邻字段共现」喂给模型，让它推断字段语义（用户 ID、时间戳、枚举、列表）；
3. **生成 .proto**：模型产出 `message` 定义 → 用 `protoc --decode_raw` / `protoc --decode` 双向验证：
   解出来的字段必须能**无损重新编码回原字节**（这是最硬的正确性判据）；
4. **迭代**：新接口/新版本再跑一轮，把推断结果并进同一个 .proto 库；
5. **接入 Burp**：写个 Burp 插件/扩展做 protobuf 编解码，之后 Repeater 里就是明文 JSON/表格，改字段直接重放。

## 关键判据（别跳）

```
decode(bytes) -> struct -> encode(struct) == bytes   # 字节级往返一致
```
只要往返不一致，说明字段类型或字段号推错了，模型给的语义再合理也是错的。

## 我怎么用它

- 配合 `decrypt-tools`（先解密）→ 本方法（再明文化）→ `cszh-exploiting-idor-vulnerabilities` / `cszh-exploiting-broken-function-level-authorization`（改字段测越权）；
- 枚举类字段靠**差分**：同接口改一个参数，看哪个字段值变了，语义立刻清楚。

## 限制

- 加密/压缩过的 protobuf（gRPC 常见 gzip + TLS）必须先解密解压；
- oneof / map / repeated 嵌套靠单条样本推不出来，必须多条样本 + 试探性改包验证。
