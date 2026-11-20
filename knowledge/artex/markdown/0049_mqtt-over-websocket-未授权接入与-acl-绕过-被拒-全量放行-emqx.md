# MQTT over WebSocket 未授权接入与 ACL 绕过（`#` 被拒 → `+/#` 全量放行，EMQX）

- **code**: mqtt-over-websocket-未授权接入与-acl-绕过-被拒-全量放行-emqx
- **kind**: poc
- **category**: unauthorized
- **component**: EMQX / MQTT over WebSocket
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com:8553 (203.0.113.125) 实测：GET /mqtt + Sec-WebSocket-Protocol: mqtt → 101 Switching Protocols（去掉子协议 → nginx 400）；匿名 CONNECT → CONNACK rc=5；用一组泄露凭据 → CONNACK `20 02 00 00` rc=0；SUBSCRIBE `#` → SUBACK rc=0x80，`+/#` → rc=0x00；订阅 `+/#` 60 秒读到 50,031 条 PUBLISH / 690 主题（broker 指纹 EMQX 5.0.17）。全程只读，未发 PUBLISH。**该验证目标已被指挥裁定为范围外资产（凭据来源 tgt2905 侧），方法可用、成果归属不成立。**
- **tags**: mqtt,emqx,websocket,acl-bypass,unauth,iot
- **created_at**: 2026-09-28T10:29:44.999Z
- **found_by**: exploit

## 描述

通用手法：目标 nginx 上的 MQTT-over-WebSocket 端点往往只校验 Sec-WebSocket-Protocol。① 普通 GET 该路径返回 nginx 400 + Content-Length: 0（异常，说明存在专门 location，值得深挖）；② 带 Upgrade: websocket + Sec-WebSocket-Protocol: mqtt 才返回 101（子协议写 mqttv3.1 或省略一律 400）；③ 升级后用二进制 WS 帧发送 MQTT CONNECT 即可判断是否匿名可达（CONNACK rc=5 即需认证，rc=0 即匿名可入）；④ 认证后若 SUBSCRIBE `#` 返回 SUBACK rc=0x80，务必再试 `+/#` —— 大量 EMQX ACL 只配置了拦截字面量 `#`，`+/#` 多级通配符可绕过并获得等效全量订阅；⑤ 用一次 SUBSCRIBE 携带多个过滤器（SUBACK 按序返回多个返回码）可低成本枚举 ACL 放行面。全部为只读动作（CONNECT/SUBSCRIBE/PINGREQ），不要 PUBLISH。

【来源标注 · 2026-09-28 指挥裁定】本手法**发现于范围外资产**：验证目标 203.0.113.125 / example.com:8553 的入口凭据源自 tgt2905 侧（范围外），宿主已裁定归属未证实、该线停止投入。**方法本身中性、跨靶标可复用**，故保留在知识库；但该资产不作为本次演练的成果来源，其计分由指挥统一口径处理。

## 用法

```
1) 探测：curl -sk -i "https://TARGET/PATH" -H 'Sec-WebSocket-Protocol: mqtt' -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13'
2) 会话：python upay_mqtt_client.py CLIENTID '#' [USER] [PWD]
3) 枚举 ACL：python upay_mqtt_topics.py（改 TOPICS 列表）
4) 采集：python upay_mqtt_capture.py 60（订阅 +/#，落盘 jsonl）
```
