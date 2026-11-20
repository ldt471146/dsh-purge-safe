# VerneMQ-over-WebSocket 匿名消息总线快速评估（无鉴权 CONNECT/SUB/PUB + 直连要求 + 空闲判定）

- **code**: vernemq-ws-anon-bus-eval
- **kind**: script
- **category**: unauthorized
- **component**: VerneMQ (Erlang/Cowboy, MQTT-over-WS)
- **source**: self
- **verified**: 1
- **verified_note**: 目标 example.com:8084（203.0.113.129）：匿名 MQTT CONNECT 收到 CONNACK 20020000（rc=0 accepted）；SUBSCRIBE '#'/'$SYS/#' 均 SUBACK 0x00；PUBLISH QoS1 到任意主题返回 PUBACK。480s 监听中 TOTAL_PUBLISH=3370（SYS=3362，非 $SYS 仅 CHECK 60s 周期健康检查 + 自投回显），无第三方消费者反应。
- **tags**: mqtt,vernemq,websocket,anonymous,unauthorized,message-bus,recon
- **created_at**: 2026-10-14T20:47:58.992Z

## 描述

评测任意 MQTT-over-WebSocket 端点（尤其 VerneMQ/EMQX/Cowboy）是否可零凭据读写，并判断其是否承载真实业务流量。要点：①必须直连——平台出口代理会让 ELB 的 WS upgrade 返回空/连接被丢，需清 http_proxy/https_proxy/all_proxy 且 http_proxy_host=None；②无 paho/mosquitto 时可自写最小 MQTT-over-WS 客户端（websocket-client 手搓 CONNECT/SUBSCRIBE/PUBLISH 帧，支持一帧多包解码）；③订阅 '#' 之外必须单独订阅 '$SYS/#'（'#' 不匹配 $ 开头主题）；④keepalive=60 不发 PINGREQ 时 broker 约 90-120s 主动重置连接，持久监听需周期 PINGREQ；⑤按 $SYS 判读集群/节点/桥接身份，并显式订阅 $SYS/broker/version 等 Mosquitto 风格键以判 broker 类型；⑥结论需区分「可读写 broker」与「有可用消费端」——若无业务主题流量、盲投注入无第三方消费反应，则不能升级为消息注入/XSS/SSRF。
