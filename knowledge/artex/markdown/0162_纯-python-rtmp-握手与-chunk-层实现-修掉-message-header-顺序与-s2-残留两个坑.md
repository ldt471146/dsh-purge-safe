# 纯 Python RTMP 握手与 chunk 层实现（修掉 message header 顺序与 S2 残留两个坑）

- **code**: 纯-python-rtmp-握手与-chunk-层实现-修掉-message-header-顺序与-s2-残留两个坑
- **kind**: script
- **category**: protocol
- **component**: SRS (Simple Realtime Server) 5.0.210
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-03 在 example.com:1935（SRS 5.0.210 Bee）跑通：connect → amf0Command _result txn=1 → code=NetConnection.Connect.Success, description="Connection succeeded"，并解出服务端指纹 srs_server=SRS/5.0.210(Bee)、srs_version=5.0.210、srs_server_ip=172.28.93.122。5 组 tcUrl 对照响应完全一致。修复前所有用例表现为 post_hs_bytes=0。
- **tags**: rtmp,amf0,srs,protocol,fuzzing,harness,auth-probe
- **created_at**: 2026-10-03T09:07:56.784Z
- **found_by**: vuln-scan

## 描述

RTMP 协议握手的 chunk 层有一个容易踩的坑：fmt=0 的 message header 是 11 字节，字段顺序固定为 timestamp(3,BE) → length(3,BE) → typeId(1) → streamId(4,LE)。写错顺序服务端会静默丢弃全部 chunk，表现为「握手 4/4 成功但命令发出去没回包」，很容易误判成服务端在过滤。第二个坑：SRS 在收到 C0+C1 后会一次性回 3073 字节（S0+S1+S2），如果只 drain 1537 字节，剩余 1536 字节会被当成 chunk 头解析，导致所有回包都变成 type0/len0。本脚本修好了这两点，只做 connect 不 publish。

## 用法

```
python rtmp_connect_probe.py cases.json

cases.json = [[标签, tcUrl], ...]
对同一节点跑「有效凭证 / 无凭证 / 伪造凭证」三组，若三者 _result 完全一致 → 说明该层不校验凭证（凭证校验在 publish 层），此时不能据此认定凭证有效。
```
