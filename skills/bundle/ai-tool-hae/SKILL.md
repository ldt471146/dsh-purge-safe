---
name: ai-tool-hae
description: HaE —— Burp Suite 的高亮/提取插件（Hunter-AE），用正则规则把 HTTP/WebSocket/文件流量里的敏感信息（身份证、手机号、密钥、内网 IP、报错栈）自动标出来。信息侦察阶段提效最明显的一个。
---
# HaE（HTTP/文件 敏感信息高亮提取）

- 伞仓库：https://github.com/overspace-labs/HaE
- 网络版（Burp 插件）：https://github.com/overspace-labs/HaENet
- 文件版：https://github.com/overspace-labs/HaEFile
- AI 校验规则：https://github.com/overspace-labs/HaEValidator
- 2022 KCon 兵器谱入选；2026 Burp Extension Awards 提名最多

## 它解决什么问题

手工翻 Burp 的 Proxy/Repeater 历史，找「这个响应里有没有泄露手机号/内部接口/密钥」是纯体力活。
HaE 用**规则（正则 + 作用域 + 颜色 + 格式）**把命中项直接高亮在报文里，并按规则聚合到独立面板。

## 用法要点

1. HaE 面板 → 规则管理 → 导入/新建规则；
2. 每条规则四要素：`name` / `scope`（请求头/体、响应头/体、URL、WebSocket）/ `regex` / `format`（1=高亮 2=提取）；
3. 官方规则仓库 + 社区规则可直接导入，也可按项目自定义（比如某系统的订单号、内部 host 命名）；
4. 配合 Burp 的 **Project options → Misc → 高亮**，让命中项在 Proxy 历史里一眼可见。

## 我怎么用它

- **信息侦察**：代理全量流量，按 `内网IP|token|secret|身份证|手机号|邮箱|AK/SK|报错栈` 规则捞线索；
- **接口发现**：把响应体里的 `/api/v1/...` 路径全提取，直接喂 `dir-bruteforce`；
- **越权线索**：提取 `userId|uid|accountId` 字段名，配合 `cszh-exploiting-idor-vulnerabilities` 验证。

## 常见误报

`手机号` / `身份证` 这类规则误报率高，规则里要加边界（前后不能是数字）与校验位判断；
HaEValidator 就是干这个的（用 AI 二次判定），批量导出前跑一遍能省很多手工筛选。
