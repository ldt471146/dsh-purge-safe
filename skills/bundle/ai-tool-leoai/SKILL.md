---
name: ai-tool-leoai
description: LeoAI —— AI 驱动的后渗透综合管理平台（Java Agent + PHP Agent 双运行时，LangChain4j 接入多模型，内置内存马/WebShell 生成器与 100+ AI Tools）。用于把「拿到的一台机器」变成可编排的 C2 工作台，并让平台 AI 把任务下发给节点 AI 在被控会话里执行。
---
# LeoAI（AI 后渗透管理平台）

- 仓库：https://github.com/cha0upup/LeoAI ｜ GPLv3 ｜ Java 17+ ｜ Spring Boot 3.5 + LangChain4j
- 定位：**后渗透阶段的 C2 + 工作台**，不是扫描器。有合法授权时用来管理多台被控主机、编排 AI 任务、生成内存马/WebShell。

## 核心结构

```
平台 AI ── 分析主机/规则/插件/成果，把任务分发给 ↓
Node AI ── 在当前 Agent 会话上下文里调用工具、回传过程、交付结果
Agent Runtime ── Java(PHP 5.6+) 双运行时，能力按 Runtime Profile 动态声明
```

三件套值得记住：

| 模块 | 用途 |
|---|---|
| **内存马生成器** | 24 种中间件（Tomcat/Jetty/WebLogic/WebSphere/Undertow/Resin/GlassFish/TongWeb/Apusic/BES/Spring MVC/WebFlux/XXL-JOB/Dubbo…）× 49 种 Packer（OGNL/SpEL/EL/Groovy/Freemarker/MVEL/BeanShell/BCEL/Translet/XmlDecoder/H2…） |
| **流量伪装** | PayloadCodec = 序列化 → GZIP → AES，**伪装即通信密钥**，两端编解码必须一致 |
| **代理/隧道** | SOCKS5、HTTP(CONNECT)、`ssh -L` 本地转发、`ssh -R` 反向隧道，服务端监听地址可绑 `bindAddr` |

## 起服务

```bash
# 直接跑
java --add-opens java.base/java.lang=ALL-UNNAMED -jar LeoAi-3.0.0.jar     # 端口 8082，初始 admin/54ikun

# Docker（推荐，不折腾 JDK）
git clone https://github.com/cha0upup/LeoAI.git && cd LeoAI
docker compose up -d --build
```

数据是 SQLite（`data.db`），**v3.0.0 与历史库不兼容**，升级要换数据目录。

## 我怎么用它

1. **接模型**：管理后台 → AI 配置 → 加通道（OpenAI/通义/DeepSeek/Claude 兼容）→ 测连接；
2. **挂节点**：新增主机（URL + 协议 HTTP/Chunked/WebSocket + 访问密钥），密钥必须和 Shell 端一致；
3. **打隧道**：控制台 → 代理 → SOCKS5，Proxychains/Burp 上游指过去，再喂给 `fscan-intranet`/`gogo-intranet`；
4. **要权限**：内存马按中间件版本选 Packer，生成后拿 Core/Shell/Injector 三个 class 分开投递；
5. **留证据**：成果库按任务归档，报告里直接引用。

## 坑

- 必须带 `--add-opens java.base/java.lang=ALL-UNNAMED`，否则 `InaccessibleObjectException`；
- 内存马和 Packer 都跟中间件**版本强绑定**（TongWeb 6/7/8 的包名不同，XXL-JOB 2.0-2.1 用 Hessian、2.2+ 用 JSON），版本错就 500；
- 管理端口**别暴露公网**，前置 Nginx + IP 白名单。
