---
name: hfh-code-audit
description: 网络安全知识库「代码审计」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 12-代码审计-CodeAudit。按语言给出白盒/灰盒审计方法论与危险函数速查：PHP（注入、文件操作、反序列化）、Java（Spring/Struts2、反序列化、表达式注入）、Python（Django/Flask、SSTI、eval/反序列化）、JavaScript/Node.js（原型污染、命令注入、SSRF）、Go（SQL 注入、模板注入、竞态与配置）、C/C++（缓冲区溢出、格式化字符串、UAF、整数溢出）、Rust（unsafe 与 FFI）以及 AI Agent 代码审计（LangChain、Prompt 模板注入、工具函数命令注入、权限失控），含 10 份中文原文 references。
---

# 代码审计（Code Audit）

> 上游来源：<https://github.com/Hi-FullHouse/CyberSecurity-Skills> → `12-代码审计-CodeAudit`
> 本技能包由上游 10 个 Markdown 文件转存，正文是导航与一句话要点，**中文原文完整保留在 `references/`**。

## 使用方式

1. 先确认语言与框架，再打开对应文件；每个文件都带**危险模式（代码片段）+ 审计命令速查 + 工具**。
2. 审计目的通常是**为利用服务**：找到注入点后要能给出可复现的请求/Payload，而不是只列清单。
3. 结论落库时写清：文件与行、数据流（source → sink）、可利用性判断与利用前置条件。

## 知识清单（逐文件要点）

### 1. PHP 代码审计（PHP Code Audit）
- **一句话要点**：静态分析 PHP 代码找注入、文件操作与反序列化问题，**PHP 站点里这类洞最容易被直接打穿**。
- **覆盖**：常见 PHP 漏洞模式（SQL 注入、命令执行、文件包含与上传、代码执行 eval/assert、变量覆盖、反序列化）、危险函数清单、框架（ThinkPHP 一类）审计切入点、静态分析工具。
- **原文**：`references/PHP-PHPCodeAudit.md`

### 2. Java 代码审计（Java Code Audit）
- **一句话要点**：审 Java Web 与框架（Spring/Struts2）的特有漏洞与通用缺陷，**反序列化与表达式注入是重灾区**。
- **覆盖**：Java Web 漏洞模式、Spring/Struts2 框架漏洞、反序列化与 gadget 链、表达式与模板注入、文件上传与路径穿越、权限与鉴权缺陷、组件版本（Nday）核对、工具链。
- **原文**：`references/Java-JavaCodeAudit.md`

### 3. Python 代码审计（Python Code Audit）
- **一句话要点**：审 Django/Flask 等应用与运行时风险，**SSTI、eval/exec、反序列化（pickle/yaml）最常见**。
- **覆盖**：Python Web 框架审计（Django/Flask 配置与视图、模板渲染）、命令执行与注入、pickle/yaml 反序列化、SSRF 与文件操作、依赖与配置泄露、工具（bandit 一类）。
- **原文**：`references/Python-PythonCodeAudit.md`

### 4. JavaScript 代码审计（JavaScript / Node.js Code Audit）
- **一句话要点**：前端 XSS 与后端 Node.js 风险一起审，**原型污染与命令注入是 Node 侧高频问题**。
- **覆盖**：Node.js Web 安全（命令注入、模板注入、SSRF、路径穿越）、原型污染与依赖链风险、客户端 XSS 与 DOM sink、npm 供应链与依赖审计、工具。
- **原文**：`references/JavaScript-JSCodeAudit.md`

### 5. Go 代码审计（Go Code Audit）
- **一句话要点**：Go 内存安全但**不等于没有漏洞**——注入、竞态、配置与加密误用需专门看。
- **覆盖**：SQL 注入（拼接与 ORM 误用）、模板与命令注入、SSRF 与文件操作、竞态条件与并发缺陷、加密 API 误用与配置错误、`gosec` 等审计命令速查。
- **原文**：`references/Go-GoCodeAudit.md`

### 6. C 代码审计（C Code Audit）
- **一句话要点**：C 代码审计核心是**内存安全、未定义行为与危险库函数**，直接决定能否 RCE。
- **覆盖**：缓冲区溢出（栈/堆）、格式化字符串、整数溢出与符号问题、释放后使用（UAF）与双重释放、危险函数清单（strcpy/sprintf/gets…）、静态分析与动态验证工具。
- **原文**：`references/C-CCodeAudit.md`

### 7. C++ 代码审计（C++ Code Audit）
- **一句话要点**：在 C 的问题之外，还要看**虚函数劫持、智能指针误用、STL 与异常安全**。
- **覆盖**：继承自 C 的内存问题、虚表与对象生命周期、智能指针与双重释放、STL 容器与迭代器失效、异常安全与模板元编程风险、审计命令速查（grep 危险函数）。
- **原文**：`references/C++-CPPCodeAudit.md`

### 8. Rust 代码审计（Rust Code Audit）
- **一句话要点**：Rust 的安全保证**只在 Safe Rust 内成立**——`unsafe`、FFI 与不安全宏是审查重点。
- **覆盖**：`unsafe` 代码块审计、FFI 边界与内存布局、不安全的宏与第三方 crate、整数与切片越界、审计命令速查（grep unsafe）。
- **原文**：`references/Rust-RustCodeAudit.md`

### 9. AI Agent 代码审计（AI Agent Code Audit）
- **一句话要点**：结合传统审计与 AI 特有风险，**覆盖 LangChain 等 Agent 编排、Prompt 模板、工具函数与 RAG 管道**。
- **覆盖**：LangChain 应用审计；五类危险模式——① Prompt 模板注入（用户输入直接拼接）② 工具函数命令注入（未校验参数拼接 Shell）③ 敏感信息泄露（错误信息含凭据）④ Agent 权限失控（可创建/修改其他 Agent）⑤ 循环调用未限制；四组审计 Checklist（Tool 实现、Prompt 安全、Agent 配置最小权限、依赖版本锁定）；工具链。
- **原文**：`references/AI-Agent-AIAgentCodeAudit.md`

### 10. 分类导读（README）
- **一句话要点**：上游该分类的官方目录说明（阶段目标：白盒/灰盒审查源代码发现代码层漏洞）。
- **原文**：`references/README.md`

## 审计纪律

- **数据流优先**：每条结论给出 source（用户输入点）→ 传播路径 → sink（危险函数）三段，缺一段就是不可利用的猜测。
- **版本对齐 Nday**：组件与框架先核对版本，命中公开漏洞的优先（性价比高于手工挖逻辑）。
- **不修剪风险描述**：报告中如实区分「可远程无认证利用」「需登录」「需特定配置」。
- **审计结论要能落地**：给出最小验证请求或 PoC 片段，而不是仅列出危险函数名。
