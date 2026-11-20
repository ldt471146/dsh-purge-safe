# 工作流程：使用 Frida 进行 iOS 逆向工程（Reverse Engineering）

## 工作流程 1：完整 iOS 逆向分析流水线

```
[获取 IPA/二进制] --> [解密 FairPlay] --> [静态分析] --> [动态分析]
                              |                  |               |
                       [frida-ios-dump]    [class-dump]    [frida-trace]
                       [Clutch]            [Ghidra]        [自定义 hook]
                                          [Hopper]        [方法拦截]
                                                                |
                                                        [提取密钥材料]
                                                        [映射逻辑流]
                                                        [记录调查结果]
```

## 工作流程 2：加密密钥提取

```
[Hook CommonCrypto] --> [捕获 CCCrypt 调用] --> [提取密钥材料]
                              |
                       [记录算法、模式、IV]
                       [记录输入/输出数据]
                              |
                       [重建协议]
                       [记录加密方案]
```

## 决策矩阵：iOS 逆向方法选择

| 二进制类型 | 静态工具 | 动态工具 | 备注 |
|-----------|---------|---------|------|
| Objective-C | class-dump + Ghidra | Frida ObjC.classes | 完整运行时可见性 |
| Swift（NSObject 基础）| dsdump + Ghidra | Frida ObjC.classes | 部分可见性 |
| 纯 Swift | Ghidra + Swift 反混淆 | Frida Module.enumerateExports | 有限运行时访问 |
| C/C++ 原生 | Ghidra | Frida Interceptor.attach | 基于地址的 hook |
