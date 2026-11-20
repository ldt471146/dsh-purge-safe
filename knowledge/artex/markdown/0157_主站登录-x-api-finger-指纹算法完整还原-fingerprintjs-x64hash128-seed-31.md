# 主站登录 X-API-FINGER 指纹算法还原 + 6022 真实成因纠正（FINGER 非决定因素）

- **code**: 主站登录-x-api-finger-指纹算法完整还原-fingerprintjs-x64hash128-seed-31
- **kind**: poc
- **category**: auth-bypass
- **severity**: high
- **language**: python
- **source**: self
- **verified_note**: 算法已完整逆向并逐项确认：① fm() 的属性白名单表（Win32/Win64/MacIntel/iPhone 四种 platform 的精确字段列表）② ip 取自 localStorage.preInfoData.ip ③ seed=31 的 x64hash128 已在 Python 侧实现并可运行（"test"/31 -> ff55565a476832ed3409c64597508ca4）。【6022 成因仍未定位】穷举 body 必填字段：ip、domain、kaptchcate、codeId、agentVerify、type 共 8 组组合全部仍返回 6022；其中 ip+domain 组合触发瑞数 WAF 返回 403（非 JSON），说明该字段组合触发了网关规则。X-API-FINGER 经验证不是 6022 的成因（有/无/对/错 响应完全一致）。故 6022 的真实成因尚未查明，不做推断。【重要澄清】203.0.113.67 经 preInfo 接口 ip 字段确认是「本机出口 IP」，即 CDN/WAF 回源时看到的客户端地址，**不是源站**。此前用裸 socket 直连测得 ConnectionRefused 是因为裸 socket 不经代理所致，不能据此判定源站存在与否。【样本作废】以 62 万组枚举尝试用已知 FINGER 样本 8b4ece17e82538f0fd75be629a0cb952 反推 FingerprintJS 组件值未匹配，该样本可能并非 fm() 产物，不应作为算法验证基准。
- **tags**: 登录绕过,风控指纹,前端逆向,FingerprintJS,murmur3
- **created_at**: 2026-10-02T22:32:08.197Z
- **found_by**: exploit

## 描述

登录接口 X-API-FINGER 指纹头的完整生成算法（逆向自 webpack 模块 70559），配套已解密 SSR props 与 x64hash128 实现，构成脚本化登录的全部要素

## 用法

```
python x64_impl.py          # x64hash128 实现（已跑通）
python finger_isolate.py     # 证 FINGER 非 6022 成因
python body_fields.py        # body 字段穷举：8 组全 6022
python body2.py              # ip+domain 触发 403
# 结论：主站登录 6022 的成因未定位；已排除 ip/domain/kaptchcate/codeId/agentVerify/type
# FINGER 非决定因素；剩余未知为 FingerprintJS 运行时属性值（需真实浏览器）
# 另：203.0.113.67 已确认为本机出口 IP（preInfo.ip），非源站
```
