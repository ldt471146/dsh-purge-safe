# CN7 /jumpto/img SSRF 内网/云元数据不可达（边缘代理阻断，实测负面）

- **code**: cn7-jumpto-img-ssrf-内网-云元数据不可达-边缘代理阻断-实测负面
- **kind**: poc
- **category**: ssrf
- **component**: CN7 CMS 3.1.5 博彩平台（多租户）
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.16:10666 实测：/jumpto/img/ 代理外网图片成功(200/image/png)，但 127.0.0.1/localhost/RFC1918/169.254.169.254/203.0.113.11 全部 502(154B)或504(~5.5s)拒绝；nip.io/[::ffff:]/gopher/file/%00/302 等绕过均失败。判据：可达=200图片或SPA兜底92709B，被挡=502/504。
- **tags**: ssrf,CN7,图片代理,内网不可达,负面
- **created_at**: 2026-10-09T15:07:43.927Z

## 描述

补充 cn7-平台-jumpto-img-lt-url-gt-未授权开放图片代理-ssrf 的边界：该代理运行在 CDN/边缘(阿里云 ENS 香港，响应头 Via: ens-cache*.hk*/EagleId/X-Cache/X-Custom-Check:true)，出口在公网边缘网络，因此 loopback 指向边缘自身、RFC1918 到不了源站内网，内网 SSRF 被拓扑阻断，无法打内网服务或读云元数据。

## 用法

```
curl -k 'https://<目标>/jumpto/img/https://www.baidu.com/img/flexible/logo/pc/result.png'  # 200 image/png = 代理可用(仅外网)
curl -k 'https://<目标>/jumpto/img/https://127.0.0.1:10666/assets/logo/favicon.ico'  # 502/154B = 内网被挡
# 判定：仅外网 https 图片可代理；内网/元数据不可达，勿再投入内网 SSRF。
```
