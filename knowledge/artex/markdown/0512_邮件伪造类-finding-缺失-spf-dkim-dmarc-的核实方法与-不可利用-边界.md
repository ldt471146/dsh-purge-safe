# 邮件伪造类 finding（缺失 SPF/DKIM/DMARC）的核实方法与「不可利用」边界

- **code**: 邮件伪造类-finding-缺失-spf-dkim-dmarc-的核实方法与-不可利用-边界
- **kind**: script
- **category**: info-leak
- **component**: DNS / Email Authentication (SPF-DKIM-DMARC)
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-04 对 winners.club/junshengkj.xyz/i663r4.com/jau5ml.top/vz4wu8.com：dnspython@8.8.8.8/1.1.1.1 + nslookup@8.8.8.8 复核，TXT 仅 winners.club 一条 protonmail-verification，MX 全 NODATA，_dmarc NXDOMAIN/NODATA，13 个 DKIM selector 全无；13 个邮件前缀(mail/smtp/webmail/imap/pop/mx/mx1/email/newsletter/em/edm/notify/support)×5 域 A+MX 全 NXDOMAIN/NODATA，不存在邮件基础设施。
- **path**: pocs/邮件伪造类-finding-缺失-spf-dkim-dmarc-的核实方法与-不可利用-边界/poc.py
- **tags**: email-spoofing,spf,dkim,dmarc,dns,negative,roe
- **created_at**: 2026-11-04T12:07:20.312Z
- **engine**: winners.club
- **found_by**: exploit

## 描述

适用条件：目标域被报「无 SPF/DKIM/DMARC，可伪造发件人」。核实=只读 DNS；利用=必须向真实第三方收件人投递伪造邮件，通常属 RoE 明确排除或超出授权范围，且收件人不是授权目标。若目标同时无 MX/无邮件主机，则不存在服务器侧入口，无法转化为权限/数据/会话。判据：_dmarc 返回 NXDOMAIN/NODATA 且 apex 无 v=spf1、无 DKIM selector、无 MX。

## 用法

```
python mail_auth_check.py；只读 DNS，不发起任何 SMTP。若目标是纯静态/CDN 站且无 MX/邮件主机，应直接给「配置类、无实际可利用入口」结论，不做投递。
```

## 正文

```
#!/usr/bin/env python3
# 只读核实：5 域 SPF/DKIM/DMARC/MX 与常见邮件前缀
# 依赖 dnspython: pip install dnspython
import dns.resolver, dns.exception

R = dns.resolver.Resolver(configure=False)
R.nameservers = ['8.8.8.8', '1.1.1.1']; R.timeout = 5; R.lifetime = 8
doms = ['winners.club', 'junshengkj.xyz', 'i663r4.com', 'jau5ml.top', 'vz4wu8.com']
selectors = ['default','selector1','selector2','google','k1','mail','dkim','s1','s2','smtp','protonmail','pm','proton']
prefixes = ['mail','smtp','webmail','imap','pop','mx','mx1','email','newsletter','em','edm','notify','support']

def q(name, rt):
    try:
        return 'OK ' + ' | '.join(str(x) for x in R.resolve(name, rt))
    except dns.resolver.NXDOMAIN: return 'NXDOMAIN'
    except dns.resolver.NoAnswer: return 'NODATA'
    except dns.exception.Timeout: return 'TIMEOUT'
    except Exception as e: return type(e).__name__ + ':' + str(e)[:60]

for d in doms:
    print('===== ' + d + ' =====')
    for rt in ('TXT','MX','NS'):
        print(rt, q(d, rt))
    print('DMARC', q('_dmarc.' + d, 'TXT'))
    print('DKIM', '; '.join(s+'='+q(s+'._domainkey.'+d,'TXT') for s in selectors))
    for p in prefixes:
        fq = p + '.' + d
        a, mx = q(fq,'A'), q(fq,'MX')
        if a not in ('NXDOMAIN','NODATA') or mx not in ('NXDOMAIN','NODATA'):
            print('MAILHOST', fq, a, mx)

# 判定：
# 全部 _dmarc=NXDOMAIN/NODATA、无 v=spf1、DKIM 无、无 MX/无邮件前缀主机
#  => 伪造技术前提成立，但无服务器侧可打面；唯一利用是向第三方投递伪造邮件（通常 RoE 排除）。
# 若出现 v=spf1 且 -all / _dmarc p=quarantine|reject => 该 finding 应被证否。

```
