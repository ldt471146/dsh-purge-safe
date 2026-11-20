# 纯 Python AWS SigV4 实现：无 awscli/boto3 时实测 AWS 凭据有效性（STS GetCallerIdentity）

- **code**: 纯-python-aws-sigv4-实现-无-awscli-boto3-时实测-aws-凭据有效性-sts-getcalleridentity
- **kind**: script
- **category**: methodology
- **component**: AWS STS / SigV4
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 自检通过：用 AWS 官方文档示例假凭据 AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI... 调用，返回 HTTP 403 <Code>InvalidClientTokenId</Code>（"The security token included in the request is invalid."）而非 SignatureDoesNotMatch，证明 canonical request / string-to-sign / signing key 全链签名实现正确，仅凭据本身无效。本靶标因 AWS Launcher 的 accounts 表被证实为空、未取得真实凭据，故未能在真实有效凭据上端到端验证。
- **path**: pocs/纯-python-aws-sigv4-实现-无-awscli-boto3-时实测-aws-凭据有效性-sts-getcalleridentity/aws_sigv4_sts_check.py
- **tags**: aws,sts,sigv4,凭据验证,云凭据
- **created_at**: 2026-09-27T19:15:24.415Z
- **found_by**: exploit

## 描述

无 boto3/awscli 环境下用纯 Python 手写 AWS SigV4，直接调用 STS GetCallerIdentity 实测凭据有效性。用于拿到别人给的/挖到的 AWS access key 后快速判定是否真实有效（返回 Arn/Account/UserId 即有效）。自检方法：用 AWS 官方文档示例假凭据调用，若返回 403 InvalidClientTokenId（而非 SignatureDoesNotMatch），说明签名实现正确、仅凭据无效。

## 用法

```
python aws_sigv4_sts_check.py <ACCESS_KEY_ID> <SECRET_ACCESS_KEY> [SESSION_TOKEN]
有效时返回 HTTP 200 与 <GetCallerIdentityResult><Arn>/<Account>/<UserId>；
无效凭据返回 403 InvalidClientTokenId；签名写错返回 403 SignatureDoesNotMatch（可据此自检实现）。
需要长期凭证或临时凭证（临时凭证必须带 session_token）。
```

## 正文

```
import hashlib, hmac, datetime, urllib.request, urllib.error

def _sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def _sig_key(secret, datestamp, region, service):
    k = _sign(("AWS4" + secret).encode("utf-8"), datestamp)
    k = _sign(k, region); k = _sign(k, service); k = _sign(k, "aws4_request")
    return k

def sts_get_caller_identity(ak, sk, session_token=None, region="us-east-1", timeout=25):
    host, service = "sts.amazonaws.com", "sts"
    now = datetime.datetime.now(datetime.timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ"); datestamp = now.strftime("%Y%m%d")
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    headers = {"content-type": "application/x-www-form-urlencoded",
               "host": host, "x-amz-date": amzdate}
    if session_token:
        headers["x-amz-security-token"] = session_token
    names = sorted(headers)
    canonical_headers = "".join("%s:%s\n" % (n, headers[n].strip()) for n in names)
    signed_headers = ";".join(names)
    canonical_request = "\n".join(["POST", "/", "", canonical_headers, signed_headers, payload_hash])
    scope = "%s/%s/%s/aws4_request" % (datestamp, region, service)
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                     hashlib.sha256(canonical_request.encode()).hexdigest()])
    sig = hmac.new(_sig_key(sk, datestamp, region, service),
                   sts.encode("utf-8"), hashlib.sha256).hexdigest()
    send = dict(headers)
    send["Authorization"] = ("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
                             % (ak, scope, signed_headers, sig))
    req = urllib.request.Request("https://" + host + "/", data=body.encode(), headers=send, method="POST")
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 必须显式禁用本机代理
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, r.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(20000).decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)

if __name__ == "__main__":
    import sys
    print(sts_get_caller_identity(*sys.argv[1:4]))

```
