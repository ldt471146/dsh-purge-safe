#!/bin/bash
# 1) 域名 -> Entra 租户 GUID（issuer 里就是 tenant id）
for d in kingsltd.co.uk shopto.net; do
  echo -n "$d -> "
  curl -s "https://login.microsoftonline.com/$d/.well-known/openid-configuration" \
    | python3 -c "import json,sys;print(json.load(sys.stdin).get('issuer'))"
done
# kingsltd.co.uk -> https://sts.windows.net/7f3c9fa2-195c-40ed-9624-cd799ef1d2e3/
# shopto.net     -> https://sts.windows.net/fcd0a360-5de0-4448-9246-da4a574e6b0e/

# 2) 域名是否 Federated（ADFS/第三方 IdP）还是 Managed
curl -s "https://login.microsoftonline.com/common/userrealm/it%40kingsltd.co.uk?api-version=2.1"
# {"NameSpaceType":"Federated","AuthURL":"https://fs.kingsltd.co.uk/adfs/ls/", ... "FederationBrandName":"fs.kingsltd.co.uk"}

# 3) 与设备侧比对：FortiGate /remote/login?lang=en 返回的 SAMLRequest 解码后
#    Destination=https://login.microsoftonline.com/<TENANT-GUID>/saml2
#    若 <TENANT-GUID> == 客户域名所属租户 -> 该设备为该客户配置；
#    若属于另一组织 -> 共享/托管设备，与客户无绑定，停止利用（除非另有 realm/portal 证据）。