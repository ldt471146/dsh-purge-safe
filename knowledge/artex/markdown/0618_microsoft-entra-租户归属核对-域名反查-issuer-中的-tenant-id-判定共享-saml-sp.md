# Microsoft Entra 租户归属核对：域名反查 issuer 中的 tenant ID（判定共享 SAML SP/SSL-VPN 归属）

- **code**: microsoft-entra-租户归属核对-域名反查-issuer-中的-tenant-id-判定共享-saml-sp
- **kind**: script
- **category**: recon
- **component**: Microsoft Entra ID (Azure AD) / FortiGate SSL-VPN SAML
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本任务实测：login.microsoftonline.com/kingsltd.co.uk/.well-known/openid-configuration → issuer=https://sts.windows.net/7f3c9fa2-195c-40ed-9624-cd799ef1d2e3/，与 195.171.205.58 FortiGate SAML AuthnRequest 的 Destination 租户 GUID 完全一致；shopto.net 同法 → fcd0a360-5de0-4448-9246-da4a574e6b0e（不同租户）。
- **path**: pocs/microsoft-entra-租户归属核对-域名反查-issuer-中的-tenant-id-判定共享-saml-sp/entra_tenant_attribution.sh
- **tags**: entra-id,azure-ad,saml,fortigate,ssl-vpn,attribution,tenant-id,recon
- **created_at**: 2026-11-11T17:43:23.290Z
- **engine**: 195.171.205.58

## 描述

对走 Entra ID SAML SSO 的共享设备（FortiGate SSL-VPN、第三方 SaaS 等），用 Microsoft 公开无认证端点把“域名→租户 GUID”映射出来，与设备 SAML AuthnRequest 的 Destination（login.microsoftonline.com/<tenant>/saml2）比对，即可判定该设备到底为哪家客户配置，避免把 MSP/托管设备当客户资产继续深打。

## 用法

```
curl -s https://login.microsoftonline.com/<customer-domain>/.well-known/openid-configuration → issuer 里的 GUID 即租户 ID；把该 GUID 与目标 SAML SP（如 FortiGate /remote/login?lang=en 返回的 SAMLRequest 中 Destination=login.microsoftonline.com/<tenant>/saml2）的 GUID 比对：相同=该客户专属，不同=第三方共享设备。实测例：195.171.205.58/.60 的 FortiGate Destination 为 7f3c9fa2-...，恰等于 kingsltd.co.uk 的租户，而 shopto.net 租户为 fcd0a360-... → 该 VPN 属 Kings Ltd、与 shopto 无绑定。
```

## 正文

```
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
```
