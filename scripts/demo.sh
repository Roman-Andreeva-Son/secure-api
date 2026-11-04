#!/usr/bin/env bash
# Демонстрация работы API через curl. Запуск: bash scripts/demo.sh
# Поднимает сервер на временной БД, прогоняет сценарии и останавливает сервер.
set -u
cd "$(dirname "$0")/.."

PORT=5055
B="http://127.0.0.1:${PORT}"
export DATABASE_PATH="$(mktemp -u /tmp/demoXXXXXX.db)"
JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export JWT_SECRET
DEMO_PASSWORD='Demo-Passw0rd!'

NEW_USER_PASSWORD="$DEMO_PASSWORD" python3 manage.py create-user student >/dev/null
python3 -m flask --app app run --port "$PORT" >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null; rm -f "$DATABASE_PATH"' EXIT
sleep 2

step() { printf '\n# %s\n' "$1"; }

step "1. Доступ к /api/data без токена -> 401"
echo "\$ curl -i $B/api/data"
curl -s -i "$B/api/data" | sed -n '1p;/^{/p'

step "2. Логин с неверным паролем -> 401"
echo "\$ curl -X POST $B/auth/login -d '{\"username\":\"student\",\"password\":\"wrong\"}'"
curl -s -X POST "$B/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"student","password":"wrong"}'; echo

step "3. Логин с верным паролем -> 200 и JWT"
echo "\$ curl -X POST $B/auth/login -d '{\"username\":\"student\",\"password\":\"***\"}'"
RESP=$(curl -s -X POST "$B/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"student\",\"password\":\"$DEMO_PASSWORD\"}")
TOKEN=$(printf '%s' "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
echo "{\"access_token\":\"${TOKEN:0:45}...\",\"token_type\":\"Bearer\",\"expires_in\":900}"

step "4. Создание поста с XSS-нагрузкой (свой метод POST /api/posts) -> 201, ответ экранирован"
echo "\$ curl -X POST $B/api/posts -H 'Authorization: Bearer \$TOKEN' -d '{\"title\":\"<script>alert(1)</script>\",\"body\":\"hello\"}'"
curl -s -X POST "$B/api/posts" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"<script>alert(1)</script>","body":"hello"}'

step "5. GET /api/data с токеном -> 200"
echo "\$ curl $B/api/data -H 'Authorization: Bearer \$TOKEN'"
curl -s "$B/api/data" -H "Authorization: Bearer $TOKEN"

step "6. Попытка SQL-инъекции в параметре q -> 0 результатов, ошибок нет"
echo "\$ curl \"$B/api/data?q=' OR '1'='1\" -H 'Authorization: Bearer \$TOKEN'"
curl -s -G "$B/api/data" --data-urlencode "q=' OR '1'='1" -H "Authorization: Bearer $TOKEN"

step "7. Поддельный токен -> 401"
echo "\$ curl $B/api/data -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.e30.'"
curl -s "$B/api/data" -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.e30.'
echo
