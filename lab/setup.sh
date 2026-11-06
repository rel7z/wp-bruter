#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker compose up -d db wordpress fixtures
ready=false
for ((i=0; i<60; i++)); do
  if docker compose exec -T wordpress test -s /var/www/html/wp-config.php; then ready=true; break; fi
  sleep 1
done
if [[ "$ready" != true ]]; then echo 'WordPress files did not become ready' >&2; exit 1; fi
if ! docker compose run --rm wp-cli --allow-root core is-installed; then
  docker compose run --rm wp-cli --allow-root core install \
    --url=http://127.0.0.1:18080 --title='WP-Bruter local validation' \
    --admin_user=admin --admin_password=fixture-password --admin_email=admin@example.test --skip-email
fi
# This is a dedicated lab; keep its known credential and public author deterministic.
docker compose run --rm wp-cli --allow-root user update admin --user_pass=fixture-password
docker compose run --rm wp-cli --allow-root post update 1 --post_status=publish
cat > targets.txt <<'TARGETS'
http://127.0.0.1:18080
http://127.0.0.1:18081
http://127.0.0.1:18082
http://127.0.0.1:18083
http://127.0.0.1:18084
TARGETS
printf '%s\n' 'Local lab ready. Run WP_BRUTER_LAB=1 go test -run TestWordPressLab -v .' \
  'Fixtures: 18080 clean WordPress; 18081 Cloudflare header; 18082 Wordfence; 18083 rate limit; 18084 slow.'
