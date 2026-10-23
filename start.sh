#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if ! command -v docker >/dev/null 2>&1; then
  echo 'Docker ontbreekt. Installeer Docker Engine met Compose op deze Linux-host en voer daarna bash start.sh opnieuw uit.' >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo 'Docker Compose v2 ontbreekt. Installeer de Docker Compose-plugin en probeer opnieuw.' >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo 'Geen toegang tot Docker. Start de Docker-service of voer uit: sudo bash start.sh' >&2
  exit 1
fi
if [[ ! -f .env ]]; then
  umask 077
  password="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
  printf 'VENGUARD_PASSWORD=%s\nVENGUARD_PORT=8098\nVENGUARD_BIND=0.0.0.0\n' "$password" > .env
  echo 'Een uniek beheerwachtwoord is aangemaakt in .env.'
fi
if grep -q '^VENGUARD_PASSWORD=VERVANG_' .env; then
  echo 'Vervang eerst het voorbeeldwachtwoord in .env of verwijder alleen deze voorbeeld-.env en start opnieuw.' >&2
  exit 1
fi
chmod 600 .env
# Never source .env: it is configuration, not executable shell code.
docker compose up -d --build
for attempt in {1..45}; do
  state="$(docker inspect --format '{{.State.Health.Status}}' venguard 2>/dev/null || true)"
  if [[ "$state" == healthy ]]; then break; fi
  sleep 1
done
port="$(sed -n 's/^VENGUARD_PORT=//p' .env | head -n1)"
port="${port:-8098}"
host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
host_ip="${host_ip:-IP-VAN-JE-NUC}"
echo
echo "Open VenGuard: http://${host_ip}:${port}"
printf 'Installatiewachtwoord (alleen zonder eigen account): '
sed -n 's/^VENGUARD_PASSWORD=//p' .env
echo 'Vul daarna bij Instellingen het AdGuard-beheeradres en het VenGuard LAN-adres in.'
if [[ "${state:-}" != healthy ]]; then
  echo 'De container is nog niet gezond. Bekijk indien nodig: docker compose logs --tail=50'
  exit 1
fi
