#!/bin/bash
set -euo pipefail
umask 077
exec 9>/run/lock/vorken-certificate.lock
flock -n 9 || exit 0
test -s /etc/vorken/hostinger.token || { echo 'Configure /etc/vorken/hostinger.token'; exit 1; }
email=$(cat /etc/vorken/acme.email)
operation=run
if test -s /etc/vorken/acme/certificates/vorken.xyz.crt; then operation=renew; fi
docker run --rm \
  -v /etc/vorken/acme:/state \
  -v /etc/vorken/hostinger.token:/run/hostinger.token:ro \
  -e HOSTINGER_API_TOKEN_FILE=/run/hostinger.token \
  -e HOSTINGER_PROPAGATION_TIMEOUT=300 \
  -e HOSTINGER_TTL=300 \
  goacme/lego:v4.28.0 \
  --path /state --email "$email" --accept-tos \
  --dns hostinger --dns.resolvers 1.1.1.1:53 --dns.disable-cp --domains vorken.xyz --domains '*.vorken.xyz' "$operation"
openssl x509 -in /etc/vorken/acme/certificates/vorken.xyz.crt -noout -checkend 86400
nginx -t
systemctl reload nginx
