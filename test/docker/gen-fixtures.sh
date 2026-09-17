#!/bin/sh
set -eu
D="$(cd "$(dirname "$0")/.." && pwd)/fixtures"
mkdir -p "$D"
cd "$D"
[ -f ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N '' -C test-host -f ssh_host_ed25519_key
[ -f user_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C test-user -f user_ed25519
if [ ! -f server.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=sftp-mcp test CA" -keyout ca.key -out ca.crt
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr
  printf 'subjectAltName=DNS:localhost\n' > san.ext
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -extfile san.ext -out server.crt
fi
ssh-keygen -lf ssh_host_ed25519_key.pub | awk '{print $2}' > host_fingerprint.txt
