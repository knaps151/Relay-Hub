#!/usr/bin/env bash
set -euo pipefail

PKI_DIR=/vpn/pki
CCD_DIR=/vpn/ccd
SERVER_CONF=/vpn/server.conf
STATUS_FILE=/vpn/openvpn-status.log

OVPN_PORT="${OVPN_PORT:-1194}"
OVPN_PROTO="${OVPN_PROTO:-tcp}"
OVPN_NETWORK="${OVPN_NETWORK:-10.100.1.0}"
OVPN_NETMASK="${OVPN_NETMASK:-255.255.255.0}"
OVPN_SERVER_CN="${OVPN_SERVER_CN:-parktech-relay}"

mkdir -p "$PKI_DIR" "$CCD_DIR" /vpn/clients /vpn/issued /vpn/private

init_pki() {
  echo "Initializing OpenVPN PKI with openssl..."
  openssl genrsa -out "$PKI_DIR/ca.key" 2048
  openssl req -x509 -new -nodes -key "$PKI_DIR/ca.key" -sha256 -days 3650 \
    -out "$PKI_DIR/ca.crt" -subj "/CN=ParkTech Relay CA"

  openssl genrsa -out "$PKI_DIR/server.key" 2048
  openssl req -new -key "$PKI_DIR/server.key" -out "$PKI_DIR/server.csr" \
    -subj "/CN=${OVPN_SERVER_CN}"
  openssl x509 -req -in "$PKI_DIR/server.csr" -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" \
    -CAcreateserial -out "$PKI_DIR/server.crt" -days 3650 -sha256

  # DSA-param DH is much faster for POC cold starts; swap to plain 2048 on production VPS if desired
  openssl dhparam -dsaparam -out "$PKI_DIR/dh.pem" 2048
  openvpn --genkey secret "$PKI_DIR/ta.key"

  # Convenience copies for API flat-layout lookups
  mkdir -p "$PKI_DIR/issued" "$PKI_DIR/private"
  cp "$PKI_DIR/server.crt" "$PKI_DIR/issued/server.crt"
  cp "$PKI_DIR/server.key" "$PKI_DIR/private/server.key"
  cp "$PKI_DIR/ca.key" "$PKI_DIR/private/ca.key"
}

if [[ ! -f "$PKI_DIR/ca.crt" || ! -f "$PKI_DIR/server.crt" || ! -f "$PKI_DIR/ta.key" ]]; then
  init_pki
fi

cat > "$SERVER_CONF" <<EOF
port ${OVPN_PORT}
proto ${OVPN_PROTO}
dev tun
topology subnet
server ${OVPN_NETWORK} ${OVPN_NETMASK}
keepalive 10 60
persist-key
persist-tun
client-config-dir ${CCD_DIR}
status ${STATUS_FILE}
status-version 2
verb 3
mute 20
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
dh ${PKI_DIR}/dh.pem
ca ${PKI_DIR}/ca.crt
cert ${PKI_DIR}/server.crt
key ${PKI_DIR}/server.key
tls-auth ${PKI_DIR}/ta.key 0
duplicate-cn
push "topology subnet"
EOF

mkdir -p /dev/net
if [[ ! -e /dev/net/tun ]]; then
  mknod /dev/net/tun c 10 200 || true
fi

echo "Starting OpenVPN on ${OVPN_PROTO}/${OVPN_PORT}..."
exec openvpn --config "$SERVER_CONF"
