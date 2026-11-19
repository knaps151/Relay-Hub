FROM alpine:3.20

RUN apk add --no-cache openvpn easy-rsa iptables bash openssl

WORKDIR /vpn
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1194/tcp
ENTRYPOINT ["/entrypoint.sh"]
