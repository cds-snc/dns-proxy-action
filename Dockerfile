FROM alpine:3.12

COPY bin/entrypoint.sh /entrypoint.sh
COPY release/latest/dns-proxy-action /dns-proxy-action

ENTRYPOINT ["/entrypoint.sh"]