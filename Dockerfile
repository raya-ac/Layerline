FROM alpine:3.21

RUN addgroup -S layerline && adduser -S -G layerline layerline

COPY zig-out/bin/layerline /usr/local/bin/layerline
COPY server.conf /etc/layerline/server.conf
COPY public /var/www/layerline/public

RUN chown -R layerline:layerline /etc/layerline /var/www/layerline

USER layerline
EXPOSE 8080/tcp 8443/udp
ENTRYPOINT ["/usr/local/bin/layerline", "--config", "/etc/layerline/server.conf"]
