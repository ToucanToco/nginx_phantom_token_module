FROM alpine:3.21 AS builder

RUN apk add --no-cache --virtual .build-deps \
    gcc libc-dev make pcre2-dev pcre-dev zlib-dev linux-headers libxslt-dev \
    gd-dev geoip-dev perl-dev libedit-dev mercurial alpine-sdk findutils bash

COPY configure /tmp
COPY config /tmp
COPY Makefile /tmp
COPY phantom_token.c /tmp
ARG NGINX_VERSION
ENV NGINX_VERSION=$NGINX_VERSION
ADD nginx-$NGINX_VERSION.tar.gz /tmp/

WORKDIR /tmp
RUN ./configure && make -j $(nproc)

FROM busybox

ARG NGINX_VERSION
COPY --from=builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /

COPY ./builders/init_module.sh /usr/local/bin/init_module.sh
ENTRYPOINT [ "/usr/local/bin/init_module.sh" ]
