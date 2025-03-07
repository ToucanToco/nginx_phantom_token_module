FROM debian:bullseye AS builder

RUN apt update && apt install -y \
    build-essential git tree software-properties-common dirmngr apt-transport-https ufw libpcre2-dev zlib1g-dev

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
