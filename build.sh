#!/bin/bash

#########################################################################
# Builds a particular NGINX version for a particular Linux OS and version
#########################################################################

NGINX_VERSION=${NGINX_VERSION:-1.25.5}
NGINX_TARBALL=nginx-${NGINX_VERSION}.tar.gz
LINUX_DISTRO=${LINUX_DISTRO:-alpine}

TAG_NAME=$(git describe --tags --abbrev=0 --exact-match 2>/dev/null)
TAG_NAME_DEV=$(git describe --tags --abbrev=0 2>/dev/null)
VERSION_CORE="$(echo $TAG_NAME | sed 's/+/-/')"
VERSION_CORE_DEV="$(echo $TAG_NAME_DEV | sed 's/+/-/')"
GIT_COMMIT="$(git rev-parse --short=7 HEAD)"

if [ -n "$TAG_NAME" ] && [ -n "$VERSION_CORE" ]; then
  VERSION="$VERSION_CORE"
elif [ -n "$TAG_NAME_DEV" ] && [ -n "$VERSION_CORE_DEV" ]; then
  VERSION="$VERSION_CORE_DEV-dev"
else
  VERSION="$GIT_COMMIT"
fi

if [ "$LINUX_DISTRO" != 'alpine' ] &&
   [ "$LINUX_DISTRO" != 'alpine3.21' ] &&
   [ "$LINUX_DISTRO" != 'debian11' ] &&
   [ "$LINUX_DISTRO" != 'debian12' ] &&
   [ "$LINUX_DISTRO" != 'ubuntu18' ] &&
   [ "$LINUX_DISTRO" != 'ubuntu20' ] &&
   [ "$LINUX_DISTRO" != 'ubuntu22' ] &&
   [ "$LINUX_DISTRO" != 'ubuntu24' ] &&
   [ "$LINUX_DISTRO" != 'amazon2' ] &&
   [ "$LINUX_DISTRO" != 'amazon2023' ] &&
   [ "$LINUX_DISTRO" != 'centosstream9' ]; then
  echo "$LINUX_DISTRO is not a supported Linux distribution"
  exit 1
fi

function getLibraryPrefix() {
  if [ "$LINUX_DISTRO" == 'alpine' ]; then
    echo 'alpine'
  elif [ "$LINUX_DISTRO" == 'alpine3.21' ]; then
    echo 'alpine3.21'
  elif [ "$LINUX_DISTRO" == 'debian11' ]; then
    echo 'debian.bullseye'
  elif [ "$LINUX_DISTRO" == 'debian12' ]; then
    echo 'debian.bookworm'
  elif [ "$LINUX_DISTRO" == 'ubuntu18' ]; then
    echo 'ubuntu.18.04'
  elif [ "$LINUX_DISTRO" == 'ubuntu20' ]; then
    echo 'ubuntu.20.04'
  elif [ "$LINUX_DISTRO" == 'ubuntu22' ]; then
    echo 'ubuntu.22.04'
  elif [ "$LINUX_DISTRO" == 'ubuntu24' ]; then
    echo 'ubuntu.24.04'
  elif [ "$LINUX_DISTRO" == 'amazon2' ]; then
    echo 'amzn2'
  elif [ "$LINUX_DISTRO" == 'amazon2023' ]; then
    echo 'amzn2023'
  elif [ "$LINUX_DISTRO" == 'centosstream9' ]; then
    echo 'centos.stream.9'
  fi
}

if [[ ! -r $NGINX_TARBALL ]]; then
  if [ -z "$DOWNLOAD_PROGRAM" ]; then
      if hash curl &>/dev/null; then
        DOWNLOAD_PROGRAM="curl -O"
      elif hash wget &>/dev/null; then
        DOWNLOAD_PROGRAM="wget"
      else
        echo "Couldn't find curl or wget, please install either of these programs."
        exit 1
      fi
  fi
  $DOWNLOAD_PROGRAM https://nginx.org/download/nginx-"${NGINX_VERSION}".tar.gz
fi

docker build \
  -t "nginx-module-builder:$LINUX_DISTRO" \
  --build-arg NGINX_VERSION="$NGINX_VERSION" \
  -f builders/$LINUX_DISTRO.Dockerfile .
if [ $? -ne 0 ]; then
  echo "Docker build problem encountered for OS $LINUX_DISTRO and NGINX $NGINX_VERSION"
  exit 1
fi

mkdir -p build
LIBRARY_PREFIX=$(getLibraryPrefix)
docker run --name nginx-modules "nginx-module-builder:$LINUX_DISTRO"
docker cp nginx-modules:/ngx_curity_http_phantom_token_module.so ./build/$LIBRARY_PREFIX.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
docker rm -f nginx-modules

if [ -n "$PUSH" ]; then
  cleanup() {
    docker buildx rm builder || true
  }
  trap cleanup EXIT INT TERM
  cleanup
  docker buildx create --name builder --driver docker-container --use
  docker buildx build --platform=linux/amd64,linux/arm64/v8 \
  -t "nginx-module-builder:$LINUX_DISTRO" \
  -t quay.io/toucantoco/ngx-auth-module:$VERSION-$LINUX_DISTRO-ngx$NGINX_VERSION \
  -t quay.io/toucantoco/ngx-auth-module:$VERSION-$LINUX_DISTRO \
  --build-arg NGINX_VERSION="$NGINX_VERSION" \
  -f builders/$LINUX_DISTRO.Dockerfile . \
  --push
  if [ -n "$TAG_NAME" ] && [ -n "$VERSION_CORE" ]; then
    docker buildx build --platform=linux/amd64,linux/arm64/v8 \
    -t "nginx-module-builder:$LINUX_DISTRO" \
    -t quay.io/toucantoco/ngx-auth-module:latest-$LINUX_DISTRO-ngx$NGINX_VERSION \
    -t quay.io/toucantoco/ngx-auth-module:latest-$LINUX_DISTRO \
    --build-arg NGINX_VERSION="$NGINX_VERSION" \
    -f builders/$LINUX_DISTRO.Dockerfile . \
    --push
  fi
fi
