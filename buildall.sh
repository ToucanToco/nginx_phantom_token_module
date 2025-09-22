#!/bin/bash

##################################################################################
# Builds an entire release with all supported NGINX versions and Linux OS versions
##################################################################################

NGINX_VERSIONS=('1.18.0' '1.25.5' '1.29.1')
LINUX_DISTROS=('ubuntu18' 'ubuntu22' 'alpine' 'alpine3.21')
rm log.txt 2>/dev/null

#
# Avoid building modules for platforms NGINX does not support
#
function isValidBuild() {
    local LINUX_DISTRO_PARAM=$1
    local NGINX_VERSION_PARAM=$2

    if [ "$LINUX_DISTRO_PARAM" == 'ubuntu24' ] && [[ "$NGINX_VERSION_PARAM" < '1.25.5' ]]; then
      echo 'false'
    elif [ "$LINUX_DISTRO_PARAM" == 'centosstream9' ] && [[ "$NGINX_VERSION_PARAM" > '1.25.5'  ]]; then
      echo 'false'
    else
      echo 'true'
    fi
}

#
# Build modules for all supported environments and versions
#
for LINUX_DISTRO in ${LINUX_DISTROS[@]}
do
  for NGINX_VERSION in ${NGINX_VERSIONS[@]}
  do
    if [ "$(isValidBuild $LINUX_DISTRO $NGINX_VERSION)" == 'true' ]; then

      echo "Building the NGINX $NGINX_VERSION phantom token module for $LINUX_DISTRO ..."
      export NGINX_VERSION=$NGINX_VERSION
      export LINUX_DISTRO=$LINUX_DISTRO
      ./build.sh
      if [ $? -ne 0 ]; then
        exit 1
      fi

    else
      echo "Skipping unsupported build for NGINX $NGINX_VERSION and $LINUX_DISTRO ..."
    fi
  done
done
