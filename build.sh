#!/bin/bash
set -e

VERSION=$(grep 'VERSION = ' src/server.py | cut -d'"' -f2)
DIST="carbonio-oidc-connector-${VERSION}"
OUT="${DIST}.tar.gz"

echo "Building ${OUT}..."

tar czf "${OUT}" \
    --transform "s|^|${DIST}/|" \
    src/*.py \
    nginx/upstream-oidc.conf \
    nginx/backend-oidc.conf \
    systemd/carbonio-oidc.service \
    install.sh \
    uninstall.sh \
    config.json.example

echo "Done: ${OUT}"
echo "Deploy: tar xzf ${OUT} && cd ${DIST} && sudo bash install.sh"
