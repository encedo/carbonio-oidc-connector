#!/bin/bash
set -e

OIDC_DIR="/opt/zextras/oidc"
NGINX_EXT="/opt/zextras/conf/nginx/extensions"
SYSTEMD_DIR="/etc/systemd/system"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run as root (sudo ./uninstall.sh)"
    exit 1
fi

echo "[1/4] Stopping and disabling service..."
systemctl stop carbonio-oidc 2>/dev/null || true
systemctl disable carbonio-oidc 2>/dev/null || true
rm -f "$SYSTEMD_DIR/carbonio-oidc.service"
systemctl daemon-reload

echo "[2/4] Removing nginx extensions..."
rm -f "$NGINX_EXT/upstream-oidc.conf"
rm -f "$NGINX_EXT/backend-oidc.conf"
su - zextras -c "/opt/zextras/common/sbin/nginx -t" && \
    su - zextras -c "/opt/zextras/common/sbin/nginx -s reload" || \
    echo "WARNING: nginx reload failed — check manually."

echo "[3/4] Removing Python files..."
rm -f "$OIDC_DIR"/*.py
echo "      -> config.json preserved at $OIDC_DIR/config.json"

echo "[4/4] Done."
echo "To remove config.json and directory as well:"
echo "  rm -rf $OIDC_DIR"
