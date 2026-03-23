#!/bin/bash
set -e

OIDC_DIR="/opt/zextras/oidc"
NGINX_EXT="/opt/zextras/conf/nginx/extensions"
SYSTEMD_DIR="/etc/systemd/system"

if [ "$(id -u)" -ne 0 ]; then
    echo "BLAD: uruchom jako root (sudo ./uninstall.sh)"
    exit 1
fi

echo "[1/4] Zatrzymanie i wylaczenie serwisu..."
systemctl stop carbonio-oidc 2>/dev/null || true
systemctl disable carbonio-oidc 2>/dev/null || true
rm -f "$SYSTEMD_DIR/carbonio-oidc.service"
systemctl daemon-reload

echo "[2/4] Usuniecie nginx extensions..."
rm -f "$NGINX_EXT/upstream-oidc.conf"
rm -f "$NGINX_EXT/backend-oidc.conf"
su - zextras -c "/opt/zextras/common/sbin/nginx -t" && \
    su - zextras -c "/opt/zextras/common/sbin/nginx -s reload" || \
    echo "OSTRZEZENIE: nginx reload nie powiodl sie — sprawdz recznie."

echo "[3/4] Usuniecie plikow Python..."
rm -f "$OIDC_DIR"/*.py
echo "      -> config.json pozostaje w $OIDC_DIR/config.json (nie usuwam)"

echo "[4/4] Gotowe."
echo "Aby usunac rowniez config.json i katalog:"
echo "  rm -rf $OIDC_DIR"
