#!/bin/bash
set -e

OIDC_DIR="/opt/zextras/oidc"
NGINX_EXT="/opt/zextras/conf/nginx/extensions"
SYSTEMD_DIR="/etc/systemd/system"
LOG_FILE="/var/log/carbonio-oidc.log"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run as root (sudo ./install.sh)"
    exit 1
fi

echo "[1/6] Creating directory $OIDC_DIR..."
mkdir -p "$OIDC_DIR"
cp src/*.py "$OIDC_DIR/"

echo "[2/6] Installing config.json (if not present)..."
if [ ! -f "$OIDC_DIR/config.json" ]; then
    cp config.json.example "$OIDC_DIR/config.json"
    echo "      -> Fill in $OIDC_DIR/config.json before starting the service!"
else
    echo "      -> config.json already exists, skipping."
fi

echo "[3/6] Setting permissions..."
chown -R zextras:zextras "$OIDC_DIR"
chmod 750 "$OIDC_DIR"
chmod 640 "$OIDC_DIR/config.json"
chmod 644 "$OIDC_DIR"/*.py

echo "[4/6] Installing nginx extensions..."
cp nginx/upstream-oidc.conf "$NGINX_EXT/"
cp nginx/backend-oidc.conf  "$NGINX_EXT/"
chown zextras:zextras "$NGINX_EXT/upstream-oidc.conf" "$NGINX_EXT/backend-oidc.conf"

echo "[5/6] Installing systemd service..."
cp systemd/carbonio-oidc.service "$SYSTEMD_DIR/"
systemctl daemon-reload
systemctl enable carbonio-oidc

echo "[6/6] Preparing log file and verifying nginx..."
touch "$LOG_FILE"
chown zextras:zextras "$LOG_FILE"
su - zextras -c "/opt/zextras/common/sbin/nginx -t" && \
    su - zextras -c "/opt/zextras/common/sbin/nginx -s reload" || \
    { echo "ERROR: nginx -t failed — check configuration!"; exit 1; }

echo ""
echo "=== Installation complete ==="
echo "1. Edit $OIDC_DIR/config.json (set preauth_key for your domain)"
echo "2. systemctl start carbonio-oidc"
echo "3. curl http://127.0.0.1:8754/oidc/health"
