#!/bin/bash
set -e

VERSION=$(grep 'VERSION = ' src/server.py | cut -d'"' -f2)
PKG="carbonio-oidc-connector"
ARCH="all"
BUILD_DIR="$(mktemp -d)"
ROOT="${BUILD_DIR}/${PKG}_${VERSION}_${ARCH}"

echo "Building ${PKG}_${VERSION}_${ARCH}.deb..."

# --- Directory structure ---
mkdir -p "${ROOT}/DEBIAN"
mkdir -p "${ROOT}/opt/zextras/oidc"
mkdir -p "${ROOT}/opt/zextras/conf/nginx/extensions"
mkdir -p "${ROOT}/etc/systemd/system"

# --- Python sources ---
cp src/*.py "${ROOT}/opt/zextras/oidc/"
cp config.json.example "${ROOT}/opt/zextras/oidc/config.json.example"

# --- nginx extensions ---
cp nginx/upstream-oidc.conf "${ROOT}/opt/zextras/conf/nginx/extensions/"
cp nginx/backend-oidc.conf  "${ROOT}/opt/zextras/conf/nginx/extensions/"

# --- systemd service ---
cp systemd/carbonio-oidc.service "${ROOT}/etc/systemd/system/"

# --- DEBIAN/control ---
cat > "${ROOT}/DEBIAN/control" << EOF
Package: ${PKG}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Encedo <contact@encedo.com>
Depends: python3 (>= 3.8), python3-cryptography
Section: mail
Priority: optional
Homepage: https://github.com/encedo/carbonio-oidc-connector
Description: OIDC Relying Party sidecar for Carbonio CE
 Adds SSO login via any OIDC Provider as an alternative to
 username/password authentication in Carbonio CE (Zimbra-based).
 Supports EdDSA, RS256/384/512, ES256/384/512 signed JWTs.
 Survives apt upgrade of all Carbonio packages.
EOF

# --- DEBIAN/postinst ---
cat > "${ROOT}/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

OIDC_DIR="/opt/zextras/oidc"
NGINX_EXT="/opt/zextras/conf/nginx/extensions"

case "$1" in
    configure)
        # Set ownership and permissions
        chown -R zextras:zextras "${OIDC_DIR}"
        chmod 750 "${OIDC_DIR}"
        chmod 644 "${OIDC_DIR}"/*.py
        chmod 640 "${OIDC_DIR}/config.json.example"
        chown zextras:zextras "${NGINX_EXT}/upstream-oidc.conf" "${NGINX_EXT}/backend-oidc.conf"

        # Install config.json if not already present
        if [ ! -f "${OIDC_DIR}/config.json" ]; then
            cp "${OIDC_DIR}/config.json.example" "${OIDC_DIR}/config.json"
            chmod 640 "${OIDC_DIR}/config.json"
            chown zextras:zextras "${OIDC_DIR}/config.json"
            echo "carbonio-oidc-connector: edit ${OIDC_DIR}/config.json before starting the service."
        fi

        # Create log file
        touch /var/log/carbonio-oidc.log
        chown zextras:zextras /var/log/carbonio-oidc.log

        # Clear Python bytecode cache so the new .py files are picked up
        rm -rf "${OIDC_DIR}/__pycache__"

        systemctl daemon-reload
        systemctl enable carbonio-oidc

        # On upgrade the service was stopped by prerm — restart it.
        # On fresh install do not start — user must configure config.json first.
        if [ -n "$2" ]; then
            # $2 is set to the old version string during upgrade
            systemctl start carbonio-oidc
            echo "carbonio-oidc-connector: service restarted."
        fi

        # Reload nginx
        if su - zextras -c "/opt/zextras/common/sbin/nginx -t" 2>/dev/null; then
            su - zextras -c "/opt/zextras/common/sbin/nginx -s reload"
        else
            echo "WARNING: nginx config test failed — reload skipped. Check configuration."
        fi
        ;;
esac

exit 0
EOF

# --- DEBIAN/prerm ---
cat > "${ROOT}/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

NGINX_EXT="/opt/zextras/conf/nginx/extensions"

case "$1" in
    upgrade)
        # On upgrade: just stop the service — nginx confs stay in place
        systemctl stop carbonio-oidc 2>/dev/null || true
        ;;
    remove|purge|deconfigure)
        # On removal: stop, disable, remove nginx extensions and reload nginx
        systemctl stop carbonio-oidc 2>/dev/null || true
        systemctl disable carbonio-oidc 2>/dev/null || true

        rm -f "${NGINX_EXT}/upstream-oidc.conf" "${NGINX_EXT}/backend-oidc.conf"
        su - zextras -c "/opt/zextras/common/sbin/nginx -s reload" 2>/dev/null || true

        systemctl daemon-reload
        ;;
esac

exit 0
EOF

chmod 755 "${ROOT}/DEBIAN/postinst" "${ROOT}/DEBIAN/prerm"

# --- Build ---
dpkg-deb --build --root-owner-group "${ROOT}"
mv "${BUILD_DIR}/${PKG}_${VERSION}_${ARCH}.deb" .

rm -rf "${BUILD_DIR}"

echo "Done: ${PKG}_${VERSION}_${ARCH}.deb"
echo ""
echo "Install:   sudo dpkg -i ${PKG}_${VERSION}_${ARCH}.deb"
echo "Configure: sudo editor /opt/zextras/oidc/config.json"
echo "Start:     sudo systemctl start carbonio-oidc"
echo "Remove:    sudo dpkg -r ${PKG}"
