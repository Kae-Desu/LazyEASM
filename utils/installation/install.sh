#!/bin/bash

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

mkdir -p "$PROJECT_ROOT/static/icons"
mkdir -p "$PROJECT_ROOT/static/images"

# --- GENERATE RAHASIA UNIK ---
# Generate Password: 16 karakter acak (alphanumeric)
RANDOM_PASS=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)
# Generate Secrets: 128 karakter
RANDOM_JWT=$(openssl rand -base64 96 | tr -d '/+=' | head -c 128)
RANDOM_FLASK=$(openssl rand -base64 96 | tr -d '/+=' | head -c 128)

# --- SIMPAN KE .env ---
cat << EOF > "$PROJECT_ROOT/.env"
FLASK_SECRET_KEY=$RANDOM_FLASK
JWT_SECRET=$RANDOM_JWT
ADMIN_USER=lazymin
ADMIN_PASS=$RANDOM_PASS
# HTTPS with a certificate generated on first start (see .env.example)
TLS_MODE=self-signed
EOF

chmod 600 "$PROJECT_ROOT/.env"

# The address users open LazyEASM at: shown at startup and included in the
# HTTPS certificate. Inside a container the outbound address is Docker's
# internal one, so it is detected only on the host (start.sh runs this there).
if [ -z "$PUBLIC_IP" ] && [ ! -f /.dockerenv ] && command -v ip &> /dev/null; then
    PUBLIC_IP=$(ip -4 route get 1 2>/dev/null | grep -oP '(?<=src\s)\d+\.\d+\.\d+\.\d+' | head -1)
fi
if [ -n "$PUBLIC_IP" ]; then
    echo "PUBLIC_IP=$PUBLIC_IP" >> "$PROJECT_ROOT/.env"
fi

echo "===================================================="
echo "          LazyEASM Security Initialized             "
echo "===================================================="
echo ""
echo "Username : lazymin"
echo "Password : $RANDOM_PASS"
echo ""
echo "Save this password now! It is stored hashed on first start and removed from .env."
echo "Change it in the dashboard; to reset it, set ADMIN_PASS in .env and restart."
echo "===================================================="