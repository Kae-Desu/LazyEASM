#!/bin/bash

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

mkdir -p "$PROJECT_ROOT/static/icons"
mkdir -p "$PROJECT_ROOT/static/images"

# --- GENERATE RAHASIA UNIK ---
# No password here: the account is created in the browser on first run,
# with the one-time setup code LazyEASM prints when it starts
# Generate Secrets: 128 karakter
RANDOM_JWT=$(openssl rand -base64 96 | tr -d '/+=' | head -c 128)
RANDOM_FLASK=$(openssl rand -base64 96 | tr -d '/+=' | head -c 128)

# --- SIMPAN KE .env ---
cat << EOF > "$PROJECT_ROOT/.env"
FLASK_SECRET_KEY=$RANDOM_FLASK
JWT_SECRET=$RANDOM_JWT
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
echo "Secrets generated in .env. On first start LazyEASM prints a one-time"
echo "setup code: open it in your browser and create your account with it."
echo "===================================================="
