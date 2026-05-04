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
FLASK_SECRET=$RANDOM_FLASK
JWT_SECRET=$RANDOM_JWT
ADMIN_USER=lazymin
ADMIN_PASS=$RANDOM_PASS
EOF

chmod 600 "$PROJECT_ROOT/.env"

echo "===================================================="
echo "          LazyEASM Security Initialized             "
echo "===================================================="
echo ""
echo "Username : lazymin"
echo "Password : $RANDOM_PASS"
echo ""
echo "Save this password now!"
echo "===================================================="