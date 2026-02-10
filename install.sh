#!/bin/bash

# Pastikan folder static/icons ada untuk menghindari error
mkdir -p static/icons
mkdir -p static/images

# --- GENERATE RAHASIA UNIK ---
# Generate Password: 12 karakter acak (alphanumeric)
RANDOM_PASS=$(openssl rand -base64 12 | tr -d '/+' | cut -c1-12)
# Generate Secrets
RANDOM_JWT=$(openssl rand -hex 24)
RANDOM_FLASK=$(openssl rand -hex 24)

# --- SIMPAN KE .env ---
cat << EOF > .env
FLASK_SECRET=$RANDOM_FLASK
JWT_SECRET=$RANDOM_JWT
ADMIN_USER=admin
ADMIN_PASS=$RANDOM_PASS
EOF

# Kunci file .env agar hanya bisa dibaca owner (chmod 600)
chmod 600 .env

clear
echo "===================================================="
echo "          LazyEASM Security Initialized             "
echo "===================================================="
echo "Setup selesai. Tidak ada password default yang digunakan."
echo ""
echo "Kredensial Akses Anda:"
echo "----------------------------------------------------"
echo "Username : admin"
echo "Password : $RANDOM_PASS"
echo "----------------------------------------------------"
echo "PENTING: Simpan password di atas sekarang!"
echo "Aplikasi tidak akan berjalan tanpa data di file .env"
echo "===================================================="