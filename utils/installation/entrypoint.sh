#!/bin/bash

detect_access_ip() {
    if [ -n "$PUBLIC_IP" ]; then
        echo "$PUBLIC_IP"
        return
    fi

    HOST_IP=$(ip -4 route get 1 2>/dev/null | grep -oP '(?<=src\s)\d+\.\d+\.\d+\.\d+' | head -1)
    if [ -n "$HOST_IP" ] && [[ ! "$HOST_IP" =~ ^172\. ]]; then
        echo "$HOST_IP"
        return
    fi

    echo "<your-ip>"
}

print_access() {
    # Port as published on the host (docker-compose sets PUBLIC_PORT), scheme from TLS_MODE
    local port="${PUBLIC_PORT:-10001}"
    local scheme="http"
    local tls_mode
    tls_mode=$(grep -E '^TLS_MODE=' /app/.env 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]')
    if [ -n "$tls_mode" ] && [ "$tls_mode" != "off" ]; then
        scheme="https"
    fi
    ACCESS_IP=$(detect_access_ip)
    echo ""
    echo "Access:  $scheme://$ACCESS_IP:$port"
    echo "         $scheme://localhost:$port"
    if [ "$tls_mode" = "self-signed" ]; then
        echo "         (self-signed certificate: the browser warns once; compare the"
        echo "          SHA-256 fingerprint printed below before accepting it)"
    fi
}

if [ ! -f /app/.env ]; then
    echo "===================================================="
    echo "          LazyEASM - First Run Detected             "
    echo "===================================================="
    bash /app/utils/installation/install.sh
else
    echo "===================================================="
    echo "          LazyEASM - Starting                       "
    echo "===================================================="
fi
print_access

# Web app and background worker run as separate processes (see run.py)
exec python /app/run.py
