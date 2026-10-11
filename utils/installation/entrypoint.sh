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

if [ ! -f /app/.env ]; then
    echo "===================================================="
    echo "          LazyEASM - First Run Detected             "
    echo "===================================================="
    bash /app/utils/installation/install.sh
    echo ""
    ACCESS_IP=$(detect_access_ip)
    echo "Access:  http://$ACCESS_IP:10001"
    echo "         http://localhost:10001"
else
    echo "===================================================="
    echo "          LazyEASM - Starting                       "
    echo "===================================================="
    ACCESS_IP=$(detect_access_ip)
    echo ""
    echo "Access:  http://$ACCESS_IP:10001"
    echo "         http://localhost:10001"
fi

python /app/main.py