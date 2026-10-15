#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="$SCRIPT_DIR/utils/installation"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

show_help() {
    echo "LazyEASM - External Attack Surface Management"
    echo ""
    echo "Usage: ./start.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --native    Run in native mode (no Docker)"
    echo "  --stop      Stop Docker containers"
    echo "  --logs      Show Docker logs (follow mode)"
    echo "  --clean     Remove Docker containers, images, and volumes"
    echo "  --help      Show this help message"
    echo ""
    echo "Default: Docker mode"
    echo ""
    echo "Examples:"
    echo "  ./start.sh              # Start in Docker"
    echo "  ./start.sh --native     # Start in native mode"
    echo "  ./start.sh --logs       # View Docker logs"
    echo "  ./start.sh --stop       # Stop Docker containers"
    echo "  ./start.sh --clean     # Remove Docker containers and images"
}

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        *)       echo "unknown" ;;
    esac
}

install_docker() {
    OS=$(detect_os)

    echo -e "${YELLOW}Docker not found. Installing...${NC}"

    case $OS in
        linux)
            if [ "$(id -u)" -ne 0 ]; then
                echo -e "${RED}Error: Run with sudo for Docker installation${NC}"
                echo "Example: sudo ./start.sh"
                exit 1
            fi
            apt-get update
            apt-get install -y locales
            sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen 2>/dev/null || true
            locale-gen en_US.UTF-8 2>/dev/null || true
            export LANG=en_US.UTF-8
            apt-get install -y docker.io
            # Compose v2 plugin (`docker compose`); the package name differs by
            # distro and release, and older releases only have v1 (`docker-compose`)
            if ! docker compose version &> /dev/null; then
                apt-get install -y docker-compose-v2 \
                    || apt-get install -y docker-compose-plugin \
                    || apt-get install -y docker-compose
            fi
            systemctl start docker
            systemctl enable docker
            DOCKER_USER="${SUDO_USER:-$USER}"
            if [ -n "$DOCKER_USER" ] && [ "$DOCKER_USER" != "root" ]; then
                usermod -aG docker "$DOCKER_USER"
                echo -e "${GREEN}Docker installed. You may need to logout/login for group changes.${NC}"
            else
                echo -e "${GREEN}Docker installed.${NC}"
            fi
            ;;
        macos)
            echo -e "${RED}Docker not installed.${NC}"
            echo "Install Docker Desktop from: https://docs.docker.com/desktop/install/mac-install/"
            exit 1
            ;;
        *)
            echo -e "${RED}Unsupported OS. Install Docker manually.${NC}"
            exit 1
            ;;
    esac
}

install_native_deps() {
    OS=$(detect_os)

    echo -e "${YELLOW}Installing native dependencies...${NC}"

    case $OS in
        linux)
            if [ "$(id -u)" -ne 0 ]; then
                echo -e "${RED}Error: Run with sudo for native installation${NC}"
                echo "Example: sudo ./start.sh --native"
                exit 1
            fi
            apt-get update
            apt-get install -y locales
            sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen 2>/dev/null || true
            locale-gen en_US.UTF-8 2>/dev/null || true
            export LANG=en_US.UTF-8
            apt-get install -y python3 python3-pip python3-venv nmap openssl curl git
            ;;
        macos)
            if ! command -v brew &> /dev/null; then
                echo -e "${RED}Homebrew not installed.${NC}"
                echo "Install from: https://brew.sh"
                exit 1
            fi
            brew install python3 nmap openssl curl git
            ;;
        *)
            echo -e "${RED}Unsupported OS. Install dependencies manually:${NC}"
            echo "  - Python 3 + pip"
            echo "  - nmap"
            echo "  - openssl"
            echo "  - curl"
            exit 1
            ;;
    esac
}

check_docker() {
    command -v docker &> /dev/null \
        && { docker compose version &> /dev/null || command -v docker-compose &> /dev/null; }
}

# Docker Compose v2 (`docker compose`) when available, v1 (`docker-compose`) otherwise
compose() {
    if docker compose version &> /dev/null; then
        docker compose "$@"
    else
        docker-compose "$@"
    fi
}

check_native() {
    local missing=()

    command -v python3 &> /dev/null || missing+=("python3")
    command -v pip3 &> /dev/null || missing+=("pip3")
    command -v nmap &> /dev/null || missing+=("nmap")
    command -v openssl &> /dev/null || missing+=("openssl")

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}Missing dependencies: ${missing[*]}${NC}"
        return 1
    fi
    return 0
}

setup_venv() {
    cd "$SCRIPT_DIR"

    if [ ! -d ".venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv .venv
    fi

    echo "Installing Python dependencies..."
    .venv/bin/pip install --upgrade pip --quiet
    .venv/bin/pip install -r requirements.txt --quiet

    install_chromium
}

# Headless Chromium for web screenshots. The browser downloads into the
# user's cache (no root needed); its system libraries need root once. These
# are separate steps: `install --with-deps` without root stops at the
# libraries and never downloads the browser.
install_chromium() {
    echo "Installing headless Chromium for web screenshots..."
    if ! .venv/bin/python -m playwright install chromium; then
        echo -e "${YELLOW}Chromium download failed; web screenshots stay disabled until it is installed.${NC}"
        return
    fi
    [ "$(detect_os)" = "linux" ] || return
    if [ "$(id -u)" -eq 0 ]; then
        .venv/bin/python -m playwright install-deps chromium \
            || echo -e "${YELLOW}Installing Chromium's system libraries failed; web screenshots may not work.${NC}"
        return
    fi
    # Without root: only ask for the libraries if some are actually missing
    local shell
    shell=$(find "${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}" -type f -name chrome-headless-shell 2>/dev/null \
            | sort | tail -1)
    if [ -n "$shell" ] && ldd "$shell" 2>/dev/null | grep -q "not found"; then
        echo -e "${YELLOW}Chromium needs system libraries that are missing. Install them once as root, then restart:${NC}"
        echo "    sudo $SCRIPT_DIR/.venv/bin/python -m playwright install-deps chromium"
    fi
}

start_docker() {
    if ! check_docker; then
        install_docker
    fi

    cd "$SCRIPT_DIR"

    if [ -d ".env" ]; then
        echo -e "${YELLOW}.env is a directory (Docker auto-created). Removing and regenerating...${NC}"
        rm -rf .env
    fi

    if [ ! -f ".env" ]; then
        echo -e "${YELLOW}No .env found. Running install script...${NC}"
        bash "$INSTALL_DIR/install.sh"
    fi

    echo -e "${GREEN}Starting LazyEASM in Docker mode...${NC}"
    # --build: after `git pull` the image is rebuilt with the new code (cached
    # layers keep it quick when nothing changed)
    compose up -d --build

    echo ""
    echo -e "${GREEN}LazyEASM started!${NC}"
    show_startup_info
    echo "View logs:  ./start.sh --logs"
    echo "Stop:       ./start.sh --stop"
}

# Address, certificate fingerprint and (first run) the setup code from the
# container's startup output
show_startup_info() {
    local logs=""
    for _ in $(seq 1 45); do
        logs=$(compose logs --no-color --no-log-prefix lazyeasm 2>/dev/null)
        echo "$logs" | grep -q "fingerprint:\|Serving LazyEASM" && break
        sleep 2
    done
    echo "$logs" | grep -E "^(Access:| {9}https?://)" | tail -2
    echo "$logs" | grep -o "fingerprint: [0-9A-F:]*" | tail -1 | sed 's/^/HTTPS certificate SHA-256 /'
    # db/ is mounted from here; the file exists only until the account is created
    if [ -e "$SCRIPT_DIR/db/setup_code" ] && echo "$logs" | grep -q "one-time setup code"; then
        local code
        code=$(echo "$logs" | grep -A2 "one-time setup code" | grep -oE "[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}" | tail -1)
        echo ""
        echo -e "${YELLOW}First run: open the address above and create your account with this setup code:${NC}"
        echo -e "    ${GREEN}${code}${NC}"
    fi
    echo ""
}

start_native() {
    if ! check_native; then
        install_native_deps
    fi

    echo -e "${GREEN}Starting LazyEASM in native mode...${NC}"
    cd "$SCRIPT_DIR"

    if [ ! -f "$SCRIPT_DIR/.env" ]; then
        echo -e "${YELLOW}No .env found. Running install script...${NC}"
        bash "$INSTALL_DIR/install.sh"
    fi

    setup_venv

    .venv/bin/python run.py
}

MODE="docker"

for arg in "$@"; do
    case $arg in
        --native) MODE="native" ;;
        --stop)
            cd "$SCRIPT_DIR"
            compose down
            echo -e "${GREEN}LazyEASM stopped.${NC}"
            exit 0
            ;;
        --clean)
            cd "$SCRIPT_DIR"
            echo -e "${YELLOW}Removing LazyEASM Docker containers and images...${NC}"
            compose down --rmi all --volumes
            echo -e "${GREEN}LazyEASM Docker resources removed.${NC}"
            exit 0
            ;;
        --logs)
            cd "$SCRIPT_DIR"
            compose logs -f lazyeasm
            exit 0
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $arg${NC}"
            show_help
            exit 1
            ;;
    esac
done

case $MODE in
    docker) start_docker ;;
    native) start_native ;;
esac