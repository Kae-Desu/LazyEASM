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
            apt-get install -y docker.io docker-compose
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
    command -v docker &> /dev/null && command -v docker-compose &> /dev/null
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
}

start_docker() {
    if ! check_docker; then
        install_docker
    fi

    echo -e "${GREEN}Starting LazyEASM in Docker mode...${NC}"
    cd "$SCRIPT_DIR"
    docker-compose up -d

    echo ""
    echo -e "${GREEN}LazyEASM started!${NC}"
    echo "View logs:  ./start.sh --logs"
    echo "Stop:       ./start.sh --stop"
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

    .venv/bin/python main.py
}

MODE="docker"

for arg in "$@"; do
    case $arg in
        --native) MODE="native" ;;
        --stop)
            cd "$SCRIPT_DIR"
            docker-compose down
            echo -e "${GREEN}LazyEASM stopped.${NC}"
            exit 0
            ;;
        --clean)
            cd "$SCRIPT_DIR"
            echo -e "${YELLOW}Removing LazyEASM Docker containers and images...${NC}"
            docker-compose down --rmi all --volumes
            echo -e "${GREEN}LazyEASM Docker resources removed.${NC}"
            exit 0
            ;;
        --logs)
            cd "$SCRIPT_DIR"
            docker-compose logs -f lazyeasm
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