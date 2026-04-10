#!/bin/bash
# BIG-PHISH Installation Script for Linux/macOS

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🐋 BIG-PHISH v1.0.0 Installer${NC}"
echo -e "${BLUE}========================================${NC}"

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        echo -e "${RED}Unsupported OS${NC}"
        exit 1
    fi
    echo -e "${GREEN}Detected OS: $OS${NC}"
}

# Check Python version
check_python() {
    if command -v python3 &>/dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if [[ $(echo "$PYTHON_VERSION >= 3.7" | bc) -eq 1 ]]; then
            echo -e "${GREEN}Python $PYTHON_VERSION detected${NC}"
        else
            echo -e "${RED}Python 3.7+ required${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Python3 not found${NC}"
        exit 1
    fi
}

# Install system dependencies
install_deps_linux() {
    echo -e "${BLUE}Installing system dependencies...${NC}"
    
    if command -v apt-get &>/dev/null; then
        sudo apt-get update
        sudo apt-get install -y python3-pip python3-dev build-essential \
            nmap nikto curl wget git tcpdump net-tools iputils-ping \
            traceroute dnsutils iptables chromium-browser chromium-chromedriver
    elif command -v yum &>/dev/null; then
        sudo yum install -y python3-pip python3-devel gcc nmap nikto \
            curl wget git tcpdump net-tools traceroute bind-utils iptables
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3-pip python3-devel gcc nmap nikto \
            curl wget git tcpdump net-tools traceroute bind-utils iptables
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm python-pip python-virtualenv nmap nikto \
            curl wget git tcpdump net-tools iputils traceroute bind-tools iptables
    fi
}

install_deps_macos() {
    echo -e "${BLUE}Installing Homebrew and dependencies...${NC}"
    
    if ! command -v brew &>/dev/null; then
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    brew update
    brew install python@3.11 nmap nikto curl wget git tcpdump net-tools
    brew install --cask chromedriver
}

# Setup virtual environment
setup_venv() {
    echo -e "${BLUE}Setting up virtual environment...${NC}"
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    pip install --upgrade pip setuptools wheel
    pip install -r requirements.txt
    pip install -r requirements-full.txt
}

# Create directories
create_dirs() {
    echo -e "${BLUE}Creating directories...${NC}"
    
    mkdir -p .bigphish
    mkdir -p reports
    mkdir -p logs
    mkdir -p config
    mkdir -p wordlists
    mkdir -p phishing_templates
    mkdir -p captured_credentials
    mkdir -p ssh_keys
    mkdir -p traffic_logs
    mkdir -p nikto_results
}

# Setup configuration
setup_config() {
    echo -e "${BLUE}Setting up configuration...${NC}"
    
    if [ ! -f "config/config.json" ]; then
        cp config.example.json config/config.json 2>/dev/null || cat > config/config.json <<EOF
{
    "monitoring": {"enabled": true, "port_scan_threshold": 10},
    "scanning": {"default_ports": "1-1000", "timeout": 30},
    "security": {"auto_block": false, "log_level": "INFO"},
    "nikto": {"enabled": true, "timeout": 300},
    "traffic_generation": {"enabled": true, "max_duration": 300, "allow_floods": false},
    "social_engineering": {"enabled": true, "default_port": 8080, "capture_credentials": true},
    "crunch": {"enabled": true, "max_file_size_mb": 1024, "default_output_dir": "wordlists"},
    "ssh": {"enabled": true, "default_timeout": 30, "max_connections": 5}
}
EOF
        echo -e "${GREEN}Created default configuration${NC}"
    fi
}

# Setup systemd service (Linux only)
setup_service() {
    if [[ "$OS" == "linux" ]]; then
        echo -e "${BLUE}Setting up systemd service...${NC}"
        
        SERVICE_FILE="/etc/systemd/system/bigphish.service"
        SCRIPT_DIR=$(pwd)
        
        sudo bash -c "cat > $SERVICE_FILE" <<EOF
[Unit]
Description=BIG-PHISH Cybersecurity Tool
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$SCRIPT_DIR
Environment="PATH=$SCRIPT_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$SCRIPT_DIR/venv/bin/python3 bigphish.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        sudo systemctl daemon-reload
        echo -e "${GREEN}Service installed. Run: sudo systemctl enable bigphish${NC}"
    fi
}

# Setup desktop shortcut
setup_desktop() {
    if [[ "$OS" == "linux" ]]; then
        echo -e "${BLUE}Creating desktop shortcut...${NC}"
        
        cat > ~/.local/share/applications/bigphish.desktop <<EOF
[Desktop Entry]
Name=BIG-PHISH
Comment=Cybersecurity & Phishing Command Center
Exec=$PWD/run.sh
Icon=$PWD/icon.png
Terminal=true
Type=Application
Categories=Network;Security;
EOF
        
        chmod +x ~/.local/share/applications/bigphish.desktop
    fi
}

# Create run script
create_run_script() {
    echo -e "${BLUE}Creating run script...${NC}"
    
    cat > run.sh <<'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source venv/bin/activate
python3 bigphish.py "$@"
EOF
    
    chmod +x run.sh
}

# Main installation
main() {
    detect_os
    check_python
    
    if [[ "$OS" == "linux" ]]; then
        install_deps_linux
    elif [[ "$OS" == "macos" ]]; then
        install_deps_macos
    fi
    
    setup_venv
    create_dirs
    setup_config
    create_run_script
    
    if [[ "$OS" == "linux" ]]; then
        setup_service
        setup_desktop
    fi
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}✅ BIG-PHISH Installation Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "${BLUE}Run with: ./run.sh${NC}"
    echo -e "${BLUE}Or: source venv/bin/activate && python3 bigphish.py${NC}"
}

main