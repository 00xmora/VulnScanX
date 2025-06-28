#!/bin/bash

# install.sh - Script to install external tools for VulnScanX

echo "Starting installation of external tools for VulnScanX..."

# --- Install Go (required for DalFox, Amass, Subfinder, httpx) ---
echo -e "\n[+] Installing Go..."
GO_VERSION="1.21.0" # You can update this to a newer stable version
OS=$(go env GOOS)
ARCH=$(go env GOARCH)

if [ -z "$OS" ]; then
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
fi
if [ -z "$ARCH" ]; then
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64";;
        aarch64) ARCH="arm64";;
        armv7l) ARCH="armv6l";; # For Raspberry Pi etc.
    esac
fi

GO_TAR="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
GO_URL="https://golang.org/dl/${GO_TAR}"

if ! command -v go &> /dev/null; then
    echo "Go not found, downloading from ${GO_URL}"
    wget -q --show-progress ${GO_URL}
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf ${GO_TAR}
    rm ${GO_TAR}
    # Add Go to PATH (for current session and future sessions)
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    source ~/.profile # Apply to current session
    source ~/.bashrc # Apply to current session
    echo "Go ${GO_VERSION} installed. Please restart your terminal or run 'source ~/.profile' to ensure Go is in your PATH."
else
    echo "Go is already installed."
fi

# --- Install Python dependencies (from requirements.txt) ---
echo -e "\n[+] Installing Python dependencies from requirements.txt..."
pip install -r requirements.txt

# --- Install External Tools (Go-based) ---
echo -e "\n[+] Installing Go-based tools (DalFox, Amass, Subfinder, httpx, ffuf)..."
# Ensure GOPATH is set for go install
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# DalFox
echo "  - Installing DalFox..."
go install github.com/hahwul/dalfox@latest

# Amass
echo "  - Installing Amass..."
go install github.com/owasp-amass/amass/v3/...@master

# Subfinder
echo "  - Installing Subfinder..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx
echo "  - Installing httpx..."
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# ffuf
echo "  - Installing ffuf..."
go install github.com/ffuf/ffuf@latest

# --- Install External Tools (Python-based, if not already handled by pip) ---
# Note: sublist3r is typically pip-installed, but if it has a separate binary, add here.
# For tools like sqlmap, commix, they might be apt-installed or cloned.

# DNSRecon (Python-based, usually pip installable)
echo "  - Installing DNSRecon (via pip)..."
pip install dnsrecon

# --- Install sqlmap (if not already present) ---
echo "  - Checking for sqlmap..."
if ! command -v sqlmap &> /dev/null; then
    echo "sqlmap not found, attempting to install..."
    # You might need to adjust this based on your OS or preference
    # For Debian/Ubuntu:
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y sqlmap
    elif command -v git &> /dev/null; then
        echo "Attempting to clone sqlmap from GitHub..."
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ~/sqlmap
        echo "sqlmap cloned to ~/sqlmap. You may need to add it to your PATH manually."
        echo 'export PATH=$PATH:~/sqlmap' >> ~/.profile
        echo 'export PATH=$PATH:~/sqlmap' >> ~/.bashrc
    else
        echo "Neither apt-get nor git found. Please install sqlmap manually."
    fi
else
    echo "sqlmap is already installed."
fi

# --- Install commix (if not already present) ---
echo "  - Checking for commix..."
if ! command -v commix &> /dev/null; then
    echo "commix not found, attempting to install..."
    # For Debian/Ubuntu:
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y commix
    elif command -v git &> /dev/null; then
        echo "Attempting to clone commix from GitHub..."
        git clone --depth 1 https://github.com/commixproject/commix.git ~/commix
        echo "commix cloned to ~/commix. You may need to add it to your PATH manually."
        echo 'export PATH=$PATH:~/commix' >> ~/.profile
        echo 'export PATH=$PATH:~/commix' >> ~/.bashrc
    else
        echo "Neither apt-get nor git found. Please install commix manually."
    fi
else
    echo "commix is already installed."
fi


echo -e "\nInstallation script finished. Please ensure all tools are in your PATH."
echo "You might need to restart your terminal or run 'source ~/.profile' or 'source ~/.bashrc'."
echo "Verify installations by typing tool names (e.g., 'dalfox', 'amass', 'sqlmap')."
