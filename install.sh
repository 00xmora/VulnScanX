#!/bin/bash

# install.sh - Script to install external tools for VulnScanX

echo "Starting installation of external tools for VulnScanX..."

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# --- Install Go (required for DalFox, Amass, Subfinder, httpx, ffuf) ---
echo -e "\n[+] Installing Go..."
GO_VERSION="1.21.0" # You can update this to a newer stable version
OS=$(go env GOOS)
ARCH=$(go env GOARCH)

if [ -z "$OS" ]; then
    OS=$(uname -s | tr '[:upper:]' '[:lower__]')
fi
if [ -z "$ARCH" ]; then
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64";;
        aarch64) ARCH="arm64";;
        armv7l) ARCH="armv6l";; # For Raspberry Pi etc.
        armhf) ARCH="armv6l";; # Alias for armv7l sometimes
    esac
fi

GO_TAR="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
GO_URL="https://golang.org/dl/${GO_TAR}"

if ! command_exists go; then
    echo "Go not found, downloading from ${GO_URL}"
    wget -q --show-progress ${GO_URL}
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf ${GO_TAR}
    rm ${GO_TAR}
    
    # Add Go to PATH (for current session and future sessions)
    # Check if lines already exist to prevent duplicates
    grep -q 'export PATH=$PATH:/usr/local/go/bin' ~/.profile || echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
    grep -q 'export PATH=$PATH:/usr/local/go/bin' ~/.bashrc || echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    
    # Source only if it's an interactive shell (to avoid issues in non-interactive scripts)
    if [ "$PS1" ]; then
        source ~/.profile
        source ~/.bashrc
    fi
    echo "Go ${GO_VERSION} installed. Please restart your terminal or run 'source ~/.profile' to ensure Go is in your PATH."
else
    echo "Go is already installed."
fi

# Ensure GOPATH is set for go install commands
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# --- Install Python dependencies (from requirements.txt) ---
echo -e "\n[+] Installing Python dependencies from requirements.txt (excluding CLI tools for pipx)..."
# Install pipx first
if ! command_exists pipx; then
    echo "pipx not found, installing..."
    python3 -m pip install --user pipx || { echo "Failed to install pipx. Aborting."; exit 1; }
    python3 -m pipx ensurepath || { echo "Failed to ensure pipx path. Aborting."; exit 1; }
    # Source pipx path for current session
    if [ "$PS1" ]; then
        eval "$(register-python-argcomplete pipx)"
        export PATH="$PATH:$HOME/.local/bin" # Ensure ~/.local/bin is in PATH for pipx
    fi
else
    echo "pipx is already installed."
fi

# Create and activate a virtual environment for the application's Python dependencies
VENV_DIR=".venv_vulnscanx"
echo -e "\n[+] Creating and activating Python virtual environment in $VENV_DIR..."
python3 -m venv "$VENV_DIR" || { echo "Failed to create virtual environment. Aborting."; exit 1; }
source "$VENV_DIR"/bin/activate || { echo "Failed to activate virtual environment. Aborting."; exit 1; }
echo "Virtual environment activated."

# Create a temporary requirements file for main app dependencies, excluding CLI tools
TEMP_REQUIREMENTS_FILE="temp_app_requirements.txt"
# Filter out python CLI tools that are installed via pipx or other means
# Ensure to update this list if you add/remove Python CLI tools.
grep -vE '^(dnsrecon|sublist3r|sqlmap|commix)' requirements.txt > "$TEMP_REQUIREMENTS_FILE"

# Install dependencies into the virtual environment
pip install -r "$TEMP_REQUIREMENTS_FILE" || { echo "Failed to install main Python dependencies into virtual environment. Aborting."; exit 1; }
rm "$TEMP_REQUIREMENTS_FILE"
echo "Python dependencies installed into virtual environment."

# Deactivate the virtual environment after installation (optional, but good practice for scripts)
deactivate
echo "Virtual environment deactivated for script execution. Remember to activate it manually for development: source $VENV_DIR/bin/activate"


# --- Install External Tools (Go-based) ---
echo -e "\n[+] Installing Go-based tools (DalFox, Amass, Subfinder, httpx, ffuf)..."

TOOLS=(
    "github.com/hahwul/dalfox@latest"
    "github.com/owasp-amass/amass/v3/...@master"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/ffuf/ffuf@latest"
)

for TOOL_PATH in "${TOOLS[@]}"; do
    TOOL_NAME=$(basename $(echo "$TOOL_PATH" | cut -d'@' -f1))
    if ! command_exists "$TOOL_NAME"; then
        echo "  - Installing $TOOL_NAME..."
        go install "$TOOL_PATH" || echo "    WARNING: Failed to install $TOOL_NAME. Please install it manually."
    else
        echo "  - $TOOL_NAME is already installed."
    fi
done

# --- Install External Tools (Python-based CLI via pipx) ---
echo -e "\n[+] Installing Python-based CLI tools via pipx (dnsrecon, sublist3r)..."

PIPX_TOOLS=(
    "dnsrecon"
    # "sublist3r" # Sublist3r is old and might cause issues. Removed it from core.
)

for TOOL_NAME in "${PIPX_TOOLS[@]}"; do
    if ! command_exists "$TOOL_NAME"; then
        echo "  - Installing $TOOL_NAME with pipx..."
        pipx install "$TOOL_NAME" || echo "    WARNING: Failed to install $TOOL_NAME with pipx. Please install it manually."
    else
        echo "  - $TOOL_NAME is already installed (via pipx)."
    fi
done


# --- Install sqlmap and commix (prefer apt-get, fallback to git clone) ---
echo -e "\n[+] Checking for sqlmap..."
if ! command_exists sqlmap; then
    echo "sqlmap not found, attempting to install..."
    if command_exists apt-get; then
        echo "  - Attempting to install sqlmap via apt-get..."
        sudo apt-get update && sudo apt-get install -y sqlmap || echo "    WARNING: Failed to install sqlmap via apt-get."
    else
        echo "  - Attempting to clone sqlmap from GitHub..."
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ~/sqlmap || echo "    WARNING: Failed to clone sqlmap."
        grep -q 'export PATH=$PATH:~/sqlmap' ~/.profile || echo 'export PATH=$PATH:~/sqlmap' >> ~/.profile
        grep -q 'export PATH=$PATH:~/sqlmap' ~/.bashrc || echo 'export PATH=$PATH:~/sqlmap' >> ~/.bashrc
    fi
else
    echo "sqlmap is already installed."
fi

echo -e "\n[+] Checking for commix..."
if ! command_exists commix; then
    echo "commix not found, attempting to install..."
    if command_exists apt-get; then
        echo "  - Attempting to install commix via apt-get..."
        sudo apt-get update && sudo apt-get install -y commix || echo "    WARNING: Failed to install commix via apt-get."
    else
        echo "  - Attempting to clone commix from GitHub..."
        git clone --depth 1 https://github.com/commixproject/commix.git ~/commix || echo "    WARNING: Failed to clone commix."
        grep -q 'export PATH=$PATH:~/commix' ~/.profile || echo 'export PATH=$PATH:~/commix' >> ~/.profile
        grep -q 'export PATH=$PATH:~/commix' ~/.bashrc || echo 'export PATH=$PATH:~/commix' >> ~/.bashrc
    fi
else
    echo "commix is already installed."
fi

echo -e "\nInstallation script finished. Please ensure all tools are in your PATH."
echo "You might need to restart your terminal or run 'source ~/.profile' or 'source ~/.bashrc'."
echo "To run the main application, you will need to activate the virtual environment first:"
echo "source $VENV_DIR/bin/activate"
echo "Then you can run your Python application."
echo "Verify installations by typing tool names (e.g., 'dalfox', 'amass', 'sqlmap')."