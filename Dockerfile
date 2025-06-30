# Use a base image with Python 3.12 and common build tools
FROM python:3.12-slim-bookworm

# Set environment variables for non-interactive installs and Go
ENV DEBIAN_FRONTEND=noninteractive
ENV GO_VERSION=1.21.0
ENV GOROOT=/usr/local/go
ENV PATH=$PATH:$GOROOT/bin:$HOME/go/bin

# Install system dependencies:
# - build-essential: For compiling Go and other tools
# - wget, curl, git: For downloading and cloning
# - chromium (and chromedriver): For Selenium active crawling
# - sqlmap, commix, dnsutils (for dig): System packages for external tools
# - jq: useful for JSON parsing
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    curl \
    git \
    chromium \
    chromium-driver \
    sqlmap \
    commix \
    dnsutils \
    jq \
    gnupg \
    ca-certificates \
    software-properties-common && \
    rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

# Set working directory in the container
WORKDIR /app

# Copy requirements.txt first to leverage Docker cache
COPY requirements.txt .

# Install pipx globally
RUN pip install --no-cache-dir pipx && \
    pipx ensurepath

# Install Python dependencies using pip (for Flask app itself)
# Filter out tools that are installed via system packages or pipx
RUN grep -vE '^(dnsrecon|sublist3r|sqlmap|commix)' requirements.txt > /tmp/app_requirements.txt && \
    pip install --no-cache-dir -r /tmp/app_requirements.txt && \
    rm /tmp/app_requirements.txt

# Install Python CLI tools via pipx
# Using --force to reinstall if already present (e.g. from system packages, though unlikely for pipx isolated envs)
# DNSRecon is typically a pipx tool
RUN pipx install dnsrecon || echo "Failed to install dnsrecon via pipx, might already be present globally."

# Copy the rest of the application code
COPY . .

# Install Go-based tools
RUN go install github.com/hahwul/dalfox@latest && \
    go install github.com/owasp-amass/amass/v3/...@master && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/ffuf/ffuf@latest

# Expose the port the Flask app will run on
EXPOSE 80

# Command to run the application
CMD ["python", "VulnScanX.py", "-p", "80"]