# Use an official Python runtime as a parent image
FROM python:3.9-slim-buster

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND noninteractive # Avoid prompts during apt-get install
ENV GOPATH /go # Set GOPATH for Go modules
ENV PATH $PATH:$GOPATH/bin # Add Go binaries to PATH

# Create a directory for Go binaries if it doesn't exist
RUN mkdir -p ${GOPATH}/bin

# Install system dependencies for web drivers and Go
# Use apt-get for tools available in Debian/Ubuntu repositories
# -y for non-interactive installation
# --no-install-recommends to keep image size down
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        chromium-browser \
        wget \
        git \
        ca-certificates \
        fonts-liberation \
        libappindicator3-1 \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libatspi2.0-0 \
        libcairo2 \
        libcups2 \
        libdbus-1-3 \
        libdrm2 \
        libgbm1 \
        libgdk-pixbuf2.0-0 \
        libglib2.0-0 \
        libglib2.0-dev \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libx11-6 \
        libx11-xcb1 \
        libxcb1 \
        libxcomposite1 \
        libxcursor1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxi6 \
        libxrandr2 \
        libxrender1 \
        libxss1 \
        libxtst6 \
        libfontconfig1 \
        libsqlite3-0 \
        # Install Go directly from apt
        golang \
        # Install sqlmap and commix via apt if available (Debian/Ubuntu)
        sqlmap \
        commix \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* # Clean up apt cache to reduce image size

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Go-based tools using 'go install'
# These will be installed into $GOPATH/bin, which is already in PATH
RUN go install github.com/hahwul/dalfox@latest \
    && go install github.com/owasp-amass/amass/v3/...@master \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/ffuf/ffuf@latest \
    # Install DNSRecon (Python tool, but often part of common pentest suites)
    # If not in apt, pip install it here
    && pip install dnsrecon

# Copy the entire application code into the container
COPY . /app

# Set permissions for the scans directory
RUN mkdir -p /app/scans && chmod 777 /app/scans

# Expose the port the app runs on
EXPOSE 80

# Command to run the application
CMD ["python", "-u", "VulnScanX.py", "-p", "80"]
