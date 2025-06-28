# VulnScanX: Automated Web Vulnerability Scanner

![VulnScanX Screenshot](/documentation/logo.png) <!-- Replace with a relevant screenshot -->

VulnScanX is a powerful, web-based automated vulnerability scanning tool designed to help identify common security flaws in web applications. Built with Python (Flask) and modern frontend technologies, it provides a comprehensive suite of reconnaissance and vulnerability detection capabilities, offering real-time progress updates, detailed reports, and a user-friendly interface.

## ✨ Key Features

* **Comprehensive Reconnaissance:**
    * **Passive Subdomain Enumeration:** Gathers subdomains from public OSINT sources (e.g., Subfinder, Amass passive mode, SecurityTrails, VirusTotal, Crt.sh, DNSdumpster, Netcraft, SOCRadar).
    * **Active Subdomain Enumeration:** Performs DNS brute-forcing (DNSRecon) and virtual host enumeration (FFUF) to discover hidden subdomains and virtual hosts.
    * **Passive URL/Endpoint Discovery:** Extracts historical URLs from archives like Wayback Machine.
    * **Active URL/Endpoint Crawling:** Uses Selenium to interactively crawl web applications, capturing network requests and extracting endpoints from JavaScript files.
        * **Authenticated Crawling:** Supports manual login directly from the UI. A browser window opens on the server, allowing the user to log in manually before the automated crawl proceeds within the authenticated session.
* **Automated Vulnerability Scanning:**
    * **Cross-Site Scripting (XSS):** Integrates with `DalFox` for robust XSS detection.
    * **SQL Injection (SQLi):** Identifies SQL injection flaws.
    * **Command Injection:** Detects vulnerabilities allowing arbitrary operating system command execution.
    * **Insecure Direct Object Reference (IDOR):** Checks for IDOR vulnerabilities by manipulating object IDs.
    * **Cross-Site Request Forgery (CSRF):** Analyzes for CSRF protection bypasses.
* **User-Friendly Interface (UI):**
    * Intuitive and responsive web interface for seamless interaction across devices.
    * **Real-time Progress:** Live scan progress updates with detailed messages and percentage completion via WebSockets.
    * **Dynamic Blog:** Blog posts are served dynamically from Markdown files, making content management easy.
    * **Custom Modals:** Non-blocking modal dialogs for alerts and confirmations.
    * **Fixed Header:** The navigation header remains static during scrolling for consistent access.
* **Detailed Reporting & History:**
    * All scan data (history, discovered assets, vulnerabilities) is persistently stored in an SQLite database.
    * View detailed results for individual scans, including a **vulnerability severity distribution chart (pie chart)**.
    * Export scan history and individual scan reports in **JSON, CSV, or HTML** formats.
* **Modular and Extensible:** Designed with a clean architecture, allowing easy integration of new scanning tools, reconnaissance techniques, or reporting features.

## 🚀 Getting Started

### Prerequisites

Ensure you have the following installed on your system:

* **Python 3.9+**
* **pip** (Python package installer)
* **Chrome Browser** (or Firefox) installed on the machine where VulnScanX server runs.
* **ChromeDriver** (or GeckoDriver) executable. **Crucially, its version MUST match your installed browser version.** Place it in your system's PATH or directly in your `VulnScanX/` project root directory.
* **External Command-Line Tools:** Many scanning modules rely on these. **The `install.sh` script will help install most of these.**
    * `amass`
    * `subfinder`
    * `httpx`
    * `dnsrecon`
    * `ffuf`
    * `dalfox`
    * `sqlmap`
    * `commix`

### Installation

#### Option 1: Using Docker (Recommended for ease of deployment)

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/VulnScanX.git](https://github.com/your-username/VulnScanX.git) # Replace with your actual repo URL
    cd VulnScanX
    ```
2.  **Build the Docker image:**
    ```bash
    docker build -t vulnscanx .
    ```
    * This process installs all Python dependencies and necessary browser components (Chromium) within the image, **along with the external scanning tools (Go-based tools, sqlmap, commix, dnsrecon)**.
3.  **Run the Docker container:**
    ```bash
    docker run -p 80:80 --name vulnscanx_app vulnscanx
    ```
    * **Important Note on Interactive Login in Docker:** If you intend to use the "Open Browser for Active Crawl" feature for manual login, running Docker in a headless environment (like a typical server VM) will not display the browser window. For this feature, you would typically run VulnScanX directly on your local machine or use a VNC/remote desktop solution to access the Docker host's graphical environment.

#### Option 2: Local Setup (Python)

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/VulnScanX.git](https://github.com/your-username/VulnScanX.git) # Replace with your actual repo URL
    cd VulnScanX
    ```
2.  **Make the installation script executable:**
    ```bash
    chmod +x install.sh
    ```
3.  **Run the installation script:**
    ```bash
    ./install.sh
    ```
    * This script will install Python dependencies from `requirements.txt` and attempt to install the Go programming language, Go-based tools (DalFox, Amass, Subfinder, httpx, ffuf), and Python-based tools (DNSRecon, sqlmap, commix).
    * **Important:** The script might require `sudo` for some installations (e.g., Go, apt packages). It will also attempt to modify your `~/.profile` and `~/.bashrc` for PATH variables. You might need to restart your terminal after running it.
4.  **Configure API Keys (Optional):**
    * Open `tools/config.ini`.
    * Add your API keys for services like SecurityTrails, VirusTotal, Pentest-Tools, etc., if you wish to enable more extensive passive reconnaissance.


### Running the Application

After installation, start the Flask application from the `VulnScanX/` root directory:

```bash
python VulnScanX.py -p 80
````

(You can change `-p 80` to any desired port, e.g., `-p 5000`).

### Accessing the Web UI

Open your web browser and navigate to:
`http://localhost` (if running on port 80)
or
`http://localhost:5000` (if running on port 5000)

## 💡 Usage Guide

1.  **Start a Scan:**
      * On the homepage, enter the `Target URL` (e.g., `https://example.com`).
      * Select `Scan Type`:
          * **Full Scan:** Automatically enables all reconnaissance methods and vulnerability checks for a comprehensive assessment.
          * **Custom Scan:** Allows you to granularly select specific `Reconnaissance Options` (Passive/Active Subdomain, Passive/Active URL Crawling, Open Browser for login) and `Custom Scan Tool Options` (XSS, SQL Injection, Command Injection, IDOR, CSRF).
      * Additionally, provide `Custom Headers` in JSON format (e.g., `{"Authorization": "Bearer YOUR_TOKEN", "Cookie": "sessionid=abc"}`).
      * Click `Start Scan`.
2.  **Monitor Progress:**
      * The `Scan Progress` area on the homepage will display real-time updates, messages, and a percentage progress bar.
      * If `Active URL Crawling` with `Open Browser` is selected, a new browser window will appear on the server machine. **You must manually log in or perform necessary actions in this browser.** Once done, click the `Login Complete - Continue Scan` button that appears in the VulnScanX UI to resume the scan.
3.  **View Results:**
      * Upon scan completion, the UI will automatically redirect you to the `/results` page.
      * This page displays a summary of vulnerabilities, a severity distribution chart, detailed tables for vulnerabilities, discovered endpoints, and reconnaissance data.
4.  **Manage History:**
      * Navigate to the `/history` page to view a list of all your past scans.
      * Each entry shows the domain, scan date, and a summary of vulnerabilities.
      * You can `View Details` of any past scan (redirects to `/results` for that scan ID).
      * You can `Delete` individual scan history records.
5.  **Export Reports:**
      * From the `/results` page, you can export the current scan's report.
      * From the `/history` page, you can export all scan history.
      * Available formats: `JSON`, `CSV` or `HTML`.

## 🤝 Contributing

We welcome contributions\! Please feel free to fork the repository, open issues, or submit pull requests.