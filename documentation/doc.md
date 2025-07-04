# VulnScanX Project Documentation

## 1. Introduction

VulnScanX is an open-source, web-based automated vulnerability scanning tool designed to streamline the process of identifying common security weaknesses in web applications. It provides a user-friendly interface for initiating and monitoring scans, managing historical data, and generating comprehensive reports. The tool integrates various reconnaissance techniques and automated vulnerability checks to offer a holistic security assessment.

## 2. Project Goals

* **Automate Initial Security Assessments:** Reduce manual effort in reconnaissance and common vulnerability detection.
* **Provide Real-time Feedback:** Keep users informed about scan progress and status.
* **Offer Granular Control:** Allow users to customize scan types and modules for targeted assessments.
* **Generate Actionable, Professional Reports:** Provide clear, visually appealing, and exportable reports for analysis and remediation.
* **Facilitate Authenticated Scanning:** Enable scanning of web applications behind login pages through interactive browser control.
* **Maintain Extensibility:** Design a modular architecture for easy integration of new tools and features.

## 3. Directory Structure

```
VulnScanX/
├── VulnScanX.py               \# Main Flask application entry point
├── routes.py                  \# Defines Flask UI and API routes using Blueprints
├── scan\_orchestrator.py       \# Orchestrates scan logic and calls individual tools
├── setup.sh                   \# Shell script for initial setup (e.g., installing tools)
├── static/
│   ├── css/
│   │   └── style.css          \# Main CSS file for styling the web UI
│   └── js/
│       └── script.js          \# Frontend JavaScript for interactivity, Socket.IO, form handling
├── templates/
│   ├── 404.html               \# Custom 404 Not Found error page
│   ├── blog.html              \# Blog index page (lists posts)
│   ├── blog\_post.html         \# Template for displaying individual blog posts (Markdown converted to HTML)
│   ├── history.html           \# Scan history page
│   ├── index.html             \# Main homepage with scan initiation form
│   ├── results.html           \# Page to display detailed scan results
│   ├── report\_history.html    \# HTML template for exporting full scan history
│   └── report\_single\_scan.html\# HTML template for exporting a single scan report
├── tools/
│   ├── **init**.py            \# Makes 'tools' a Python package
│   ├── ai\_assistant.py        \# (Placeholder/Future: For potential AI assistant integration)
│   ├── autorecon.py           \# Handles passive/active subdomain enumeration and URL crawling
│   ├── commandinjection.py    \# Module for Command Injection scanning logic
│   ├── config.ini             \# Configuration file for API keys
│   ├── csrf.py                \# Module for CSRF scanning logic
│   ├── dalfox.py              \# Module for XSS scanning (integrates DalFox tool)
│   ├── database.py            \# Defines SQLAlchemy ORM models (ScanHistory, Vulnerability, Endpoint, ReconResult)
│   ├── idor.py                \# Module for IDOR scanning logic
│   └── sqlinjection.py        \# Module for SQL Injection scanning logic
└── docs/
└── Project\_Details.md     \# This detailed documentation file
```


## 4. Core Components & Their Roles

* **`VulnScanX.py`**:
    * **Application Entry Point:** Initializes the Flask application and Flask-SocketIO server.
    * **Database Setup:** Configures and initializes the SQLite database using SQLAlchemy.
    * **Global Emitters:** Defines `emit_progress` and `emit_vulnerability` functions, which are critical for real-time communication with the frontend via WebSockets.
    * **Login Event Management:** Manages `threading.Event` objects (`scan_login_events`) to pause and resume scan threads during interactive login.
    * **Route Registration:** Delegates route handling to `routes.py`.
* **`routes.py`**:
    * **Modular Routing:** Uses Flask Blueprints (`ui_bp` for user interface pages and `api_bp` for RESTful API endpoints) for better organization and scalability.
    * **UI Routes:** Renders HTML templates for the homepage, results, history, and dynamically loaded blog posts.
    * **API Endpoints:**
        * `POST /api/scans`: Initiates new full or custom scans.
        * `GET /api/scans/<int:scan_id>/results`: Fetches detailed results (vulnerabilities, endpoints, recon data) for a specific scan.
        * `DELETE /api/scans/<int:scan_id>`: Deletes a scan history record and associated data.
        * `GET /api/history/export`: Exports all scan history data in JSON, CSV, or HTML formats.
        * `GET /api/scans/<int:scan_id>/export`: Exports a single scan report in JSON, CSV, or HTML formats.
    * **Input Validation:** Performs essential validation on incoming request data to ensure data integrity and security.
    * **Scan Threading:** Launches long-running scan functions (`full_scan`, `custom_scan`) in separate threads to prevent the main Flask application from blocking.
    * **Error Handling:** Provides consistent JSON error responses for API calls and renders a custom 404 page for undefined routes.
    * **Report HTML Generation:** Renders dedicated HTML templates (`report_history.html`, `report_single_scan.html`) for export purposes (HTML and client-side PDF).
* **`scan_orchestrator.py`**:
    * **Scan Workflow Management:** Contains `full_scan` and `custom_scan` functions that define the sequence and execution of reconnaissance and scanning tasks.
    * **Tool Coordination:** Calls individual scanning modules (`autorecon`, `dalfox`, `sqlinjection`, etc.) in a structured manner.
    * **Progress Tracking:** Calculates and emits real-time progress percentages and concise messages to the frontend via WebSockets.
    * **Temporary File Management:** Handles creation and cleanup of temporary files used by various external tools.
    * **Interactive Login Integration:** Utilizes `threading.Event` objects to pause the scan thread, allowing the user to perform manual login in a separate browser window, and then resumes upon receiving a signal from the UI.
* **`install.sh`**:
    * **Automated Tool Installation:** A shell script designed to automate the installation of Go, Go-based tools (Amass, Subfinder, httpx, DalFox, FFUF), and Python-based tools (DNSRecon, sqlmap, commix) on Linux-like systems. It also handles Python dependencies from `requirements.txt`.
* **`static/` (Frontend Assets)**:
    * **`css/style.css`**: Defines the application's modern dark theme, responsive layout, fixed header, full-width content sections, and detailed styling for all UI elements (forms, tables, buttons, custom modals, progress bar, severity indicators).
    * **`js/script.js`**: The main client-side JavaScript, responsible for all frontend interactivity.
        * **Socket.IO Client:** Establishes and manages the WebSocket connection for real-time bidirectional communication.
        * **Form Handling:** Captures user input from the scan form, including granular reconnaissance options, tool selections, and custom headers.
        * **Dynamic UI Updates:** Updates scan progress messages, the visual progress bar, and dynamically displays vulnerabilities, endpoints, and reconnaissance results.
        * **Interactive Login:** Displays a "Login Complete" button in the UI and sends a signal to the backend to resume the scan after manual browser login.
        * **Results & History Display:** Populates scan results and history tables, including rendering a vulnerability severity distribution chart using Chart.js.
        * **Custom Modals:** Provides a consistent, non-blocking modal system for user alerts and confirmations, enhancing user experience.
* **`templates/` (HTML Templates)**:
    * **`index.html`**: The primary user interface for initiating new scans, displaying real-time progress, and general application overview.
    * **`results.html`**: Presents a comprehensive report for a single scan, including summary cards, a vulnerability severity distribution chart, and detailed tables for vulnerabilities, discovered endpoints, and reconnaissance results.
    * **`history.html`**: Lists all past scans with summaries, scan actions (view details, delete), and options to export the entire history.
    * **`blog.html` & `blog_post.html`**: Implement a dynamic blog system that lists and displays content from Markdown files, making content updates flexible.
    * **`report_history.html` & `report_single_scan.html`**: Dedicated HTML templates optimized for HTML export. They feature simplified, inline CSS for better compatibility with professional layout for reports.
    * **`404.html`**: A user-friendly custom page displayed when a requested web resource is not found.
* **`tools/` (Backend Modules)**:
    * **`database.py`**: Defines the SQLAlchemy ORM models (`ScanHistory`, `Vulnerability`, `Endpoint`, `ReconResult`) that map Python objects to database tables, managing data persistence and relationships.
    * **`autorecon.py`**: The core reconnaissance module. It orchestrates external tools and custom logic for comprehensive subdomain enumeration (passive/active) and URL crawling (passive/active, including authenticated Selenium crawling).
    * **`commandinjection.py`, `dalfox.py`, `sqlinjection.py`, `idor.py`, `csrf.py`**: Individual Python modules implementing the logic for detecting specific web vulnerability types. They interact with the database to store and retrieve findings.
    * **`config.ini`**: A configuration file used to store API keys for external services leveraged during reconnaissance (e.g., SecurityTrails, VirusTotal).

## 5. Key Features in Detail

### 5.1. Scan Types & Customization

VulnScanX offers flexibility in scanning:

* **Full Scan:** A one-click solution that automatically executes all available reconnaissance methods and vulnerability checks, providing a comprehensive assessment.
* **Custom Scan:** Empowers users to tailor their scans by individually selecting:
    * **Reconnaissance Options:** Choose between Passive Subdomain Enumeration, Active Subdomain Enumeration, Passive URL Crawling, and Active URL Crawling (with an option to open a browser for manual login).
    * **Vulnerability Scan Tools:** Select specific checks for XSS, SQL Injection, Command Injection, IDOR, and CSRF.
* **Custom Headers:** Users can provide custom HTTP headers (e.g., `Authorization` tokens, `Cookie` headers) in JSON format to facilitate authenticated scanning or bypass certain access controls.

### 5.2. Advanced Reconnaissance

VulnScanX employs a multi-faceted approach to information gathering:

* **Passive Subdomain Enumeration:** Leverages publicly available data and OSINT tools to discover subdomains without direct interaction with the target, minimizing digital footprint. This includes querying services like SecurityTrails, VirusTotal, Crt.sh, DNSdumpster, Netcraft, SOCRadar, and utilizing tools like Subfinder and Amass (passive mode).
* **Active Subdomain Enumeration:** Actively probes DNS records and performs brute-forcing techniques (e.g., DNSRecon) and virtual host enumeration (FFUF) to uncover less obvious subdomains and hidden virtual hosts.
* **Passive URL/Endpoint Discovery:** Extracts historical URLs and endpoints from web archives like the Wayback Machine, providing insights into past application structures.
* **Active URL/Endpoint Crawling:** Utilizes Selenium to control a real browser, simulating user interaction. It navigates the application, clicks links, interacts with forms, and monitors network requests to identify endpoints. It also extracts potential endpoints from JavaScript files.
    * **Interactive Authenticated Crawling:** A unique feature allowing the user to manually log into the target application in a browser window opened by the server. The scan pauses until the user confirms successful login via the UI, ensuring that subsequent automated crawling is performed within an authenticated session.

### 5.3. Automated Vulnerability Detection

The tool automates checks for critical web vulnerabilities:

* **Cross-Site Scripting (XSS):** Integrates the `DalFox` tool to identify various types of XSS vulnerabilities (reflected, stored, DOM-based) that allow attackers to inject malicious client-side scripts.
* **SQL Injection (SQLi):** Employs techniques to detect SQL injection flaws, which can lead to unauthorized database access.
* **Command Injection:** Scans for vulnerabilities that enable attackers to execute arbitrary operating system commands on the server.
* **Insecure Direct Object Reference (IDOR):** Identifies IDOR flaws where insufficient access control allows users to access or manipulate resources they are not authorized for by changing object IDs.
* **CSRF (Cross-Site Request Forgery):** Analyzes web forms and requests to detect CSRF vulnerabilities, which can trick authenticated users into performing unintended actions.

### 5.4. Real-time Feedback and User Experience

* **WebSocket Communication:** Leverages Flask-SocketIO to establish a persistent, real-time communication channel between the Flask backend and the frontend.
* **Live Progress Updates:** Users receive instant updates on scan progress, including detailed messages about the current task, its status (info, success, error, warning), and a percentage completion bar.
* **Intuitive UI:** The web interface is designed for ease of use, with clear navigation, responsive design, and custom modal dialogs for all alerts and confirmations, replacing disruptive browser native pop-ups.
* **Automatic Redirection:** Upon scan completion, the user is automatically redirected to the detailed results page for immediate review.

### 5.5. Comprehensive Reporting and Data Management

* **Persistent Data Storage:** All scan data, including the target URL, scan date, discovered subdomains, endpoints, reconnaissance findings, and detailed vulnerability reports, are stored in an SQLite database.
* **Scan History:** The `/history` page provides a centralized overview of all past scans, allowing users to track their assessment activities.
* **Detailed Scan Reports:** The `/results` page offers an in-depth report for each individual scan, featuring:
    * A summary of vulnerability counts (High, Medium, Low).
    * A visually appealing **pie chart** illustrating the distribution of vulnerability severities.
    * Detailed tables listing all identified vulnerabilities, discovered endpoints (showing path/query), and reconnaissance results.
* **Flexible Export Options:** Users can export their scan data in multiple formats:
    * **JSON:** For programmatic consumption or integration with other tools.
    * **CSV:** For easy viewing and manipulation in spreadsheet software.
    * **HTML:** For a web-based, interactive report view.

## 6. Project Extensibility

VulnScanX is built with a modular and extensible architecture:

* **New Tool Integration:** Integrating new reconnaissance tools or vulnerability scanners is straightforward. Developers can add new Python modules to the `tools/` directory and integrate them into the `scan_orchestrator.py` workflow.
* **Database Schema Extension:** The SQLAlchemy ORM provides a flexible way to extend the database schema if new types of data need to be stored or relationships need to be defined.
* **Frontend Customization:** The separation of concerns in the frontend (HTML templates, CSS, JavaScript) allows for easy customization of the user interface and user experience.

This detailed documentation serves as a comprehensive guide to the VulnScanX project, its capabilities, and its underlying architecture.