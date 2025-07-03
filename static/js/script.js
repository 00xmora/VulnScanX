// VulnScanX/static/js/script.js - Consolidated and updated for database integration and WebSocket preparation

document.addEventListener("DOMContentLoaded", function() {
    // Initialize Socket.IO connection
    const socket = io();
    let currentSocketId = null;
    let severityChartInstance = null; // Global variable to hold the Chart.js instance
    let currentScanId = null; // Variable to hold the ID of the currently running scan for login signalling

    // --- Custom Modal for Alerts/Confirmations ---
    function showModal(message, type = 'info', onConfirm = null) {
        let modal = document.getElementById('custom-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'custom-modal';
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(0,0,0,0.5);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 1000;
            `;
            document.body.appendChild(modal);
        }

        modal.innerHTML = `
            <div style="
                background-color: #333; /* Darker background for modal content */
                color: #e0e0e0; /* Light text */
                padding: 30px;
                border-radius: 12px;
                box-shadow: 0 8px 25px rgba(0,0,0,0.5); /* Stronger shadow */
                max-width: 450px;
                text-align: center;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                border: 1px solid #6a11cb; /* Accent border */
            ">
                <p style="margin-bottom: 25px; font-size: 1.2em; color: #e0e0e0;">${message}</p>
                <button id="modal-ok-btn" style="
                    background-color: #2ed573;
                    color: white;
                    padding: 12px 25px;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    font-size: 1em;
                    margin: 0 8px;
                    transition: transform 0.2s ease, box-shadow 0.2s ease;
                    font-weight: 600;
                ">OK</button>
                ${onConfirm ? `<button id="modal-cancel-btn" style="
                    background-color: #ff4757;
                    color: white;
                    padding: 12px 25px;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    font-size: 1em;
                    margin: 0 8px;
                    transition: transform 0.2s ease, box-shadow 0.2s ease;
                    font-weight: 600;
                ">Cancel</button>` : ''}
            </div>
        `;
        modal.style.display = 'flex';

        document.getElementById('modal-ok-btn').onclick = () => {
            modal.style.display = 'none';
            if (onConfirm) onConfirm(true);
        };

        if (onConfirm) {
            document.getElementById('modal-cancel-btn').onclick = () => {
                modal.style.display = 'none';
                onConfirm(false);
            };
        }
    }


    // --- Socket.IO Event Listeners ---
    socket.on('connect', function() {
        console.log('Connected to WebSocket with SID:', socket.id);
        currentSocketId = socket.id; // Store the SID
    });

    socket.on('scan_progress', function(data) {
        console.log('Scan Progress:', data);
        const progressDiv = document.getElementById("scan-progress");
        const progressBar = document.getElementById("scan-progress-bar");
        const loginPromptArea = document.getElementById("login-prompt-area"); // Get the login prompt area
        const loginCompleteBtn = document.getElementById("login-complete-btn"); // Get the login complete button

        // Only update for the currently relevant scan (important if multiple clients or scans)
        if (currentScanId && data.scan_id !== currentScanId) {
            return;
        }
        
        // Update currentScanId if it's the first progress update for this scan
        if (currentScanId === null && data.scan_id) {
            currentScanId = data.scan_id;
        }

        if (progressDiv) {
            progressDiv.innerHTML += `<p class="${data.status || 'info'}">${data.message}</p>`;
            progressDiv.scrollTop = progressDiv.scrollHeight;
        }

        if (progressBar && typeof data.progress === 'number') {
            progressBar.style.width = `${data.progress}%`;
            progressBar.textContent = `${data.progress}%`;
            progressBar.style.backgroundColor = getProgressBarColor(data.status);
        }

        // Handle interactive login required status
        if (data.status === 'login_required' && loginPromptArea && loginCompleteBtn) {
            loginPromptArea.style.display = 'block'; // Show the login prompt area
            loginCompleteBtn.disabled = false; // Ensure button is enabled
            showModal(`Manual login required for Scan ID ${data.scan_id}. Please complete login in the opened browser window and click 'I have logged in. Continue scan.' button below.`, 'warning');
        } else if (loginPromptArea) {
            // Hide login prompt if status is not 'login_required'
            loginPromptArea.style.display = 'none';
        }
    });

    socket.on('new_vulnerability', function(data) {
        console.log('New Vulnerability:', data);
        if (window.location.pathname === "/results") {
            // Check if this vulnerability belongs to the current scan being viewed
            const urlParams = new URLSearchParams(window.location.search);
            const viewedScanId = parseInt(urlParams.get('scan_id'));
            if (data.scan_id === viewedScanId) {
                addResultRow(data.vulnerability);
                // Re-render chart and update overview cards with new data
                // This would require fetching all vulnerabilities again or maintaining a client-side list
                // For simplicity, we'll update overview cards directly and suggest full chart re-render on page load.
                // For live updates, a more sophisticated client-side data management is needed.
                // For now, let's just re-fetch and re-display results or trigger a partial update.
                // This call below will refresh entire results section
                // if (viewedScanId) fetchAndDisplayScanResults(viewedScanId);
            }
        }
    });

    socket.on('scan_complete', function(data) {
        console.log('Scan Complete:', data);
        const progressDiv = document.getElementById("scan-progress");
        const progressBar = document.getElementById("scan-progress-bar");
        const loginPromptArea = document.getElementById("login-prompt-area");

        if (data.scan_id === currentScanId) { // Only process for the current scan
            if (progressDiv) {
                progressDiv.innerHTML += `<p class="success">${data.message}</p>`;
                progressDiv.scrollTop = progressDiv.scrollHeight;
            }

            if (progressBar) {
                progressBar.style.width = '100%';
                progressBar.textContent = '100% Complete';
                progressBar.style.backgroundColor = 'green';
            }

            if (loginPromptArea) {
                loginPromptArea.style.display = 'none'; // Hide on scan completion
            }

            const scanId = data.scan_id;
            if (scanId) {
                showModal("Scan finished! Redirecting to results page...", 'success', () => {
                    window.location.href = `/results?scan_id=${scanId}`;
                });
            } else {
                showModal("Scan finished! No scan ID provided for redirection.", 'success');
            }
            currentScanId = null; // Reset current scan ID after completion
        }
    });

    socket.on('scan_error', function(data) {
        console.error('Scan Error:', data);
        const progressDiv = document.getElementById("scan-progress");
        const progressBar = document.getElementById("scan-progress-bar");
        const loginPromptArea = document.getElementById("login-prompt-area");

        if (data.scan_id === currentScanId) { // Only process for the current scan
            if (progressDiv) {
                progressDiv.innerHTML += `<p class="error">${data.message}</p>`;
                progressDiv.scrollTop = progressDiv.scrollHeight;
            }

            if (progressBar) {
                progressBar.style.backgroundColor = 'red';
                progressBar.textContent = `Error at ${data.progress || 0}%`;
            }
            showModal(`Scan Error: ${data.message}`, 'error');

            if (loginPromptArea) {
                loginPromptArea.style.display = 'none'; // Hide on scan error
            }
            currentScanId = null; // Reset current scan ID after error
        }
    });

    // --- Form Submission Logic ---
    const scanForm = document.getElementById("scan-form");
    const scanProgressDiv = document.getElementById("scan-progress");
    const vulnerabilitiesTableBody = document.querySelector("#vulnerabilities-table tbody");
    const endpointsTableBody = document.querySelector("#endpoints-table tbody");
    const reconTableBody = document.querySelector("#recon-table tbody");
    const progressBarContainer = document.getElementById("progress-bar-container");

    let progressBar = document.getElementById("scan-progress-bar");
    if (!progressBar && progressBarContainer) {
        progressBar = document.createElement('div');
        progressBar.id = 'scan-progress-bar';
        progressBar.style.cssText = `
            width: 0%;
            height: 25px;
            background-color: #4CAF50;
            text-align: center;
            line-height: 25px;
            color: white;
            font-weight: bold;
            border-radius: 5px;
            transition: width 0.5s ease-in-out;
            margin-top: 10px;
        `;
        progressBarContainer.appendChild(progressBar);
    }
    
    // Get the login prompt area and button
    const loginPromptArea = document.getElementById("login-prompt-area");
    const loginCompleteBtn = document.getElementById("login-complete-btn");


    if (scanForm) {
        scanForm.addEventListener("submit", function(event) {
            event.preventDefault();
            
            const formData = new FormData(scanForm);
            const data = {};
            formData.forEach((value, key) => {
                data[key] = value;
            });

            data["passive_crawl"] = document.getElementById("passive-crawl") ? document.getElementById("passive-crawl").checked : false;
            data["active_crawl"] = document.getElementById("active-crawl") ? document.getElementById("active-crawl").checked : false;
            data["open_browser"] = document.getElementById("open-browser") ? document.getElementById("open-browser").checked : false;
            data["passive_subdomain"] = document.getElementById("passive-subdomain") ? document.getElementById("passive-subdomain").checked : false;
            data["active_subdomain"] = document.getElementById("active-subdomain") ? document.getElementById("active-subdomain").checked : false;
            data["wordlist_path"] = document.getElementById("wordlist-path") ? document.getElementById("wordlist-path").value : null;


            data["crawling"] = document.getElementById("crawling") && document.getElementById("crawling").checked ? "on" : "off";
            data["xss"] = document.getElementById("xss") && document.getElementById("xss").checked ? "on" : "off";
            data["sql_injection"] = document.getElementById("sql-injection") && document.getElementById("sql-injection").checked ? "on" : "off";
            data["command_injection"] = document.getElementById("command-injection") && document.getElementById("command-injection").checked ? "on" : "off";
            data["idor"] = document.getElementById("idor") && document.getElementById("idor").checked ? "on" : "off";
            data["csrf"] = document.getElementById("csrf") && document.getElementById("csrf").checked ? "on" : "off";
            
            const headersInput = document.getElementById("headers").value;
            if (headersInput) {
                try {
                    data["headers"] = JSON.parse(headersInput);
                } catch (e) {
                    showModal("Invalid JSON for custom headers. Please fix it.", 'error');
                    return;
                }
            } else {
                data["headers"] = {};
            }

            const headers2Input = document.getElementById("headers2").value;
            if (headers2Input) {
                try {
                    data["headers2"] = JSON.parse(headers2Input);
                } catch (e) {
                    showModal("Invalid JSON for custom headers2. Please fix it.", 'error');
                    return;
                }
            } else {
                data["headers"] = {};
            }

            if (data["scan_type"] === "full") {
                data["passive_crawl"] = true;
                data["active_crawl"] = true;
                data["passive_subdomain"] = true;
                data["active_subdomain"] = true;

                data["crawling"] = "on";
                data["xss"] = "on";
                data["sql_injection"] = "on";
                data["command_injection"] = "on";
                data["idor"] = "on";
                data["csrf"] = "on";
            }

            if (currentSocketId) {
                data["sid"] = currentSocketId;
            } else {
                console.warn("Socket.IO SID not available yet. Progress updates might not be sent to this client.");
                showModal("Could not connect to WebSocket. Progress updates may not be real-time.", 'warning');
            }

            console.log("Starting scan with data:", data);
            scanProgressDiv.innerHTML = "<p>Scan is starting...</p>";
            if (progressBar) {
                progressBar.style.width = '0%';
                progressBar.textContent = '0%';
                progressBar.style.backgroundColor = '#4CAF50';
            }
            if (loginPromptArea) { // Hide login prompt initially on new scan
                loginPromptArea.style.display = 'none';
            }
            if (loginCompleteBtn) { // Disable login complete button initially
                loginCompleteBtn.disabled = true;
            }


            fetch("/api/scans", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(data)
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => { throw new Error(err.details || err.error || 'Unknown error'); });
                }
                return response.json();
            })
            .then(result => {
                currentScanId = result.scan_id; // Store scan ID
                console.log(result.message);
                scanProgressDiv.innerHTML = `<p>${result.message}</p>`;

                // Show login prompt if active crawl and open browser selected
                if (data["active_crawl"] && data["open_browser"] && loginPromptArea && loginCompleteBtn) {
                    loginPromptArea.style.display = 'block';
                    loginCompleteBtn.disabled = false;
                }
            })
            .catch(error => {
                console.error("Error starting scan:", error);
                showModal(`Error starting scan: ${error.message || error}`, 'error');
                scanProgressDiv.innerHTML = `<p style="color: red;">Error: ${error.message || error}</p>`;
                currentScanId = null; // Reset scan ID on error
            });
        });
    }

    // New: Event listener for the "Login Complete" button
    if (loginCompleteBtn) {
        loginCompleteBtn.addEventListener('click', function() {
            if (currentScanId) {
                loginCompleteBtn.disabled = true; // Disable button to prevent multiple clicks
                const loginPromptArea = document.getElementById("login-prompt-area"); // Re-get inside function for scope

                fetch(`/api/scans/${currentScanId}/login_complete`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(err => { throw new Error(err.details || err.error || 'Unknown error'); });
                    }
                    return response.json();
                })
                .then(data => {
                    console.log('Login complete signal sent:', data.message);
                    const progressDiv = document.getElementById("scan-progress");
                    if (progressDiv) {
                        progressDiv.innerHTML += `<p class="info">Login completion signal sent. Scan should resume shortly.</p>`;
                        progressDiv.scrollTop = progressDiv.scrollHeight;
                    }
                    if (loginPromptArea) {
                        loginPromptArea.style.display = 'none'; // Hide the prompt after signaling
                    }
                })
                .catch(error => {
                    console.error('Error sending login complete signal:', error);
                    showModal(`Error signaling login completion: ${error.message || error}`, 'error');
                    loginCompleteBtn.disabled = false; // Re-enable if error occurred
                });
            } else {
                console.warn('No active scan ID to signal login completion.');
            }
        });
    }

    // --- Results Display Functions ---
    // (This part remains largely the same as before, ensure it's not duplicated)
    function displayResults(scanData) {
        const scanResultsHeader = document.getElementById("scan-results-header");
        const scanTargetInfo = document.getElementById("scan-target-info");
        const noVulnsMessage = document.getElementById("no-vulns-message");
        const noEndpointsMessage = document.getElementById("no-endpoints-message");
        const noReconMessage = document.getElementById("no-recon-message");


        // Update header and target info
        if (scanTargetInfo && scanData.domain) {
            scanResultsHeader.textContent = `Scan Results`;
            scanTargetInfo.innerHTML = `
                <h3>Target: <a href="https://${scanData.domain}" target="_blank">${scanData.domain}</a></h3>
                <p>Scan ID: ${scanData.scan_id} | Date: ${new Date(scanData.scan_date).toLocaleString()}</p>
            `;
        } else {
            scanResultsHeader.textContent = "Scan Results";
            scanTargetInfo.innerHTML = "<p>No scan information available.</p>";
        }

        // Clear existing results
        if (vulnerabilitiesTableBody) vulnerabilitiesTableBody.innerHTML = '';
        if (endpointsTableBody) endpointsTableBody.innerHTML = '';
        if (reconTableBody) reconTableBody.innerHTML = '';

        // Display Vulnerabilities
        const vulnerabilities = scanData.vulnerabilities || [];
        if (vulnerabilities.length === 0) {
            noVulnsMessage.style.display = 'block';
            if(vulnerabilitiesTableBody) vulnerabilitiesTableBody.closest('.results-table-container').style.display = 'none';
        } else {
            noVulnsMessage.style.display = 'none';
            if(vulnerabilitiesTableBody) vulnerabilitiesTableBody.closest('.results-table-container').style.display = 'block';
            vulnerabilities.sort((a, b) => {
                const severityOrder = { 'high': 3, 'medium': 2, 'low': 1, 'info': 0, 'n/a': -1 };
                return severityOrder[b.severity.toLowerCase()] - severityOrder[a.severity.toLowerCase()];
            });
            vulnerabilities.forEach(vuln => {
                addResultRow(vuln);
            });
        }

        // Display Endpoints
        const endpoints = scanData.endpoints || [];
        if (endpoints.length === 0) {
            noEndpointsMessage.style.display = 'block';
            if(endpointsTableBody) endpointsTableBody.closest('.results-table-container').style.display = 'none';
        } else {
            noEndpointsMessage.style.display = 'none';
            if(endpointsTableBody) endpointsTableBody.closest('.results-table-container').style.display = 'block';
            endpoints.forEach(endpoint => {
                addEndpointRow(endpoint);
            });
        }

        // Display Recon Results
        const reconResults = scanData.recon_results || [];
        if (reconResults.length === 0) {
            noReconMessage.style.display = 'block';
            if(reconTableBody) reconTableBody.closest('.results-table-container').style.display = 'none';
        } else {
            noReconMessage.style.display = 'none';
            if(reconTableBody) reconTableBody.closest('.results-table-container').style.display = 'block';
            reconResults.forEach(recon => {
                addReconRow(recon);
            });
        }

        // Update Overview Cards and render Chart
        updateOverviewCards(vulnerabilities);
        renderSeverityChart(vulnerabilities); // NEW: Render the chart
    }

    function addResultRow(vuln) {
        if (!vulnerabilitiesTableBody) return;

        const row = vulnerabilitiesTableBody.insertRow();
        row.insertCell(0).textContent = vuln.vulnerability || "N/A";
        
        const severityCell = row.insertCell(1);
        severityCell.innerHTML = `<span class="severity ${vuln.severity ? vuln.severity.toLowerCase() : ''}">${vuln.severity || "N/A"}</span>`;

        const urlCell = row.insertCell(2);
        const urlLink = document.createElement("a");
        urlLink.href = vuln.url || "#";
        urlLink.target = "_blank";

        try {
            const parsedUrl = new URL(vuln.url);
            urlLink.textContent = parsedUrl.pathname + parsedUrl.search; // Show only path and query
        } catch (e) {
            urlLink.textContent = vuln.url || "N/A"; // Fallback if URL is invalid
        }
        
        urlCell.appendChild(urlLink);

        row.insertCell(3).textContent = vuln.method || "N/A";
        
        const descriptionCell = row.insertCell(4);
        descriptionCell.innerHTML = vuln.description || vuln.evidence || "No detailed description.";
    }

    function addEndpointRow(endpoint) {
        if (!endpointsTableBody) return;

        const row = endpointsTableBody.insertRow();
        const endpointUrlCell = row.insertCell(0);
        const endpointLink = document.createElement("a");
        endpointLink.href = endpoint.url || "#";
        endpointLink.target = "_blank";

        try {
            const parsedUrl = new URL(endpoint.url);
            endpointLink.textContent = parsedUrl.pathname + parsedUrl.search; // Show only path and query
        } catch (e) {
            endpointLink.textContent = endpoint.url || "N/A"; // Fallback if URL is invalid
        }
        
        endpointUrlCell.appendChild(endpointLink);

        row.insertCell(1).textContent = endpoint.method || "N/A";

        const copyCell = row.insertCell(2);
        const copyBtn = document.createElement("button");
        copyBtn.className = "copy-endpoint-btn";
        copyBtn.innerHTML = '<i class="fas fa-copy"></i> Copy';
        copyBtn.onclick = () => copyToClipboard(endpoint.url); // Keep full URL for copying
        copyCell.appendChild(copyBtn);
    }

    function addReconRow(recon) {
        if (!reconTableBody) return;

        const row = reconTableBody.insertRow();
        row.insertCell(0).textContent = recon.type || "N/A";
        row.insertCell(1).textContent = recon.value || "N/A";
    }

    function copyToClipboard(text) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        try {
            document.execCommand('copy');
            showModal('Endpoint URL copied to clipboard!', 'success');
        } catch (err) {
            console.error('Failed to copy: ', err);
            showModal('Failed to copy URL to clipboard.', 'error');
        }
        document.body.removeChild(textarea);
    }


    function updateOverviewCards(vulnerabilities = []) {
        const totalVulns = document.getElementById("total-vulns");
        const highVulns = document.getElementById("high-vulns");
        const mediumVulns = document.getElementById("medium-vulns");
        const lowVulns = document.getElementById("low-vulns");

        let highCount = 0;
        let mediumCount = 0;
        let lowCount = 0;

        vulnerabilities.forEach(vuln => {
            if (vuln.severity) {
                switch (vuln.severity.toLowerCase()) {
                    case 'high': highCount++; break;
                    case 'medium': mediumCount++; break;
                    case 'low': lowCount++; break;
                }
            }
        });

        if (totalVulns) totalVulns.textContent = vulnerabilities.length;
        if (highVulns) highVulns.textContent = highCount;
        if (mediumVulns) mediumVulns.textContent = mediumCount;
        if (lowVulns) lowVulns.textContent = lowCount;
    }

    // Function to render the severity distribution chart
    function renderSeverityChart(vulnerabilities = []) {
        const ctx = document.getElementById('severityChart');
        if (!ctx) return; // Exit if canvas element is not found

        const severityCounts = {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0,
            'N/A': 0
        };

        vulnerabilities.forEach(vuln => {
            const severity = vuln.severity ? vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1).toLowerCase() : 'N/A';
            if (severityCounts.hasOwnProperty(severity)) {
                severityCounts[severity]++;
            } else {
                severityCounts['N/A']++; // Catch any unexpected severity types
            }
        });

        const labels = Object.keys(severityCounts).filter(key => severityCounts[key] > 0);
        const data = labels.map(key => severityCounts[key]);
        const backgroundColors = labels.map(key => {
            switch (key) {
                case 'High': return '#dc3545'; // Red
                case 'Medium': return '#ffc107'; // Yellow
                case 'Low': return '#28a745'; // Green
                case 'Info': return '#17a2b8'; // Info Blue
                default: return '#6c757d'; // Grey for N/A
            }
        });
        const borderColors = backgroundColors.map(color => color); // Same border as background

        if (severityChartInstance) {
            // Update existing chart
            severityChartInstance.data.labels = labels;
            severityChartInstance.data.datasets[0].data = data;
            severityChartInstance.data.datasets[0].backgroundColor = backgroundColors;
            severityChartInstance.data.datasets[0].borderColor = borderColors;
            severityChartInstance.update();
        } else {
            // Create new chart
            severityChartInstance = new Chart(ctx, {
                type: 'pie', // Or 'doughnut' for a donut chart
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Vulnerability Severity',
                        data: data,
                        backgroundColor: backgroundColors,
                        borderColor: borderColors,
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false, // Allow custom sizing
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                color: '#e0e0e0' // Light color for legend text
                            }
                        },
                        title: {
                            display: false, // Title is handled by H3 above the chart
                            text: 'Vulnerability Severity Distribution',
                            color: '#e0e0e0'
                        }
                    }
                }
            });
        }
    }


    function getSeverityColor(severity) {
        switch (severity.toLowerCase()) {
            case 'high':
                return 'red';
            case 'medium':
                return 'orange';
            case 'low':
                return 'green';
            case 'info':
                return 'blue';
            default:
                return 'inherit';
        }
    }

    function getProgressBarColor(status) {
        switch (status.toLowerCase()) {
            case 'error':
                return 'red';
            case 'success':
                return 'green';
            case 'info':
            case 'login_required':
                return '#FFD700'; // Using yellow for info/login_required
            default:
                return '#4CAF50'; // Default green
        }
    }

    // --- Page-specific Logic ---
    // Logic for /results page
    if (window.location.pathname === "/results") {
        const urlParams = new URLSearchParams(window.location.search);
        const scanId = urlParams.get('scan_id');

        const scanResultsHeader = document.getElementById("scan-results-header");
        const scanTargetInfo = document.getElementById("scan-target-info");

        // Function to fetch and display scan results
        const fetchAndDisplayScanResults = (id) => {
            scanResultsHeader.textContent = `Loading Results...`;
            scanTargetInfo.innerHTML = `<p>Fetching details for Scan ID: ${id}...</p>`;

            // Attach event listeners for single scan export buttons (ensure they are present)
            const exportJsonBtn = document.getElementById('export-scan-json');
            const exportCsvBtn = document.getElementById('export-scan-csv');
            const exportHtmlBtn = document.getElementById('export-scan-html');

            if (exportJsonBtn) exportJsonBtn.addEventListener('click', () => exportSingleScan(id, 'json'));
            if (exportCsvBtn) exportCsvBtn.addEventListener('click', () => exportSingleScan(id, 'csv'));
            if (exportHtmlBtn) exportHtmlBtn.addEventListener('click', () => exportSingleScan(id, 'html'));


            fetch(`/api/scans/${id}/results`)
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(err => { throw new Error(err.details || err.error || 'Unknown error'); });
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.error) {
                        scanTargetInfo.innerHTML = `<p style="color: red;">Error: ${data.error}</p>`;
                        scanResultsHeader.textContent = "Scan Results";
                    } else {
                        displayResults(data); // This will now trigger chart rendering
                    }
                })
                .catch(error => {
                    scanTargetInfo.innerHTML = `<p style="color: red;">Failed to load results: ${error.message || error}</p>`;
                    scanResultsHeader.textContent = "Scan Results";
                });
        };

        if (scanId) {
            fetchAndDisplayScanResults(scanId); // Call the function to fetch and display
        } else {
            scanResultsHeader.textContent = "Scan Results";
            scanTargetInfo.innerHTML = "<p>Please specify a Scan ID to view results (e.g., /results?scan_id=123).</p>";
            document.querySelectorAll('.results-actions button').forEach(btn => btn.style.display = 'none');
        }
    }

    // Dynamic display for history.html
    const historyTableBody = document.querySelector("#history-table tbody");
    if (window.location.pathname === "/history" && historyTableBody) {
        attachHistoryButtonListeners();
        document.getElementById('export-history-json').addEventListener('click', () => exportAllHistory('json'));
        document.getElementById('export-history-csv').addEventListener('click', () => exportAllHistory('csv'));
        document.getElementById('export-history-html').addEventListener('click', () => exportAllHistory('html'));
    }

    function attachHistoryButtonListeners() {
        document.querySelectorAll('.delete-scan-btn').forEach(button => {
            button.addEventListener('click', function() {
                const scanIdToDelete = this.dataset.scanId;
                showModal(`Are you sure you want to delete scan history for ID ${scanIdToDelete}?`, 'confirm', (confirmed) => {
                    if (confirmed) {
                        deleteScanHistory(scanIdToDelete);
                    }
                });
            });
        });

        document.querySelectorAll('.view-results-btn').forEach(button => {
            button.addEventListener('click', function() {
                const scanIdToView = this.dataset.scanId;
                window.location.href = `/results?scan_id=${scanIdToView}`;
            });
        });
    }

    function exportSingleScan(scanId, format) {
        window.location.href = `/api/scans/${scanId}/export?format=${format}`;
    }

    function exportAllHistory(format) {
        window.location.href = `/api/history/export?format=${format}`;
    }

    function deleteScanHistory(scanId) {
        fetch(`/api/scans/${scanId}`, {
            method: 'DELETE'
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.details || err.error || 'Unknown error'); });
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                showModal(data.message, 'success', () => {
                    location.reload();
                });
            } else {
                showModal(`Error deleting scan: ${data.error}`, 'error');
            }
        })
        .catch(error => {
            console.error("Error deleting scan:", error);
            showModal(`Network error deleting scan: ${error.message || error}`, 'error');
        });
    }

    const scanTypeSelect = document.getElementById("scan-type");
    const customScanOptions = document.getElementById("custom-scan-options");
    const reconOptions = document.getElementById("recon-options");

    if (scanTypeSelect && customScanOptions && reconOptions) {
        scanTypeSelect.addEventListener("change", function() {
            if (this.value === "custom") {
                customScanOptions.style.display = "block";
                reconOptions.style.display = "block";
            } else {
                customScanOptions.style.display = "none";
                reconOptions.style.display = "none";
            }
        });
        if (scanTypeSelect.value === "custom") {
            customScanOptions.style.display = "block";
            reconOptions.style.display = "block";
        } else {
            customScanOptions.style.display = "none";
            reconOptions.style.display = "none";
        }
    }
});