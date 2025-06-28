import json
import os
from tools.database import Endpoint
from tools import commandinjection, dalfox, sqlinjection, autorecon, idor, csrf # Import all scan tools

# These functions will be called by routes.py in separate threads
# They need access to a Session factory, and the emitter functions from the main app.

def full_scan(url, headers, url_directory, scan_id, sid, db_session_factory, progress_emitter, vulnerability_emitter, num_threads_global, sio_instance,
              passive_crawl_enabled=False, active_crawl_enabled=False, open_browser_for_active_crawl=False,
              passive_subdomain_enabled=False, active_subdomain_enabled=False, wordlist_path=None):
    """
    Performs a full security scan on a target URL.

    Args:
        url (str): The target URL.
        headers (dict): Custom HTTP headers.
        url_directory (str): Directory for scan results.
        scan_id (int): The ID of the current scan.
        sid (str): Socket ID for progress updates.
        db_session_factory (callable): A factory function to get a new SQLAlchemy session.
        progress_emitter (callable): Function to emit scan progress updates.
        vulnerability_emitter (callable): Function to emit found vulnerabilities.
        num_threads_global (int): Global number of threads for concurrent operations.
        sio_instance (socketio.Server): Socket.IO server instance.
        passive_crawl_enabled (bool): Enable passive URL crawling.
        active_crawl_enabled (bool): Enable active URL crawling.
        open_browser_for_active_crawl (bool): Open browser for active crawl login.
        passive_subdomain_enabled (bool): Enable passive subdomain enumeration.
        active_subdomain_enabled (bool): Enable active subdomain enumeration.
        wordlist_path (str, optional): Path to the wordlist for active enumeration tools.
    """
    current_session = db_session_factory()
    temp_endpoints_file_path = os.path.join(url_directory, "temp_endpoints_for_tools.txt")

    # Define scan steps and their approximate weights for progress calculation
    scan_steps = [
        ("Reconnaissance", 20),
        ("XSS Scan", 15),
        ("Command Injection", 15),
        ("SQL Injection", 15),
        ("IDOR Scan", 15),
        ("CSRF Scan", 15),
        ("Cleanup", 5)
    ]
    total_weight = sum(weight for _, weight in scan_steps)
    current_weight = 0

    def emit_progress_internal(message, status='info'):
        nonlocal current_weight
        # Calculate percentage based on completed steps
        percentage = min(100, int((current_weight / total_weight) * 100))
        progress_emitter(scan_id, message, status, sid, percentage)
        sio_instance.emit('scan_progress', {'scan_id': scan_id, 'message': message, 'progress': percentage, 'status': status}, room=sid)

    try:
        emit_progress_internal(f'Starting scan for {url}...', 'info')

        # Phase 1: Run recon first
        step_name, step_weight = scan_steps[0]
        emit_progress_internal(f'Starting {step_name}...', 'info')
        autorecon.autorecon(
            url=url,
            url_directory=url_directory,
            headers=headers,
            session=current_session,
            scan_id=scan_id,
            passive_crawl_enabled=passive_crawl_enabled,
            active_crawl_enabled=active_crawl_enabled,
            open_browser_for_active_crawl=open_browser_for_active_crawl,
            passive_subdomain_enabled=passive_subdomain_enabled,
            active_subdomain_enabled=active_subdomain_enabled,
            wordlist_path=wordlist_path
        )
        current_weight += step_weight
        emit_progress_internal(f'{step_name} complete. Retrieving endpoints...', 'info')

        # Retrieve endpoints from DB for subsequent scans
        endpoints_urls = [e.url for e in current_session.query(Endpoint).filter_by(scan_id=scan_id).all()]
        
        # Create a temporary file of endpoints for tools that expect it.
        with open(temp_endpoints_file_path, "w") as f:
            for ep_url in endpoints_urls:
                f.write(ep_url + "\n")

        # Phase 2: Run the selected functions
        step_name, step_weight = scan_steps[1]
        emit_progress_internal(f'Running {step_name}...', 'info')
        dalfox.run_dalfox_on_url(temp_endpoints_file_path, url_directory, session=current_session, scan_id=scan_id)
        current_weight += step_weight

        step_name, step_weight = scan_steps[2]
        emit_progress_internal(f'Running {step_name}...', 'info')
        commandinjection.commandinjection(temp_endpoints_file_path, url_directory, session=current_session, scan_id=scan_id)
        current_weight += step_weight
        
        step_name, step_weight = scan_steps[3]
        emit_progress_internal(f'Running {step_name}...', 'info')
        sqlinjection.sql_injection_test(temp_endpoints_file_path, url_directory, headers, num_threads_global, "1", session=current_session, scan_id=scan_id)
        current_weight += step_weight
        
        step_name, step_weight = scan_steps[4]
        emit_progress_internal(f'Running {step_name}...', 'info')
        idor.idor(url_directory, session=current_session, scan_id=scan_id, max_workers=num_threads_global)
        current_weight += step_weight

        step_name, step_weight = scan_steps[5]
        emit_progress_internal(f'Running {step_name}...', 'info')
        csrf.csrf(temp_endpoints_file_path, session=current_session, scan_id=scan_id)
        current_weight += step_weight

        current_session.commit()
        
        step_name, step_weight = scan_steps[6]
        emit_progress_internal(f'Starting {step_name}...', 'info')
        # Cleanup temporary files and directories
        if os.path.exists(temp_endpoints_file_path):
            os.remove(temp_endpoints_file_path)
        if os.path.exists(url_directory) and os.path.isdir(url_directory):
            import shutil
            try:
                shutil.rmtree(url_directory)
                emit_progress_internal(f'Cleaned up: {url_directory}', 'info')
            except OSError as e:
                emit_progress_internal(f'Error cleaning {url_directory}: {e}', 'error')
        current_weight += step_weight

        emit_progress_internal('Scan completed!', 'success')
        sio_instance.emit('scan_complete', {'scan_id': scan_id, 'message': 'Scan finished.', 'progress': 100}, room=sid)

    except Exception as e:
        current_session.rollback()
        error_message = f"Error during scan: {e}"
        print(error_message)
        emit_progress_internal(error_message, 'error')
        sio_instance.emit('scan_error', {'scan_id': scan_id, 'message': error_message, 'progress': current_weight}, room=sid)
    finally:
        current_session.close()


def custom_scan(url, headers, crawling, xss, sqli, commandinj, idor_scan, csrf_scan, url_directory, scan_id, sid, db_session_factory, progress_emitter, vulnerability_emitter, num_threads_global, sio_instance,
                passive_crawl_enabled=False, active_crawl_enabled=False, open_browser_for_active_crawl=False,
                passive_subdomain_enabled=False, active_subdomain_enabled=False, wordlist_path=None):
    """
    Performs a custom security scan on a target URL based on selected options.

    Args:
        url (str): The target URL.
        headers (dict): Custom HTTP headers.
        crawling (str): 'on' or 'off' for general endpoint discovery.
        xss (str): 'on' or 'off' for XSS scan.
        sqli (str): 'on' or 'off' for SQL Injection scan.
        commandinj (str): 'on' or 'off' for Command Injection scan.
        idor_scan (str): 'on' or 'off' for IDOR scan.
        csrf_scan (str): 'on' or 'off' for CSRF scan.
        url_directory (str): Directory for scan results.
        scan_id (int): The ID of the current scan.
        sid (str): Socket ID for progress updates.
        db_session_factory (callable): A factory function to get a new SQLAlchemy session.
        progress_emitter (callable): Function to emit scan progress updates.
        vulnerability_emitter (callable): Function to emit found vulnerabilities.
        num_threads_global (int): Global number of threads for concurrent operations.
        sio_instance (socketio.Server): Socket.IO server instance.
        passive_crawl_enabled (bool): Enable passive URL crawling.
        active_crawl_enabled (bool): Enable active URL crawling.
        open_browser_for_active_crawl (bool): Open browser for active crawl login.
        passive_subdomain_enabled (bool): Enable passive subdomain enumeration.
        active_subdomain_enabled (bool): Enable active subdomain enumeration.
        wordlist_path (str, optional): Path to the wordlist for active enumeration tools.
    """
    current_session = db_session_factory()
    temp_endpoints_file_path = os.path.join(url_directory, "temp_endpoints_for_tools.txt")

    # Define scan steps and their approximate weights for progress calculation
    scan_steps = []
    # Adjust condition for Reconnaissance step
    if crawling == "on" or passive_subdomain_enabled or active_subdomain_enabled or passive_crawl_enabled or active_crawl_enabled:
        scan_steps.append(("Reconnaissance", 20))
    else:
        scan_steps.append(("Initial Setup", 5)) # For adding URL as endpoint

    if xss == "on":
        scan_steps.append(("XSS Scan", 15))
    if commandinj == "on":
        scan_steps.append(("Command Injection", 15))
    if sqli == "on":
        scan_steps.append(("SQL Injection", 15))
    if idor_scan == "on":
        scan_steps.append(("IDOR Scan", 15))
    if csrf_scan == "on":
        scan_steps.append(("CSRF Scan", 15))
    
    scan_steps.append(("Cleanup", 5)) # Always include cleanup

    total_weight = sum(weight for _, weight in scan_steps)
    current_weight = 0

    def emit_progress_internal(message, status='info'):
        nonlocal current_weight
        percentage = min(100, int((current_weight / total_weight) * 100))
        progress_emitter(scan_id, message, status, sid, percentage)
        sio_instance.emit('scan_progress', {'scan_id': scan_id, 'message': message, 'progress': percentage, 'status': status}, room=sid)

    try:
        emit_progress_internal(f'Starting custom scan for {url}...', 'info')
        
        # Ensure headers is a dictionary, even if empty or None from frontend
        headers = headers if isinstance(headers, dict) else {}

        # Determine endpoints to work with
        # Adjust condition for Reconnaissance execution
        if crawling == "on" or passive_subdomain_enabled or active_subdomain_enabled or passive_crawl_enabled or active_crawl_enabled:
            step_name, step_weight = scan_steps[0] # Reconnaissance
            emit_progress_internal(f'Starting {step_name}...', 'info')
            autorecon.autorecon(
                url=url,
                url_directory=url_directory,
                headers=headers,
                session=current_session,
                scan_id=scan_id,
                passive_crawl_enabled=passive_crawl_enabled,
                active_crawl_enabled=active_crawl_enabled,
                open_browser_for_active_crawl=open_browser_for_active_crawl,
                passive_subdomain_enabled=passive_subdomain_enabled,
                active_subdomain_enabled=active_subdomain_enabled,
                wordlist_path=wordlist_path
            )
            current_weight += step_weight
            emit_progress_internal(f'{step_name} complete. Retrieving endpoints...', 'info')
            endpoints_urls = [e.url for e in current_session.query(Endpoint).filter_by(scan_id=scan_id).all()]
        else:
            # If no recon, explicitly add the target URL as an endpoint to the database
            step_name, step_weight = scan_steps[0] # Initial Setup
            emit_progress_internal(f'Starting {step_name}. Adding URL as endpoint.', 'info')
            
            # Decide the method for the initial URL. If CSRF is on, default to POST for testing purposes.
            # Otherwise, default to GET.
            initial_url_method = "POST" if csrf_scan == "on" else "GET"

            # Check if the URL already exists as an endpoint for this scan to prevent duplicates
            existing_endpoint = current_session.query(Endpoint).filter_by(scan_id=scan_id, url=url, method=initial_url_method).first()
            if not existing_endpoint:
                new_endpoint = Endpoint(
                    scan_id=scan_id,
                    url=url,
                    method=initial_url_method,
                    body_params=json.dumps({}), # Always initialize as an empty dict
                    extra_headers=json.dumps(headers) # This 'headers' is now guaranteed to be a dict
                )
                current_session.add(new_endpoint)
                current_session.commit() # Commit to make it immediately available for other queries
                emit_progress_internal(f'Added {url} as a {initial_url_method} endpoint.', 'info')
            else:
                emit_progress_internal(f'{url} already exists as a {initial_url_method} endpoint.', 'info')

            endpoints_urls = [url] # Ensure it's in the list for file-based tools
            current_weight += step_weight


        # Write to a temporary file for tools that still expect file input
        with open(temp_endpoints_file_path, "w") as f:
            for ep_url in endpoints_urls:
                f.write(ep_url + "\n")

        # Phase 2: Run the selected functions with progress updates
        # The step_index needs to correctly point to the next step after either Reconnaissance or Initial Setup
        step_index_offset = 1 # Start from the second step in scan_steps list
        
        if xss == "on":
            step_name, step_weight = scan_steps[step_index_offset]
            emit_progress_internal(f'Running {step_name}...', 'info')
            dalfox.run_dalfox_on_url(temp_endpoints_file_path, url_directory, session=current_session, scan_id=scan_id)
            current_weight += step_weight
            step_index_offset += 1
        
        if commandinj == "on":
            step_name, step_weight = scan_steps[step_index_offset]
            emit_progress_internal(f'Running {step_name}...', 'info')
            commandinjection.commandinjection(temp_endpoints_file_path, url_directory, session=current_session, scan_id=scan_id)
            current_weight += step_weight
            step_index_offset += 1
        
        if sqli == "on":
            step_name, step_weight = scan_steps[step_index_offset]
            emit_progress_internal(f'Running {step_name}...', 'info')
            sqlinjection.sql_injection_test(temp_endpoints_file_path, url_directory, headers, num_threads_global, "1", session=current_session, scan_id=scan_id)
            current_weight += step_weight
            step_index_offset += 1
            
        if idor_scan == "on":
            step_name, step_weight = scan_steps[step_index_offset]
            emit_progress_internal(f'Running {step_name}...', 'info')
            idor.idor(url_directory, session=current_session, scan_id=scan_id, max_workers=num_threads_global)
            current_weight += step_weight
            step_index_offset += 1

        if csrf_scan == "on":
            step_name, step_weight = scan_steps[step_index_offset]
            emit_progress_internal(f'Running {step_name}...', 'info')
            csrf.csrf(temp_endpoints_file_path, session=current_session, scan_id=scan_id)
            current_weight += step_weight
            step_index_offset += 1

        current_session.commit()
        
        # Final cleanup step
        step_name, step_weight = scan_steps[step_index_offset] # This should be "Cleanup"
        emit_progress_internal(f'Starting {step_name}...', 'info')
        if os.path.exists(temp_endpoints_file_path):
            os.remove(temp_endpoints_file_path)
        if os.path.exists(url_directory) and os.path.isdir(url_directory):
            import shutil
            try:
                shutil.rmtree(url_directory)
                emit_progress_internal(f'Cleaned up: {url_directory}', 'info')
            except OSError as e:
                emit_progress_internal(f'Error cleaning {url_directory}: {e}', 'error')
        current_weight += step_weight # Ensure cleanup weight is added

        emit_progress_internal('Custom scan completed!', 'success')
        sio_instance.emit('scan_complete', {'scan_id': scan_id, 'message': 'Custom scan finished.', 'progress': 100}, room=sid)

    except Exception as e:
        current_session.rollback()
        error_message = f"Error during custom scan: {e}"
        print(error_message)
        emit_progress_internal(error_message, 'error')
        sio_instance.emit('scan_error', {'scan_id': scan_id, 'message': error_message, 'progress': current_weight}, room=sid)
    finally:
        current_session.close()
