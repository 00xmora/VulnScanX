import json
import threading
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, render_template, Response, stream_with_context, current_app
from sqlalchemy import func
from tools.database import ScanHistory
import markdown
from pathlib import Path
import os
from datetime import datetime

# Removed: try/except for xhtml2pdf and matplotlib
# Removed: import matplotlib, matplotlib.pyplot

# Create a Blueprint for API routes
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Create a Blueprint for UI/frontend routes
ui_bp = Blueprint('ui', __name__)

# Define the directory where Markdown blog posts are stored
POSTS_DIR = Path(__file__).parent / 'posts'

# --- UI Routes ---
@ui_bp.route("/", methods=["GET"])
def home():
    """Renders the homepage."""
    return render_template("index.html", title="Home")

@ui_bp.route("/results", methods=["GET"])
def results_page():
    """Renders the scan results page."""
    return render_template("results.html", title="Scan Results")

@ui_bp.route("/history", methods=["GET"])
def history_page():
    """Renders the scan history page."""
    db_session_factory = current_app.config['DB_SESSION_FACTORY']
    session = db_session_factory()
    try:
        scan_history_records = session.query(ScanHistory).order_by(ScanHistory.scan_date.desc()).all()
        scan_history_data = []

        for scan_record in scan_history_records:
            vuln_summary = {}
            for vuln in scan_record.vulnerabilities:
                vuln_type = vuln.vulnerability_type or "Unknown"
                vuln_summary[vuln_type] = vuln_summary.get(vuln_type, 0) + 1
            
            summary_list = [f"{t}: {c}" for t, c in vuln_summary.items()]

            scan_history_data.append({
                "id": scan_record.id,
                "domain": scan_record.domain,
                "scan_date": scan_record.scan_date.isoformat(),
                "num_vulnerabilities": len(scan_record.vulnerabilities),
                "vulnerabilities_summary": ", ".join(summary_list) if summary_list else "No vulnerabilities detected."
            })

        return render_template("history.html", scan_history=scan_history_data, title="Scan History")
    except Exception as e:
        current_app.logger.error(f"Error fetching history: {str(e)}")
        return render_template("error.html", message=f"Error fetching history: {str(e)}", title="Error"), 500
    finally:
        session.close()

@ui_bp.route("/blog", methods=["GET"])
def blog():
    """Renders the blog page or a specific blog post."""
    post_id = request.args.get("post")
    if post_id:
        post_file_path = POSTS_DIR / f"{post_id}.md"
        if not post_file_path.is_file():
            return render_template("404.html", title="Not Found"), 404

        try:
            with open(post_file_path, 'r', encoding='utf-8') as f:
                md_content = f.read()
            
            html_content = markdown.markdown(md_content)

            post_title = md_content.split('\n')[0].strip('# ').strip() if md_content.startswith('#') else post_id.replace('_', ' ').title()

            return render_template("blog_post.html", title=post_title, post_content_html=html_content)
        except Exception as e:
            current_app.logger.error(f"Error loading blog post {post_id}: {str(e)}")
            return render_template("error.html", message=f"Error loading blog post: {str(e)}", title="Error"), 500
    else:
        available_posts = []
        for md_file in POSTS_DIR.glob('*.md'):
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                
                post_title = first_line.strip('# ').strip() if first_line.startswith('#') else md_file.stem.replace('_', ' ').title()
                
                available_posts.append({
                    'id': md_file.stem,
                    'title': post_title
                })
            except Exception as e:
                current_app.logger.warning(f"Could not process blog file {md_file.name}: {str(e)}")
                continue
        
        available_posts.sort(key=lambda p: p['title'])

        return render_template("blog.html", posts=available_posts, title="Blog")

# Helper function to generate HTML for reports
# This function will now be called directly by the frontend for PDF/HTML exports
def _generate_report_html(template_name, data):
    return render_template(template_name, **data)

# Removed: _generate_pdf_from_html function
# Removed: _generate_chart_image_matplotlib function

# --- API Routes ---
@api_bp.route("/scans", methods=["POST"])
def start_scan_api():
    """
    API endpoint to start a new scan.
    Expects JSON payload with scan details.
    """
    db_session_factory = current_app.config['DB_SESSION_FACTORY']
    full_scan_func = current_app.config['FULL_SCAN_FUNC']
    custom_scan_func = current_app.config['CUSTOM_SCAN_FUNC']
    progress_emitter = current_app.config['PROGRESS_EMITTER']
    vulnerability_emitter = current_app.config['VULNERABILITY_EMITTER']
    num_threads_global = current_app.config['NUM_THREADS_GLOBAL']
    sio = current_app.config['SIO_INSTANCE']
    scan_login_events = current_app.config['SCAN_LOGIN_EVENTS']

    session = db_session_factory()
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data", "details": "Request body must be valid JSON."}), 400

        url = data.get("url")
        headers = data.get("headers", {})
        headers2 = data.get("headers2", {})
        scan_type = data.get("scan_type")
        client_sid = data.get("sid")

        passive_crawl = data.get("passive_crawl", False)
        active_crawl = data.get("active_crawl", False)
        open_browser = data.get("open_browser", False)
        passive_subdomain = data.get("passive_subdomain", False)
        active_subdomain = data.get("active_subdomain", False)
        wordlist_path = data.get("wordlist_path")

        crawling = data.get("crawling", "off")
        xss = data.get("xss", "off")
        sqli = data.get("sql_injection", "off")
        commandinj = data.get("command_injection", "off")
        idor_scan = data.get("idor", "off")
        csrf_scan = data.get("csrf", "off")
        bac_scan = data.get("bac", "off")
        
        if not url:
            return jsonify({"error": "Validation Error", "details": "URL is required."}), 400
        if not scan_type or scan_type not in ["full", "custom"]:
            return jsonify({"error": "Validation Error", "details": "Invalid scan_type. Must be 'full' or 'custom'."}), 400
        if not client_sid:
            return jsonify({"error": "Validation Error", "details": "Socket ID (sid) is required for progress updates."}), 400

        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            return jsonify({"error": "Invalid URL", "details": "Could not parse domain from URL."}), 400
        domain = parsed_url.netloc

        scan_history = session.query(ScanHistory).filter_by(domain=domain).first()
        if scan_history:
            scan_history.scan_date = func.now()
        else:
            scan_history = ScanHistory(domain=domain)
            session.add(scan_history)
        session.commit()
        scan_id = scan_history.id

        scans_base_dir = current_app.config.get('SCANS_BASE_DIR', 'scans')
        url_directory = os.path.join(scans_base_dir, domain.replace('.', '_').replace(':', '_'))
        os.makedirs(url_directory, exist_ok=True)

        progress_emitter(scan_id, f'Scan started for {domain} (ID: {scan_id}).', 'info', client_sid, 0)

        login_event = None
        if active_crawl and open_browser:
            login_event = threading.Event()
            scan_login_events[scan_id] = login_event

        if scan_type == "full":
            scan_thread = threading.Thread(
                target=full_scan_func,
                args=(
                    url, headers, url_directory, scan_id, client_sid,
                    db_session_factory, progress_emitter, vulnerability_emitter,
                    num_threads_global, sio,
                    True, True, open_browser, True, True, wordlist_path,
                    login_event, headers2
                )
            )
        elif scan_type == "custom":
            scan_thread = threading.Thread(
                target=custom_scan_func,
                args=(
                    url, headers, crawling, xss, sqli, commandinj, idor_scan, csrf_scan,
                    url_directory, scan_id, client_sid, db_session_factory, progress_emitter,
                    vulnerability_emitter, num_threads_global, sio,
                    passive_crawl, active_crawl, open_browser, passive_subdomain, active_subdomain, wordlist_path,
                    login_event, headers2, bac_scan
                )
            )
        
        scan_thread.start()

        return jsonify({"message": "Scan initiated successfully.", "scan_id": scan_id}), 202

    except Exception as e:
        session.rollback()
        current_app.logger.error(f"Error starting scan for {url}: {str(e)}")
        progress_emitter(scan_id if 'scan_id' in locals() else 'N/A', f'Error starting scan: {str(e)}', 'error', client_sid, 0)
        if 'scan_id' in locals() and scan_id in scan_login_events:
            del scan_login_events[scan_id]
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
    finally:
        session.close()

@api_bp.route("/scans/<int:scan_id>/login_complete", methods=["POST"])
def signal_login_complete_api(scan_id):
    """
    API endpoint to signal that manual login for a scan is complete.
    This will set the threading.Event associated with the scan_id.
    """
    scan_login_events = current_app.config['SCAN_LOGIN_EVENTS']
    if scan_id in scan_login_events:
        login_event = scan_login_events[scan_id]
        login_event.set() # Set the event to unblock the scan thread
        # Optionally remove the event from the dict if it's no longer needed after being set
        del scan_login_events[scan_id] 
        current_app.logger.info(f"Login complete signal received for scan ID: {scan_id}")
        return jsonify({"message": f"Login complete signal processed for scan ID {scan_id}."}), 200
    else:
        return jsonify({"error": "Not Found", "details": f"No active login event found for scan ID {scan_id}."}), 404


@api_bp.route("/scans/<int:scan_id>/results", methods=["GET"])
def get_scan_results_api(scan_id):
    """
    API endpoint to retrieve results for a specific scan ID.
    """
    db_session_factory = current_app.config['DB_SESSION_FACTORY']
    session = db_session_factory()
    try:
        scan_history = session.query(ScanHistory).filter_by(id=scan_id).first()
        if not scan_history:
            return jsonify({"error": "Not Found", "details": f"Scan with ID {scan_id} not found."}), 404

        vulnerabilities = [v.vulnerability_data for v in scan_history.vulnerabilities]
        endpoints = [{
            "url": e.url,
            "method": e.method,
            "body_params": json.loads(e.body_params) if e.body_params else {},
            "extra_headers": json.loads(e.extra_headers) if e.extra_headers else {}
        } for e in scan_history.endpoints]
        recon_results = [{"type": r.data_type, "value": r.value} for r in scan_history.recon_data]

        response_data = {
            "scan_id": scan_history.id,
            "domain": scan_history.domain,
            "scan_date": scan_history.scan_date.isoformat(),
            "vulnerabilities": vulnerabilities,
            "endpoints": endpoints,
            "recon_results": recon_results,
            "status": "completed"
        }

        return jsonify(response_data), 200
    except Exception as e:
        current_app.logger.error(f"Error retrieving results for scan ID {scan_id}: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
    finally:
        session.close()

@api_bp.route("/history/export", methods=["GET"])
def export_history_api():
    """
    API endpoint to export all scan history data in various formats.
    For PDF/HTML, it renders the HTML template.
    """
    export_format = request.args.get("format", "json").lower()
    db_session_factory = current_app.config['DB_SESSION_FACTORY']
    session = db_session_factory()
    try:
        all_scan_data_raw = session.query(ScanHistory).all()
        
        all_scan_data_processed = []
        for scan_record in all_scan_data_raw:
            vulnerabilities = [v.vulnerability_data for v in scan_record.vulnerabilities]
            recon_results = [{"type": r.data_type, "value": r.value} for r in scan_record.recon_data]
            endpoints = [{
                "url": e.url, "method": e.method,
                "body_params": json.loads(e.body_params) if e.body_params else {},
                "extra_headers": json.loads(e.extra_headers) if e.extra_headers else {}
            } for e in scan_record.endpoints]

            all_scan_data_processed.append({
                "scan_id": scan_record.id,
                "domain": scan_record.domain,
                "scan_date": scan_record.scan_date.isoformat(),
                "recon_results": recon_results,
                "endpoints": endpoints,
                "vulnerabilities": vulnerabilities,
                # Removed: "chart_image_b64" as it's generated client-side now
            })
        
        if export_format == "json":
            json_output = json.dumps(all_scan_data_processed, indent=4)
            response = Response(json_output, mimetype='application/json')
            response.headers.set("Content-Disposition", "attachment", filename="vulnscanx_history.json")
            return response
        elif export_format == "csv":
            def generate_csv():
                header = ['Scan ID', 'Domain', 'Scan Date', 'Vulnerability Type', 'Severity', 'Vulnerable URL', 'Method', 'Description/Evidence']
                yield ','.join(header) + '\n'

                for scan in all_scan_data_processed:
                    if scan['vulnerabilities']:
                        for vuln in scan['vulnerabilities']:
                            vuln_type = vuln.get('vulnerability', 'N/A')
                            severity = vuln.get('severity', 'N/A')
                            vuln_url = vuln.get('url', 'N/A')
                            vuln_method = vuln.get('method', 'N/A')
                            payload_details = vuln.get('payload', vuln.get('description', vuln.get('evidence', 'N/A')))
                            
                            row = [
                                str(scan['scan_id']),
                                scan['domain'],
                                scan['scan_date'],
                                vuln_type,
                                severity,
                                vuln_url,
                                vuln_method,
                                json.dumps(payload_details) if isinstance(payload_details, dict) else str(payload_details)
                            ]
                            yield ','.join(map(lambda x: f'"{x.replace("\"", "\"\"")}"' if ',' in str(x) or '\n' in str(x) else str(x), row)) + '\n'
                    else:
                        row = [
                            str(scan['scan_id']),
                            scan['domain'],
                            scan['scan_date'],
                            'No vulnerabilities', 'N/A', 'N/A', 'N/A', 'N/A'
                        ]
                        yield ','.join(map(lambda x: f'"{x.replace("\"", "\"\"")}"' if ',' in str(x) or '\n' in str(x) else str(x), row)) + '\n'

            response = Response(stream_with_context(generate_csv()), mimetype='text/csv')
            response.headers.set("Content-Disposition", "attachment", filename="vulnscanx_history.csv")
            return response
        elif export_format == "html" or export_format == "pdf": # PDF will fetch HTML and convert client-side
            html_content = _generate_report_html('report_history.html', {
                'all_scan_data': all_scan_data_processed,
                'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            response = Response(html_content, mimetype='text/html')
            response.headers.set("Content-Disposition", "attachment", filename="vulnscanx_history.html")
            return response
        else:
            return jsonify({"error": "Invalid export format. Choose 'json', 'csv', 'html', or 'pdf'."}), 400

    except Exception as e:
        current_app.logger.error(f"Error exporting history: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": f"Error exporting history: {str(e)}"}), 500
    finally:
        session.close()

@api_bp.route("/scans/<int:scan_id>/export", methods=["GET"])
def export_single_scan_api(scan_id):
    """
    API endpoint to export a single scan's data in various formats.
    For PDF/HTML, it renders the HTML template.
    """
    export_format = request.args.get("format", "json").lower()
    db_session_factory = current_app.config['DB_SESSION_FACTORY']
    session = db_session_factory()
    try:
        scan_record = session.query(ScanHistory).filter_by(id=scan_id).first()
        if not scan_record:
            return jsonify({"error": "Not Found", "details": f"Scan with ID {scan_id} not found."}), 404
        
        vulnerabilities = [v.vulnerability_data for v in scan_record.vulnerabilities]
        recon_results = [{"type": r.data_type, "value": r.value} for r in scan_record.recon_data]
        endpoints = [{
            "url": e.url, "method": e.method,
            "body_params": json.loads(e.body_params) if e.body_params else {},
            "extra_headers": json.loads(e.extra_headers) if e.extra_headers else {}
        } for e in scan_record.endpoints]

        single_scan_data = {
            "scan_id": scan_record.id,
            "domain": scan_record.domain,
            "scan_date": scan_record.scan_date.isoformat(),
            "recon_results": recon_results,
            "endpoints": endpoints,
            "vulnerabilities": vulnerabilities,
            # Removed: "chart_image_b64" as it's generated client-side now
        }
        
        if export_format == "json":
            json_output = json.dumps(single_scan_data, indent=4)
            response = Response(json_output, mimetype='application/json')
            response.headers.set("Content-Disposition", "attachment", filename=f"vulnscanx_scan_{scan_id}.json")
            return response
        elif export_format == "csv":
            def generate_csv():
                header = ['Scan ID', 'Domain', 'Scan Date', 'Vulnerability Type', 'Severity', 'Vulnerable URL', 'Method', 'Description/Evidence', 'Recon Type', 'Recon Value', 'Endpoint URL', 'Endpoint Method']
                yield ','.join(header) + '\n'

                vulns_csv = []
                for vuln in single_scan_data['vulnerabilities']:
                    vulns_csv.append([
                        str(single_scan_data['scan_id']),
                        single_scan_data['domain'],
                        single_scan_data['scan_date'],
                        vuln.get('vulnerability', 'N/A'),
                        vuln.get('severity', 'N/A'),
                        vuln.get('url', 'N/A'),
                        vuln.get('method', 'N/A'),
                        json.dumps(vuln.get('payload', vuln.get('description', vuln.get('evidence', 'N/A')))) if isinstance(vuln.get('payload'), dict) else str(vuln.get('payload', vuln.get('description', vuln.get('evidence', 'N/A')))),
                        '', '', '', ''
                    ])
                
                recon_csv = []
                for recon in single_scan_data['recon_results']:
                    recon_csv.append([
                        str(single_scan_data['scan_id']),
                        single_scan_data['domain'],
                        single_scan_data['scan_date'],
                        '', '', '', '', '',
                        recon.get('type', 'N/A'),
                        recon.get('value', 'N/A'),
                        '', ''
                    ])

                endpoints_csv = []
                for endpoint in single_scan_data['endpoints']:
                    endpoints_csv.append([
                        str(single_scan_data['scan_id']),
                        single_scan_data['domain'],
                        single_scan_data['scan_date'],
                        '', '', '', '', '', '', '',
                        endpoint.get('url', 'N/A'),
                        endpoint.get('method', 'N/A')
                    ])
                
                all_rows = vulns_csv + recon_csv + endpoints_csv
                if not all_rows:
                    all_rows.append([str(single_scan_data['scan_id']), single_scan_data['domain'], single_scan_data['scan_date'], 'No data', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A'])

                for row in all_rows:
                    yield ','.join(map(lambda x: f'"{str(x).replace("\"", "\"\"")}"' if ',' in str(x) or '\n' in str(x) else str(x), row)) + '\n'

            response = Response(stream_with_context(generate_csv()), mimetype='text/csv')
            response.headers.set("Content-Disposition", "attachment", filename=f"vulnscanx_scan_{scan_id}.csv")
            return response
        elif export_format == "html" or export_format == "pdf": # PDF will fetch HTML and convert client-side
            html_content = _generate_report_html('report_single_scan.html', {
                'scan': single_scan_data,
                'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            response = Response(html_content, mimetype='text/html')
            response.headers.set("Content-Disposition", "attachment", filename=f"vulnscanx_scan_{scan_id}.html")
            return response
        else:
            return jsonify({"error": "Invalid export format. Choose 'json', 'csv', 'html', or 'pdf'."}), 400

    except Exception as e:
        current_app.logger.error(f"Error exporting single scan {scan_id}: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": f"Error exporting single scan: {str(e)}"}), 500
    finally:
        session.close()


@api_bp.route("/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan_api(scan_id):
    """
    API endpoint to delete a scan history record by its ID.
    """
    db_session_factory = current_app.config['DB_SESSION_FACTORY']
    session = db_session_factory()
    try:
        scan_history = session.query(ScanHistory).filter_by(id=scan_id).first()
        if not scan_history:
            return jsonify({"success": False, "error": "Not Found", "details": f"Scan with ID {scan_id} not found."}), 404

        session.delete(scan_history)
        session.commit()
        return jsonify({"success": True, "message": f"Scan history for ID {scan_id} deleted successfully."}), 200
    except Exception as e:
        session.rollback()
        current_app.logger.error(f"Error deleting scan for ID {scan_id}: {str(e)}")
        return jsonify({"success": False, "error": "Internal Server Error", "details": f"Error deleting scan: {str(e)}"}), 500
    finally:
        session.close()


def register_routes(app, sio, db_session_factory, db_engine, progress_emitter, vulnerability_emitter, num_threads_global, full_scan_func, custom_scan_func, scan_login_events):
    """
    Registers all blueprints and configures the Flask application.
    """
    # Store necessary objects in app.config for access within blueprints
    app.config['DB_SESSION_FACTORY'] = db_session_factory
    app.config['DB_ENGINE'] = db_engine
    app.config['PROGRESS_EMITTER'] = progress_emitter
    app.config['VULNERABILITY_EMITTER'] = vulnerability_emitter
    app.config['NUM_THREADS_GLOBAL'] = num_threads_global
    app.config['FULL_SCAN_FUNC'] = full_scan_func
    app.config['CUSTOM_SCAN_FUNC'] = custom_scan_func
    app.config['SIO_INSTANCE'] = sio
    app.config['SCAN_LOGIN_EVENTS'] = scan_login_events

    # Register blueprints
    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp)

    # REGISTER A GENERIC 404 ERROR HANDLER
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html', title='Page Not Found'), 404