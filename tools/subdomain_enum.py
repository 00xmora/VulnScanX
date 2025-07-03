import os
import subprocess
import requests
import re
import json
import time
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import logging
from sqlalchemy.exc import IntegrityError
from tools.database import ReconResult # Assuming tools.database is the path after moving database.py

logger = logging.getLogger(__name__)

# Load API keys from config (assuming config.ini will be read by autorecon.py and passed)
# For independent testing, these would need to be loaded here too, but for modularity, assume parent handles.
PENTEST_API_KEY = None
SECURITYTRAILS_API_KEY = None
VIRUSTOTAL_API_KEY = None

def set_api_keys(pentest_key, securitytrails_key, virustotal_key):
    global PENTEST_API_KEY, SECURITYTRAILS_API_KEY, VIRUSTOTAL_API_KEY
    PENTEST_API_KEY = pentest_key
    SECURITYTRAILS_API_KEY = securitytrails_key
    VIRUSTOTAL_API_KEY = virustotal_key

def run_command(command, silent=False, output_file=None):
    """
    Executes a shell command.
    Args:
        command (str): The command to execute.
        silent (bool): If True, suppress stdout and stderr.
        output_file (str): If provided, redirect stdout to this file.
    Returns:
        bool: True if command succeeded, False otherwise.
    """
    try:
        if silent and output_file:
            subprocess.run(command, shell=True, check=True, stdout=open(output_file, 'w'), stderr=subprocess.DEVNULL)
        elif silent:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running command: {command} - {e}")
        return False
    return True

def get_subdomains_from_free_services(target, session=None, scan_id=None):
    """
    Retrieves subdomains from various free online services.
    Args:
        target (str): The target domain.
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
    Returns:
        set: A set of unique subdomains found.
    """
    print(f"[+] Retrieving subdomains from free services for {target}...")
    subdomains = set()
    base_domain = target

    # Pentest-Tools API
    if PENTEST_API_KEY:
        headers = {"X-API-Key": PENTEST_API_KEY}
        base_url = "https://pentest-tools.com/api"
        try:
            response = requests.post(f"{base_url}/targets", json={"name": target, "type": "domain"}, headers=headers)
            target_id = response.json().get("id")
            scan_data = {"target_id": target_id, "tool": "subdomain_finder"}
            response = requests.post(f"{base_url}/scans", json=scan_data, headers=headers)
            scan_id_pt = response.json().get("scan_id")
            while True:
                response = requests.get(f"{base_url}/scans/{scan_id_pt}", headers=headers)
                data = response.json()
                if data.get("status") == "finished":
                    for sub in data.get("results", {}).get("subdomains", []):
                        if sub.endswith(f".{target}") or sub == target:
                            subdomains.add(sub)
                    break
                time.sleep(10)
            print(f"[+] Retrieved subdomains from Pentest-Tools API")
        except Exception as e:
            print(f"Error with Pentest-Tools API: {e}")
    else:
        try:
            url = f"https://pentest-tools.com/information-gathering/find-subdomains-of-domain?domain={target}"
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            for div in soup.select("div.subdomain-result"):
                subdomain = div.text.strip()
                if subdomain.endswith(f".{target}") or subdomain == target:
                    subdomains.add(subdomain)
            print(f"[+] Retrieved subdomains from Pentest-Tools web")
        except Exception as e:
            print(f"Error with Pentest-Tools web: {e}")

    # DNSdumpster
    try:
        response = requests.get("https://dnsdumpster.com", timeout=10)
        csrf_token_match = re.search(r'name="csrfmiddlewaretoken" value="(.+?)"', response.text)
        if csrf_token_match:
            csrf_token = csrf_token_match.group(1)
            data = {"csrfmiddlewaretoken": csrf_token, "targetip": target}
            headers = {"Referer": "https://dnsdumpster.com"}
            response = requests.post("https://dnsdumpster.com", data=data, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            for td in soup.select("td.col-md-4"):
                subdomain = td.text.strip()
                if subdomain.endswith(f".{target}") or subdomain == target:
                    subdomains.add(subdomain)
            print(f"[+] Retrieved subdomains from DNSdumpster")
        else:
            print(f"[!] CSRF token not found for DNSdumpster.")
    except Exception as e:
        print(f"Error with DNSdumpster: {e}")

    print(f"[+] Nmmapper.com requires manual retrieval: https://www.nmmapper.com/subdomains")

    # SecurityTrails
    if SECURITYTRAILS_API_KEY:
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        try:
            response = requests.get(f"https://api.securitytrails.com/v1/domain/{target}/subdomains", headers=headers)
            data = response.json()
            for sub in data.get("subdomains", []):
                full_subdomain = f"{sub}.{target}"
                if full_subdomain.endswith(f".{target}") or full_subdomain == target:
                    subdomains.add(full_subdomain)
            print(f"[+] Retrieved subdomains from SecurityTrails")
        except Exception as e:
            print(f"Error with SecurityTrails: {e}")

    # Crt.sh
    try:
        response = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=10)
        for entry in response.json():
            name = entry.get("name_value", "").strip()
            if name.endswith(f".{target}") or name == target:
                subdomains.add(name)
        print(f"[+] Retrieved subdomains from Crt.sh")
    except Exception as e:
        print(f"Error with Crt.sh: {e}")

    print(f"[+] SubdomainFinder.c99.nl requires manual retrieval: https://subdomainfinder.c99.nl")

    # VirusTotal
    if VIRUSTOTAL_API_KEY:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/domains/{target}/subdomains", headers=headers)
            data = response.json()
            for sub in data.get("data", []):
                sub_id = sub.get("id")
                if sub_id and (sub_id.endswith(f".{target}") or sub_id == target):
                    subdomains.add(sub_id)
            print(f"[+] Retrieved subdomains from VirusTotal")
        except Exception as e:
            print(f"Error with VirusTotal: {e}")

    print(f"[+] FindSubDomains.com requires manual retrieval: https://findsubdomains.com")

    # Netcraft
    try:
        response = requests.get(f"https://searchdns.netcraft.com/?host=*.{target}", timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        for a in soup.select("a[href*='site=']"):
            subdomain_match = re.search(r"site=([^&]+)", a["href"])
            if subdomain_match:
                subdomain = subdomain_match.group(1)
                if subdomain.endswith(f".{target}") or subdomain == target:
                    subdomains.add(subdomain)
        print(f"[+] Retrieved subdomains from Netcraft")
    except Exception as e:
        print(f"Error with Netcraft: {e}")

    # SOCRadar
    try:
        response = requests.get(f"https://api.socradar.io/tools/subdomains?domain={target}", timeout=10)
        data = response.json()
        for sub in data.get("subdomains", []):
            if sub.endswith(f".{target}") or sub == target:
                subdomains.add(sub)
        print(f"[+] Retrieved subdomains from SOCRadar")
    except Exception as e:
        print(f"Error with SOCRadar: {e}")

    # Store unique subdomains in the database
    if session and scan_id is not None:
        for subdomain_value in subdomains:
            try:
                new_recon_result = ReconResult(
                    scan_id=scan_id,
                    data_type="subdomain",
                    value=subdomain_value
                )
                session.add(new_recon_result)
                session.commit()
            except IntegrityError:
                session.rollback()
                logger.info(f"Duplicate subdomain found and skipped: {subdomain_value}")
            except Exception as db_e:
                session.rollback()
                logger.error(f"Error saving subdomain to DB: {db_e}")

    return subdomains

def passive_subdomain_enum(domain, threads=20, session=None, scan_id=None):
    """
    Performs passive subdomain enumeration using tools like Amass, Subfinder, and Sublist3r.
    Args:
        domain (str): The target domain.
        threads (int): Number of threads for concurrent execution.
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
    """
    print(f"[+] Running passive subdomain enumeration with {threads} threads...")
    amass_output_file = "amass_passive_output.txt"
    subfinder_output_file = "subfinder_passive_output.txt"
    sublist3r_output_file = "sublist3r_passive_output.txt"
    
    commands = [
        (f"amass enum -passive -d {domain} -o {amass_output_file}", amass_output_file),
        (f"subfinder -d {domain} -o {subfinder_output_file}", subfinder_output_file),
        (f"sublist3r -d {domain} -o {sublist3r_output_file}", sublist3r_output_file)
    ]
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(run_command, cmd, True, outfile): outfile 
                   for cmd, outfile in commands}
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Error in thread for {futures[future]}: {e}")
    
    all_subdomains = set()
    for outfile in [amass_output_file, subfinder_output_file, sublist3r_output_file]:
        if os.path.exists(outfile):
            with open(outfile, 'r') as f:
                for line in f:
                    sub = line.strip()
                    if sub.endswith(f".{domain}") or sub == domain:
                        all_subdomains.add(sub)
            os.remove(outfile)

    if session and scan_id is not None:
        for subdomain_value in all_subdomains:
            try:
                new_recon_result = ReconResult(
                    scan_id=scan_id,
                    data_type="subdomain",
                    value=subdomain_value
                )
                session.add(new_recon_result)
                session.commit()
            except IntegrityError:
                session.rollback()
                logger.info(f"Duplicate subdomain found and skipped: {subdomain_value}")
            except Exception as db_e:
                session.rollback()
                logger.error(f"Error saving subdomain to DB: {db_e}")

def filter_live_domains(session=None, scan_id=None):
    """
    Filters live domains from the stored subdomains using httpx.
    Args:
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
    """
    print(f"[+] Filtering live domains...")
    
    current_subdomains = session.query(ReconResult).filter_by(scan_id=scan_id, data_type="subdomain").all()
    
    if not current_subdomains:
        print(f"[!] No subdomains found in DB for filtering")
        return

    temp_domains_file = "temp_domains_for_httpx.txt"
    with open(temp_domains_file, "w") as f:
        for sub in current_subdomains:
            f.write(sub.value + "\n")

    live_domains_output_file = "domain.live"
    if run_command(f"cat {temp_domains_file} | httpx -silent -o {live_domains_output_file}", silent=True):
        print(f"[+] Live domains filtered")
        if os.path.exists(live_domains_output_file):
            with open(live_domains_output_file, "r") as f:
                live_domains = set(f.read().splitlines())
            os.remove(live_domains_output_file)

            if session and scan_id is not None:
                for live_sub in live_domains:
                    try:
                        new_live_recon = ReconResult(
                            scan_id=scan_id,
                            data_type="live_subdomain",
                            value=live_sub
                        )
                        session.add(new_live_recon)
                        session.commit()
                    except IntegrityError:
                        session.rollback()
                        logger.info(f"Duplicate live subdomain found and skipped: {live_sub}")
                    except Exception as db_e:
                        session.rollback()
                        logger.error(f"Error saving live subdomain to DB: {db_e}")

    else:
        print(f"[!] Failed to filter live domains")
    
    os.remove(temp_domains_file)

def active_subdomain_enum(domain, session=None, scan_id=None, wordlist_path=None):
    """
    Performs active subdomain enumeration using dnsrecon and ffuf for virtual host enumeration.
    Args:
        domain (str): The target domain.
        session (sqlalchemy.orm.session.Session): SQLAlchemy session for database operations.
        scan_id (int): ID of the current scan in ScanHistory.
        wordlist_path (str, optional): Path to the wordlist for FFUF.
    """
    print(f"[+] Running active subdomain enumeration with dnsrecon and ffuf...")
    
    live_domains_from_db = session.query(ReconResult).filter_by(scan_id=scan_id, data_type="live_subdomain").all()
    live_domains = {ld.value for ld in live_domains_from_db}

    # DNSRecon part
    try:
        dns_output_file = "dns_servers.txt"
        run_command(f"dig @8.8.8.8 NS {domain} +short > {dns_output_file}", silent=True)
        
        dns_servers = set()
        if os.path.exists(dns_output_file):
            with open(dns_output_file, "r") as f:
                dns_servers = {line.strip().rstrip('.') for line in f if line.strip()}
            os.remove(dns_output_file)
        
        ns_ips = []
        if dns_servers:
            for ns in dns_servers:
                ip_output_file = f"ns_ip_{ns}.txt"
                run_command(f"dig @8.8.8.8 A {ns} +short > {ip_output_file}", silent=True)
                if os.path.exists(ip_output_file):
                    with open(ip_output_file, "r") as f:
                        ips = [line.strip() for line in f if line.strip() and re.match(r"^\d+\.\d+\.\d+\.\d+$", line)]
                        if ips:
                            ns_ips.append(ips[0])
                    os.remove(ip_output_file)
        
        wordlist = wordlist_path or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
        if not os.path.exists(wordlist):
            print(f"[!] DNSRecon wordlist not found: {wordlist}. Skipping DNSRecon.")
        else:
            if ns_ips:
                ns_list_str = ",".join(ns_ips)
                print(f"[+] Querying name servers: -n {ns_list_str}")
                
                for i, ns_ip in enumerate(ns_ips):
                    ns_option = f"-n {ns_ip}"
                    dnsrecon_output = f"dnsrecon_output_{i}.json"
                    cmd = f"dnsrecon -d {domain} -t brt -D {wordlist} {ns_option} --lifetime 10 --threads 50 -j {dnsrecon_output} -f"
                    
                    if run_command(cmd, silent=True):
                        if os.path.exists(dnsrecon_output):
                            try:
                                with open(dnsrecon_output, "r") as f:
                                    data = json.load(f)
                                    for record in data:
                                        if record.get("type") in ["A", "CNAME"] and (record.get("name", "").endswith(f".{domain}") or record.get("name", "") == domain):
                                            live_domains.add(record.get("name"))
                            except json.JSONDecodeError:
                                print(f"[!] Failed to parse dnsrecon JSON output for {dnsrecon_output}")
                            os.remove(dnsrecon_output)
                        else:
                            print(f"[!] Failed to run dnsrecon with {ns_option}")
            else:
                print(f"[!] No authoritative DNS server IPs resolved, using system resolvers for dnsrecon")
                dnsrecon_output = "dnsrecon_output.json"
                cmd = f"dnsrecon -d {domain} -t brt -D {wordlist} --lifetime 10 --threads 50 -j {dnsrecon_output} -f"
                if run_command(cmd, silent=True):
                    if os.path.exists(dnsrecon_output):
                        try:
                            with open(dnsrecon_output, "r") as f:
                                data = json.load(f)
                                for record in data:
                                    if record.get("type") in ["A", "CNAME"] and (record.get("name", "").endswith(f".{domain}") or record.get("name", "") == domain):
                                        live_domains.add(record.get("name"))
                        except json.JSONDecodeError:
                            print(f"[!] Failed to parse dnsrecon JSON output")
                        os.remove(dnsrecon_output)
                    else:
                        print(f"[!] Failed to run dnsrecon with system resolvers")
    except Exception as e:
        print(f"[!] Error in dnsrecon part of active subdomain enumeration: {e}")

    # FFUF for Virtual Host Enumeration
    print(f"[+] Running FFUF for virtual host enumeration...")
    ffuf_wordlist = wordlist_path or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
    if not os.path.exists(ffuf_wordlist):
        print(f"[!] FFUF wordlist not found: {ffuf_wordlist}. Skipping FFUF.")
    else:
        ffuf_output_file = "ffuf_vhost_output.json"
        ffuf_cmd = (
            f"ffuf -w {ffuf_wordlist}:FUZZ -u http://{domain} -H 'Host: FUZZ.{domain}' "
            f"-mc 200,204,301,302,307,403 -of json -o {ffuf_output_file} -s"
        )
        
        if run_command(ffuf_cmd, silent=True):
            if os.path.exists(ffuf_output_file):
                try:
                    with open(ffuf_output_file, "r") as f:
                        ffuf_results = json.load(f)
                        for result in ffuf_results.get("results", []):
                            host_header_value = result.get("host")
                            if host_header_value and (host_header_value.endswith(f".{domain}") or host_header_value == domain):
                                live_domains.add(host_header_value)
                except json.JSONDecodeError:
                    print(f"[!] Failed to parse FFUF JSON output for {ffuf_output_file}")
                os.remove(ffuf_output_file)
            else:
                print(f"[!] Failed to run FFUF for virtual host enumeration")

    if session and scan_id is not None:
        for live_sub_value in live_domains:
            try:
                new_live_recon = ReconResult(
                    scan_id=scan_id,
                    data_type="live_subdomain",
                    value=live_sub_value
                )
                session.add(new_live_recon)
                session.commit()
            except IntegrityError:
                session.rollback()
                logger.info(f"Duplicate live subdomain from active enum found and skipped: {live_sub_value}")
            except Exception as db_e:
                session.rollback()
                logger.error(f"Error saving live subdomain from active enum to DB: {db_e}")

    print(f"[+] Active subdomain enumeration completed and saved to DB")