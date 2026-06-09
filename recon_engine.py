import requests
import json
import re
import time
from colorama import Fore, Style, init

# Initialize colorama for clean terminal formatting
init(autoreset=True)

# 1. High-value exposed paths to audit
SENSITIVE_PATHS = [
    "/.env",
    "/.env.production",
    "/.env.local",
    "/.env.dev",
    "/config/database.yml",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/.git/config"
]

# Signatures to look for inside a file to confirm it is actually a leaked configuration
ENV_SIGNATURES = [
    "DB_PASSWORD", "DB_HOST", "AWS_SECRET_ACCESS_KEY", 
    "SECRET_KEY", "JWT_SECRET", "STRIPE_API_KEY"
]

def extract_subdomains(domain):
    print(f"{Fore.BLUE}[*] Gathering subdomains for {domain} from CT Logs...")
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry['name_value'].lower()
                if "\n" in name:
                    sub_list = name.split("\n")
                    for sub in sub_list:
                        if not sub.startswith("*."):
                            subdomains.add(sub)
                else:
                    if not name.startswith("*."):
                        subdomains.add(name)
            print(f"{Fore.GREEN}[+] Found {len(subdomains)} unique subdomains.")
            return list(subdomains)
    except Exception as e:
        print(f"{Fore.RED}[-] Error fetching from crt.sh: {e}")
    return []

def check_sensitive_paths(base_url):
    """Appends high-value files to the live URL and analyzes the responses."""
    for path in SENSITIVE_PATHS:
        target_path_url = f"{base_url}{path}"
        
        # Define standard headers + Intigriti tracking header placeholder
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            # "X-Bug-Bounty": "Intigriti-yourusername"  # Uncomment and update this if program rules request it
        }
        
        try:
            # We add allow_redirects=False so we don't get fooled by login portals redirecting us
            response = requests.get(target_path_url, headers=headers, timeout=4, verify=False, allow_redirects=False)
            
            if response.status_code == 200:
                content = response.text
                
                # Check if the page content actually matches a config file (avoids false positives)
                if any(sig in content for sig in ENV_SIGNATURES) or "repositoryformatversion" in content:
                    print(f"{Fore.RED}[!!!] CRITICAL EXPOSURE: Found valid configuration file at: {target_path_url}")
                    # Print the first 3 lines just as proof to review safely
                    preview = "\n".join(content.splitlines()[:3])
                    print(f"{Fore.YELLOW}--- File Preview ---\n{preview}\n-------------------")
                    
        except requests.exceptions.RequestException:
            pass
        
        # 2. Rate limiting delay: Sleep for 200ms between path checks to be polite to target servers
        time.sleep(0.2)

def scan_target(subdomain):
    protocols = ["https://", "http://"]
    for protocol in protocols:
        target_url = f"{protocol}{subdomain}"
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            # Fast check to see if the main subdomain responds
            response = requests.head(target_url, headers=headers, timeout=4, verify=False, allow_redirects=True)
            
            # If the host is up, execute the path scanning pipeline
            print(f"{Fore.CYAN}[+] Host Active: {target_url} - Initiating configuration audit...")
            check_sensitive_paths(target_url)
            return # Host found via this protocol, skip to next subdomain
            
        except requests.exceptions.RequestException:
            continue

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    
    print(f"{Fore.MAGENTA}=== INTIGRITI CONFIGURATION & SECRET HUNTER ===")
    target_domain = input("Enter target domain (e.g., example.com): ").strip()
    
    if target_domain:
        subdomains = extract_subdomains(target_domain)
        if subdomains:
            print(f"\n{Fore.BLUE}[*] Starting live-host validation and sensitive file scanning...")
            for sub in subdomains:
                scan_target(sub)
                # Small pause between analyzing different subdomains
                time.sleep(0.5)
            print(f"\n{Fore.MAGENTA}=== Audit Complete ===")
        else:
            print(Fore.RED + "[-] No subdomains found to analyze.")
    else:
        print(Fore.RED + "[-] Invalid Input.")