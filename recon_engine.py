import requests
import json
import re
from colorama import Fore, Style, init

# Initialize colorama for clean terminal formatting
init(autoreset=True)

def extract_subdomains(domain):
    print(f"{Fore.BLUE}[*] Gathering subdomains for {domain} from CT Logs...")
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                # Clean up the findings (remove wildcard characters)
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

# Common regex patterns used by offensive security engineers to find leaked secrets
SECRET_PATTERNS = {
    "AWS API Key": r"AKIA[0-9A-Z]{16}",
    "Slack Token": r"xox[bapr]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
    "Generic API Key / Secret": r"(?i)(api_key|secret_key|auth_token|password)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]"
}

def scan_target(subdomain):
    # Test both HTTP and HTTPS protocols
    protocols = ["https://", "http://"]
    for protocol in protocols:
        target_url = f"{protocol}{subdomain}"
        try:
            # Send request simulating a normal browser
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            response = requests.get(target_url, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                print(f"{Fore.CYAN}[HTTP 200] Analyzing content of: {target_url}")
                page_content = response.text
                
                # Run regex checks against the page source code
                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, page_content)
                    if matches:
                        for match in matches:
                            # Handle tuple results from regex capture groups
                            match_str = match[1] if isinstance(match, tuple) else match
                            print(f"{Fore.YELLOW}[!] CRITICAL: Found potential {secret_type} on {target_url} -> {match_str[:10]}...")
                return # Stop if one protocol works to save time
        except requests.exceptions.RequestException:
            continue # If connection fails, try the next protocol or move on

if __name__ == "__main__":
    # Disable SSL warning messages for aggressive scanning
    requests.packages.urllib3.disable_warnings()
    
    print(f"{Fore.MAGENTA}=== OFFENSIVE RECON & ASSET SCANNER ===")
    target_domain = input("Enter target domain (e.g., example.com): ").strip()
    
    if target_domain:
        subdomains = extract_subdomains(target_domain)
        if subdomains:
            print(f"\n{Fore.BLUE}[*] Starting active live-host and secret scan...")
            for sub in subdomains:
                scan_target(sub)
            print(f"\n{Fore.MAGENTA}=== Scan Complete ===")
        else:
            print(Fore.RED + "[-] No subdomains found to analyze.")
    else:
        print(Fore.RED + "[-] Invalid Input.")
    