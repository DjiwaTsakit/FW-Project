import re
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Pola regex lengkap berdasarkan PayloadsAllTheThings
PATTERNS = {
    'sql': re.compile(r'(id=|select=|union=|insert=|update=|delete=|drop=|exec=|from=|where=)', re.IGNORECASE),
    'rce': re.compile(r'(cmd=|exec=|run=|system=|eval=|passthru=|shell_exec=)', re.IGNORECASE),
    'lfi_rfi': re.compile(r'(file=|path=|include=|require=|php://|zip://)', re.IGNORECASE),
    'dir_traversal': re.compile(r'(\.\./|\.\.\\|/etc/passwd|C:\\Windows\\|\.\\\.\\\.\\\.)', re.IGNORECASE),
    'xss': re.compile(r'(<script>|javascript:|onerror=|onload=|alert\(|<\?php)', re.IGNORECASE),
    'open_redirect': re.compile(r'(redirect=|url=|next=|rurl=|dest=|destination=)', re.IGNORECASE),
    'suspicious_ext': re.compile(r'(\.php|\.sh|\.exe|\.tar|\.zip|\.bin|\.pl|\.py|\.jsp|\.war)', re.IGNORECASE),
    'xxe': re.compile(r'(<!ENTITY|SYSTEM|PUBLIC|DOCTYPE)', re.IGNORECASE),
    'ssrf': re.compile(r'(http://|https://|127.0.0.1|localhost)', re.IGNORECASE),
    'ssti': re.compile(r'(\{\{|\}\}|%7B%7B|%7D%7D)', re.IGNORECASE),
    'command_injection': re.compile(r'(\|;|&|\$\(|\`|\n|\r)', re.IGNORECASE),
    'csrf': re.compile(r'(<input type="hidden"|csrf_token|csrfmiddlewaretoken)', re.IGNORECASE),
    'idor': re.compile(r'(id=|user=|account=|profile=|uid=)', re.IGNORECASE),
    'xxs': re.compile(r'(<img|<iframe|<svg|<body|<style|<link)', re.IGNORECASE),
}

def filter_url(url, vuln_type):
    """Memfilter URL berdasarkan jenis kerentanan tertentu."""
    if vuln_type in PATTERNS:
        return PATTERNS[vuln_type].search(url) is not None
    return False

def process_urls(urls, vuln_type):
    """Memproses daftar URL dan mengembalikan URL yang sesuai dengan jenis kerentanan."""
    matched_urls = []
    with ThreadPoolExecutor(max_workers=20) as executor:  # Meningkatkan jumlah worker
        future_to_url = {executor.submit(filter_url, url, vuln_type): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                if future.result():
                    matched_urls.append(url)
            except Exception as e:
                print(f"Error processing URL {url}: {e}")
    return matched_urls

def main():
    parser = argparse.ArgumentParser(
        description="Filter URLs based on security vulnerability patterns.",
        formatter_class=argparse.RawTextHelpFormatter  # Memungkinkan formatting multi-baris
    )

    # Argumen input file
    parser.add_argument(
        'input_file',
        type=str,
        help="Input file containing URLs (e.g., output from waybackurls)."
    )

    # Argumen jenis kerentanan
    parser.add_argument(
        '-t', '--type',
        type=str,
        required=True,
        choices=PATTERNS.keys(),
        help="""Type of vulnerability to filter. Available options:
  - sql               : Detect SQL Injection patterns (e.g., id=, select=).
  - rce               : Detect Remote Code Execution patterns (e.g., cmd=, exec=).
  - lfi_rfi           : Detect Local/Remote File Inclusion patterns (e.g., file=, path=).
  - dir_traversal     : Detect Directory Traversal patterns (e.g., ../, /etc/passwd).
  - xss               : Detect Cross-Site Scripting patterns (e.g., <script>, javascript:).
  - open_redirect     : Detect Open Redirect patterns (e.g., redirect=, url=).
  - suspicious_ext    : Detect suspicious file extensions (e.g., .php, .exe).
  - xxe               : Detect XML External Entity patterns (e.g., <!ENTITY, SYSTEM).
  - ssrf              : Detect Server-Side Request Forgery patterns (e.g., http://, 127.0.0.1).
  - ssti              : Detect Server-Side Template Injection patterns (e.g., {{, }}).
  - command_injection : Detect Command Injection patterns (e.g., |, ;, &).
  - csrf              : Detect Cross-Site Request Forgery patterns (e.g., csrf_token).
  - idor              : Detect Insecure Direct Object Reference patterns (e.g., id=, user=).
  - xxs               : Detect HTML/XML Injection patterns (e.g., <img, <iframe)."""
    )

    # Argumen output file
    parser.add_argument(
        '-o', '--output',
        type=str,
        help="Output file to save the results."
    )

    args = parser.parse_args()

    # Membaca file input
    with open(args.input_file, 'r') as file:
        urls = file.read().splitlines()

    # Memproses URL
    matched_urls = process_urls(urls, args.type)

    # Menampilkan hasil
    print(f"Found {len(matched_urls)} URLs with potential {args.type} vulnerability:")
    for url in matched_urls:
        print(url)

    # Menyimpan hasil ke file jika opsi output diberikan
    if args.output:
        with open(args.output, 'w') as file:
            for url in matched_urls:
                file.write(url + '\n')
        print(f"Results saved to {args.output}")

if __name__ == "__main__":
    main()
