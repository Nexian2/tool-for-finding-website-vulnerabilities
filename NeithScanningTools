import requests, re, os, socket
from bs4 import BeautifulSoup
from fpdf import FPDF

BANNER = """
\033[95m
 ███╗   ██╗███████╗██╗████████╗██╗  ██╗██████╗ ███████╗ ██████╗ ███╗   ██╗
 ████╗  ██║██╔════╝██║╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔═══██╗████╗  ██║
 ██╔██╗ ██║█████╗  ██║   ██║   ███████║██████╔╝█████╗  ██║   ██║██╔██╗ ██║
 ██║╚██╗██║██╔══╝  ██║   ██║   ██╔══██║██╔═══╝ ██╔══╝  ██║   ██║██║╚██╗██║
 ██║ ╚████║███████╗██║   ██║   ██║  ██║██║     ███████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
                         \033[92m by Nolan | NeithRecon\033[0m
"""

class NeithAI:
    def suggest(self, vuln):
        responses = {
            "SQL Injection": "Use prepared statements or parameterized queries.",
            "XSS": "Always escape and validate user inputs before rendering.",
            "CSRF": "Implement a CSRF token in each form.",
            "IDOR": "Apply strict access control checks on every resource.",
            "SSRF": "Block internal IP ranges and validate outgoing requests.",
            "Login Bypass": "Use hashed passwords and strict input validation.",
            "Brute Force": "Use rate limiting and CAPTCHA mechanisms.",
        }
        return responses.get(vuln, "Manual audit is recommended for deeper investigation.")

def scan_sql_injection(url):
    payload = "' OR '1'='1"
    test = requests.get(url + payload)
    if "sql" in test.text.lower() or "mysql" in test.text.lower():
        return "SQL Injection"
    return None

def scan_xss(url):
    payload = "<script>alert(1)</script>"
    test = requests.get(url + "?q=" + payload)
    if payload in test.text:
        return "XSS"
    return None

def scan_csrf(html):
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    for f in forms:
        if not f.find("input", {"name": "csrf_token"}):
            return "CSRF"
    return None

def scan_idor(url):
    test = requests.get(url.replace("id=1", "id=2"))
    if test.status_code == 200 and "Unauthorized" not in test.text:
        return "IDOR"
    return None

def scan_ssrf(url):
    try:
        ip = socket.gethostbyname("127.0.0.1")
        if ip in requests.get(url).text:
            return "SSRF"
    except:
        return None

def login_bypass(url):
    data = {"username": "admin' --", "password": "x"}
    r = requests.post(url, data=data)
    if "Welcome" in r.text:
        return "Login Bypass"
    return None

def brute_force_test(url):
    for pwd in ['admin', '123456', 'password']:
        data = {"username": "admin", "password": pwd}
        r = requests.post(url, data=data)
        if "Welcome" in r.text:
            return f"Brute Force (Password: {pwd})"
    return None

def save_pdf(results, output="scan_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="NeithRecon Vulnerability Report", ln=True, align='C')
    for vuln in results:
        pdf.cell(200, 10, txt=f"- {vuln}", ln=True)
    pdf.output(output)

def main():
    print(BANNER)
    url = input("Target URL: ").strip()
    results = []

    try:
        html = requests.get(url).text

        for scan in [scan_sql_injection, scan_xss, lambda x: scan_csrf(html), scan_idor, scan_ssrf, login_bypass, brute_force_test]:
            res = scan(url)
            if res:
                results.append(res)
                print(f"\033[91m[!] Detected: {res} \033[0m")
                print(f"    \033[96m[AI Suggestion] {NeithAI().suggest(res)}\033[0m")

        if results:
            save_pdf(results)
            print("\n\033[92mReport saved as scan_report.pdf\033[0m")
        else:
            print("\033[92m[+] No common vulnerabilities found.\033[0m")

    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m {e}")

if __name__ == "__main__":
    main()