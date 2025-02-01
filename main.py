import requests
import sys
import argparse
import nmap

# Argument parser to handle user input
args = argparse.ArgumentParser(description="This program is a simple script intended to imitate the basic capabilities of vulnerability scanners.")
args.add_argument("ip", type=str, help="The IP of the target web server.")
args.add_argument("--n", action="store_true", dest='nvd', help="If present, queires the NVD database for known vulnerabilities of the services found.")
args.add_argument("--ns", type=str, dest="nvd_sev", choices=["low", "medium", "high", "critical"], help="Severity level included in the NVD API request. By default, it's set to critical.")
parser = args.parse_args()

# Handling NVD API request parameters
if parser.nvd_sev and not parser.nvd:
    sys.exit("Cannot select the --n flag without the --ns flag.")
elif parser.nvd and not parser.nvd_sev:
    nvd_flag = True  # Enable NVD query
    sev = 'CRITICAL' # Default severity level
elif parser.nvd and parser.nvd_sev:
    nvd_flag = True
    sev = parser.nvd_sev.upper() # Convert severity to uppercase to match API requirements
elif not parser.nvd:
    nvd_flag = False

# Construct the URL for testing HTTP methods
url = f"http://{parser.ip}"
try:
    file = {"file" : open("file.txt", 'r')}  # File to be used for certain HTTP requests
except FileNotFoundError:
    print('file.txt for POST request not found!')
    sys.exit()

# NVD API details
NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

# Initialize nmap scanner
scanner = nmap.PortScanner()
scanner.scan(parser.ip)

# Parameters for NVD API request
nvd_params = {
    'resultsPerPage' : 5,  # Limit results to 5 for efficiency
    'startIndex': 0,
}

# Sending different HTTP requests to test allowed methods
get = requests.get(url)
post = requests.post(url, files=file)
options = requests.options(url)
head = requests.head(url)
put = requests.put(url, files=file)
delete = requests.delete(url)

# Storing server response details
responses = {
    'server' : get.headers['Server'],  # Extracting server details from response headers
    'http_mthds' : {
        'GET' : get.status_code,
        'POST' : post.status_code,
        'OPTIONS' : options.status_code,
        'HEAD' : head.status_code,
        'PUT' : put.status_code,
        'DELETE' : delete.status_code
    }
}

# Displaying HTTP method test results
print(f"Server: {responses['server']}\n\
HTTP Methods Testing Results:\n\
GET : {responses['http_mthds']['GET']}\n\
POST : {responses['http_mthds']['POST']}\n\
OPTIONS: {responses['http_mthds']['OPTIONS']}\n\
HEAD : {responses['http_mthds']['HEAD']}\n\
PUT : {responses['http_mthds']['PUT']}\n\
DELETE : {responses['http_mthds']['DELETE']}\n")

# Displays the port information for the target server.
for host in scanner.all_hosts():
    print("HOST INFORMATION:")
    print(f"Host: {host} ({scanner[host].hostname()})")
    print(f"State: {scanner[host].state()}")
    
    # Iterating over detected protocols and ports
    for proto in scanner[host].all_protocols():
        print(f"Protocol: {proto}")
        ports = scanner[host][proto].keys()
        for port in ports:
            print(f"Port: {port}, State: {scanner[host][proto][port]['state']}, \
Service: {scanner[host][proto][port]['product']}, Version: {scanner[host][proto][port]['version']}")
            
            # If NVD flag is set, query the API for known vulnerabilities
            if nvd_flag:
                try:
                    nvd_params['keywordSearch'] = f"{scanner[host][proto][port]['product']} {scanner[host][proto][port]['version']}"
                    print(f"Keyword Search: {nvd_params['keywordSearch']}")
                    vulns = requests.get(NVD_URL, params=nvd_params)
                    print(f"{vulns.json()['totalResults']} vulnerabilities found.")  # Display number of vulnerabilities found
                    print(vulns.url)  # Print the API request URL for debugging
                except requests.exceptions.RequestException:
                    print(vulns.status_code)
                    print(vulns.headers)