# Documentation for Vulnerability Scanner Script
## Overview
This script is a simple imitation of basic vulnerability scanners. It performs a series of tests on a target web server, such as testing HTTP methods and scanning open ports using Nmap.  
Additionally, it queries the National Vulnerability Database (NVD) for known vulnerabilities related to the services running on the target.

## Dependencies
The following external libraries are required to run the script: 
1. requests: For sending HTTP requests and interacting with the NVD API. 
2. argparse: For parsing command-line arguments. 
3. nmap: For scanning open ports on the target server.

You can install these libraries using pip: 
```bash 
pip install requests argparse python-nmap
```

## Command-Line Arguments
- ip (required): The IP address of the target web server to be scanned.
- --n: Optional. Query the NVD database for known vulnerabilities related to the services found.
- --ns: Optional. Specifies the severity level of vulnerabilities to query from the NVD. Cannot be present without the --n option. Possible values:
    - "low": Low severity.
    - "medium": Medium severity.
    - "high": High severity.
    - "critical": Critical severity (default if not specified).

## Main Functionality
### HTTP Method Testing: 
The script sends several HTTP requests (GET, POST, OPTIONS, HEAD, PUT, DELETE) to the root URL (/) of the target server. It checks the status code of each response and prints the results.

### Port Scanning: 
Using Nmap, the script performs a port scan on the target IP. It identifies open ports and the services running on those ports, including their versions.

### Vulnerability Scanning (Optional): 
If the user specifies the --n flag, the script queries the National Vulnerability Database (NVD) API for known vulnerabilities related to the services discovered during the Nmap scan. The severity of vulnerabilities can be filtered using the --ns flag.

## Detailed Flow
### Argument Parsing: 
The script starts by using the argparse library to parse user input. It expects the IP address of the target web server as a required argument and optional flags to control the NVD querying behavior.

### NVD API Query Setup: 
The NVD API is queried based on the --n and --ns arguments. The severity level is defaulted to "CRITICAL" if not specified, and the query includes the service name and version for each open port.

## Example Usage
### Basic HTTP and Port Scan: 
```bash 
python scanner.py 192.168.1.1
```

### Query NVD for vulnerabilities of a specific service with critical severity: 
```bash 
python scanner.py 192.168.1.1 --n --ns critical
```

### Query NVD for vulnerabilities without filtering by severity: 
```bash 
python scanner.py 192.168.1.1 --n
```

## Example Output
Server: Apache/2.4.18 (Ubuntu)  
HTTP Methods Testing Results:  
GET : 200  
POST : 404  
OPTIONS: 200  
HEAD : 200  
PUT : 405  
DELETE : 405

HOST INFORMATION:  
Host: 192.168.56.2 ()  
State: up  
Protocol: tcp  
Port: 21, State: open, Service: vsftpd, Version: 3.0.3  
Keyword Search: vsftpd 3.0.3  
1 vulnerabilities found.
https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5&startIndex=0&keywordSearch=vsftpd+3.0.3      
Port: 80, State: open, Service: Apache httpd, Version: 2.4.18  
Keyword Search: Apache httpd 2.4.18  
0 vulnerabilities found.  
https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5&startIndex=0&keywordSearch=Apache+httpd+2.4.18
