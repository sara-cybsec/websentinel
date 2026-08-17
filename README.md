# WebSentinel

**Passive Web Security Posture & Surface Analyzer**

WebSentinel is a Python-based passive web security assessment tool that analyzes publicly observable security controls and surface information without attempting exploitation.

It examines HTTP security headers, TLS configuration, cookies, CORS behavior, technology disclosure, HTTPS redirection, and publicly exposed website paths, then generates structured terminal, JSON, and HTML reports.

## Features

### HTTP Security Header Analysis

WebSentinel analyzes several important browser security controls, including:

* Content-Security-Policy (CSP)
* Strict-Transport-Security (HSTS)
* Clickjacking protection
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy
* Legacy X-XSS-Protection behavior

The CSP module goes beyond presence detection and identifies potentially weaker configurations such as:

* Report-Only policies
* `unsafe-inline`
* `unsafe-eval`
* wildcard sources
* missing `object-src`
* missing `base-uri`
* missing `frame-ancestors`

### HTTPS & TLS Analysis

WebSentinel checks:

* HTTP → HTTPS redirection
* TLS certificate validation
* negotiated TLS version
* cipher suite
* certificate expiration
* certificate issuer
* Subject Alternative Name information

### Cookie Security Analysis

Cookies observed in the HTTP response are inspected for:

* `Secure`
* `HttpOnly`
* `SameSite`

These results are treated as configuration observations rather than automatically classified as vulnerabilities because cookie requirements depend on application context.

### CORS Analysis

WebSentinel reviews observable Cross-Origin Resource Sharing configuration, including:

* `Access-Control-Allow-Origin`
* `Access-Control-Allow-Credentials`
* wildcard origin behavior

### Information Disclosure

The analyzer identifies common response headers that may reveal implementation information, including:

* `Server`
* `X-Powered-By`
* `X-AspNet-Version`
* `X-AspNetMvc-Version`

### Passive Surface Discovery

WebSentinel maps publicly exposed website surface information without brute-forcing hidden resources.

It examines:

* Same-domain HTML links
* `robots.txt`
* `sitemap.xml`
* publicly referenced paths
* potentially interesting paths such as login, account, API, upload, dashboard, and authentication endpoints

This module only analyzes information already exposed by the target website.

### Multi-Site Scanning

Multiple websites can be scanned in a single run for quick comparison.

### Reporting

Results can be exported as:

* JSON
* HTML
* Both formats

The HTML report provides a visual security assessment containing findings, scores, TLS information, cookie observations, surface-discovery results, and recommendations.

## Installation

Clone the repository:

```bash
git clone https://github.com/sara-cybsec/websentinel.git
cd websentinel
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it on macOS/Linux:

```bash
source .venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run WebSentinel:

```bash
python main.py
```

Choose a scan mode:

```text
1. Scan one website
2. Scan multiple websites
Q. Quit
```

Enter a target such as:

```text
example.com
```

After the scan, WebSentinel can export the results as JSON, HTML, both formats, or neither.

## Example Output

```text
SECURITY HEADER ANALYZER
Passive Web Security Posture Assessment

HTTP Security Controls
Content-Security-Policy     WARN
Strict-Transport-Security   PASS
Clickjacking Protection     PASS
X-Content-Type-Options      PASS

HTTP → HTTPS Test            PASS
TLS / Certificate Analysis  PASS
CORS Analysis                INFO

Passive Surface Discovery
Unique paths discovered: 18
robots.txt: FOUND
sitemap.xml: FOUND
Interesting paths: 4
```

## Project Structure

```text
websentinel/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
└── reports/
```

Generated reports are excluded from version control by default.

## Technologies

* Python
* Requests
* Beautiful Soup
* lxml
* Rich
* Python SSL / Socket libraries
* Certifi
* HTML / CSS

## What I Learned

Building WebSentinel helped me explore several web security concepts in practice, including:

* HTTP response headers and browser security controls
* Content Security Policy configuration
* HTTPS and HSTS
* TLS certificates and encrypted connections
* Cookie security attributes
* Cross-Origin Resource Sharing
* Technology fingerprinting and information disclosure
* Passive attack-surface discovery
* HTML and XML parsing
* Security finding classification
* The difference between a configuration weakness and a confirmed vulnerability

One of the most important lessons from this project was that security tools need context. A missing header or unusual configuration does not automatically mean a website is vulnerable, so WebSentinel intentionally presents its results as security posture observations rather than confirmed vulnerabilities.

## Scope & Responsible Use

WebSentinel is designed for **passive security analysis**.

It does not perform exploitation, password attacks, directory brute forcing, vulnerability payload injection, or authentication bypass attempts.

Only assess systems you own or are authorized to test, and interpret automated findings within the context of the application being assessed.

## Limitations

WebSentinel is not a replacement for a professional penetration test or full vulnerability scanner.

Its scoring system represents the selected controls evaluated by the tool and should not be interpreted as an overall measurement of a website's security.

## Future Ideas

Potential future improvements include:

* Automated unit tests for detection logic
* Improved CSP parsing
* Additional passive metadata analysis
* Report comparison between scans
* Historical security posture tracking

## Disclaimer

This project was created for educational and defensive security purposes.

The results should be treated as observations that may require further manual validation.