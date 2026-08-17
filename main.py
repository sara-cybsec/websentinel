import json
import requests
import socket
import ssl
import certifi

from bs4 import BeautifulSoup
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import (
    urlparse,
    urljoin,
    urldefrag
)
from html import escape

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text


# =========================================================
# CONFIG
# =========================================================

TIMEOUT = 10
REPORTS_FOLDER = Path("reports")

USER_AGENT = "SecurityHeaderAnalyzer/6.0"

console = Console()

session = requests.Session()
session.trust_env = False


# =========================================================
# URL HELPERS
# =========================================================

def normalize_url(url):
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def build_http_url(url):
    parsed = urlparse(
        normalize_url(url)
    )

    path = parsed.path or "/"

    return (
        "http://"
        + parsed.netloc
        + path
    )


def get_hostname(url):
    parsed = urlparse(
        normalize_url(url)
    )

    return parsed.hostname


def same_domain(url_a, url_b):
    parsed_a = urlparse(url_a)
    parsed_b = urlparse(url_b)

    host_a = (
        parsed_a.hostname
        or ""
    ).lower()

    host_b = (
        parsed_b.hostname
        or ""
    ).lower()

    return host_a == host_b


def clean_url(url):
    url, _ = urldefrag(url)

    return url


def path_from_url(url):
    parsed = urlparse(url)

    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    return path


# =========================================================
# CSP ANALYSIS
# =========================================================

def check_csp(headers):

    enforced = headers.get(
        "Content-Security-Policy"
    )

    report_only = headers.get(
        "Content-Security-Policy-Report-Only"
    )

    if not enforced:

        if report_only:
            return {
                "name": "Content-Security-Policy",
                "status": "WARN",
                "score": 6,
                "max_score": 20,
                "value": report_only,
                "message": (
                    "A CSP exists only in Report-Only mode."
                ),
                "recommendation": (
                    "After testing, consider deploying an "
                    "enforced Content-Security-Policy."
                ),
                "details": [
                    {
                        "severity": "MEDIUM",
                        "finding": "CSP is not enforced"
                    }
                ]
            }

        return {
            "name": "Content-Security-Policy",
            "status": "FAIL",
            "score": 0,
            "max_score": 20,
            "value": None,
            "message": (
                "No enforced Content-Security-Policy "
                "was detected."
            ),
            "recommendation": (
                "Consider implementing an enforced CSP "
                "for HTML responses."
            ),
            "details": [
                {
                    "severity": "MEDIUM",
                    "finding": (
                        "Content-Security-Policy is missing"
                    )
                }
            ]
        }

    policy = enforced.lower()

    findings = []
    score = 20

    if "'unsafe-inline'" in policy:
        findings.append({
            "severity": "MEDIUM",
            "finding": "'unsafe-inline' is allowed"
        })

        score -= 5

    if "'unsafe-eval'" in policy:
        findings.append({
            "severity": "MEDIUM",
            "finding": "'unsafe-eval' is allowed"
        })

        score -= 5

    directives = [
        item.strip()
        for item in policy.split(";")
        if item.strip()
    ]

    for directive in directives:

        parts = directive.split()

        if (
            len(parts) > 1
            and "*" in parts[1:]
        ):
            findings.append({
                "severity": "MEDIUM",
                "finding": (
                    f"Wildcard source detected "
                    f"in {parts[0]}"
                )
            })

            score -= 3
            break

    if "object-src" not in policy:
        findings.append({
            "severity": "LOW",
            "finding": (
                "object-src directive is missing"
            )
        })

        score -= 2

    if "base-uri" not in policy:
        findings.append({
            "severity": "LOW",
            "finding": (
                "base-uri directive is missing"
            )
        })

        score -= 2

    if "frame-ancestors" not in policy:
        findings.append({
            "severity": "INFO",
            "finding": (
                "frame-ancestors directive was not detected"
            )
        })

    if (
        "script-src" not in policy
        and "default-src" not in policy
    ):
        findings.append({
            "severity": "MEDIUM",
            "finding": (
                "No script-src or default-src directive "
                "was detected"
            )
        })

        score -= 4

    score = max(
        score,
        0
    )

    if findings:

        return {
            "name": "Content-Security-Policy",
            "status": "WARN",
            "score": score,
            "max_score": 20,
            "value": enforced,
            "message": (
                f"An enforced CSP is present, but "
                f"{len(findings)} potential "
                f"configuration issue(s) were found."
            ),
            "recommendation": (
                "Review the CSP and consider stricter "
                "source restrictions, nonces, hashes, "
                "and suitable defensive directives."
            ),
            "details": findings
        }

    return {
        "name": "Content-Security-Policy",
        "status": "PASS",
        "score": 20,
        "max_score": 20,
        "value": enforced,
        "message": (
            "An enforced CSP is present and this "
            "analyzer found no obvious weaknesses."
        ),
        "recommendation": None,
        "details": []
    }


# =========================================================
# HSTS
# =========================================================

def check_hsts(headers, final_url):

    value = headers.get(
        "Strict-Transport-Security"
    )

    if not final_url.startswith("https://"):

        return {
            "name": "Strict-Transport-Security",
            "status": "WARN",
            "score": 0,
            "max_score": 20,
            "value": value,
            "message": (
                "The final response was not HTTPS."
            ),
            "recommendation": (
                "Serve the site over HTTPS before "
                "deploying HSTS."
            ),
            "details": []
        }

    if not value:

        return {
            "name": "Strict-Transport-Security",
            "status": "FAIL",
            "score": 0,
            "max_score": 20,
            "value": None,
            "message": (
                "HSTS was not detected."
            ),
            "recommendation": (
                "Consider enabling HSTS on HTTPS responses."
            ),
            "details": []
        }

    lower_value = value.lower()

    if "max-age=" not in lower_value:

        return {
            "name": "Strict-Transport-Security",
            "status": "WARN",
            "score": 5,
            "max_score": 20,
            "value": value,
            "message": (
                "HSTS exists but max-age was not detected."
            ),
            "recommendation": (
                "Add a valid max-age directive."
            ),
            "details": []
        }

    try:

        max_age = int(
            lower_value
            .split("max-age=")[1]
            .split(";")[0]
            .strip()
        )

    except (ValueError, IndexError):

        return {
            "name": "Strict-Transport-Security",
            "status": "WARN",
            "score": 5,
            "max_score": 20,
            "value": value,
            "message": (
                "HSTS exists but max-age could not "
                "be parsed."
            ),
            "recommendation": (
                "Ensure max-age contains a valid integer."
            ),
            "details": []
        }

    if max_age >= 31536000:

        return {
            "name": "Strict-Transport-Security",
            "status": "PASS",
            "score": 20,
            "max_score": 20,
            "value": value,
            "message": (
                "HSTS is enabled with a max-age "
                "of at least one year."
            ),
            "recommendation": None,
            "details": []
        }

    return {
        "name": "Strict-Transport-Security",
        "status": "WARN",
        "score": 10,
        "max_score": 20,
        "value": value,
        "message": (
            "HSTS is enabled, but max-age is "
            "shorter than one year."
        ),
        "recommendation": (
            "Consider a longer max-age if appropriate."
        ),
        "details": []
    }


# =========================================================
# CLICKJACKING
# =========================================================

def check_clickjacking(headers):

    xfo = headers.get(
        "X-Frame-Options"
    )

    csp = headers.get(
        "Content-Security-Policy",
        ""
    )

    has_frame_ancestors = (
        "frame-ancestors"
        in csp.lower()
    )

    if has_frame_ancestors:

        return {
            "name": "Clickjacking Protection",
            "status": "PASS",
            "score": 15,
            "max_score": 15,
            "value": "CSP frame-ancestors",
            "message": (
                "CSP frame-ancestors was detected."
            ),
            "recommendation": None,
            "details": []
        }

    if xfo:

        normalized = (
            xfo.upper()
            .strip()
        )

        if normalized in {
            "DENY",
            "SAMEORIGIN"
        }:

            return {
                "name": "Clickjacking Protection",
                "status": "PASS",
                "score": 15,
                "max_score": 15,
                "value": xfo,
                "message": (
                    "X-Frame-Options is configured."
                ),
                "recommendation": None,
                "details": []
            }

        return {
            "name": "Clickjacking Protection",
            "status": "WARN",
            "score": 6,
            "max_score": 15,
            "value": xfo,
            "message": (
                "An unusual X-Frame-Options "
                "value was detected."
            ),
            "recommendation": (
                "Prefer CSP frame-ancestors or "
                "a supported X-Frame-Options value."
            ),
            "details": []
        }

    return {
        "name": "Clickjacking Protection",
        "status": "FAIL",
        "score": 0,
        "max_score": 15,
        "value": None,
        "message": (
            "Neither CSP frame-ancestors nor "
            "X-Frame-Options was detected."
        ),
        "recommendation": (
            "Consider configuring CSP frame-ancestors."
        ),
        "details": []
    }


# =========================================================
# X-CONTENT-TYPE-OPTIONS
# =========================================================

def check_content_type_options(headers):

    value = headers.get(
        "X-Content-Type-Options"
    )

    if not value:

        return {
            "name": "X-Content-Type-Options",
            "status": "FAIL",
            "score": 0,
            "max_score": 15,
            "value": None,
            "message": (
                "X-Content-Type-Options is missing."
            ),
            "recommendation": (
                "Set X-Content-Type-Options to nosniff."
            ),
            "details": []
        }

    if (
        value.lower()
        .strip()
        == "nosniff"
    ):

        return {
            "name": "X-Content-Type-Options",
            "status": "PASS",
            "score": 15,
            "max_score": 15,
            "value": value,
            "message": (
                "MIME sniffing protection is enabled."
            ),
            "recommendation": None,
            "details": []
        }

    return {
        "name": "X-Content-Type-Options",
        "status": "WARN",
        "score": 5,
        "max_score": 15,
        "value": value,
        "message": (
            "The expected nosniff value was not found."
        ),
        "recommendation": (
            "Use nosniff."
        ),
        "details": []
    }


# =========================================================
# REFERRER POLICY
# =========================================================

def check_referrer_policy(headers):

    value = headers.get(
        "Referrer-Policy"
    )

    if not value:

        return {
            "name": "Referrer-Policy",
            "status": "FAIL",
            "score": 0,
            "max_score": 10,
            "value": None,
            "message": (
                "Referrer-Policy is missing."
            ),
            "recommendation": (
                "Consider explicitly configuring "
                "a restrictive Referrer-Policy."
            ),
            "details": []
        }

    preferred = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin"
    }

    normalized = (
        value.lower()
        .strip()
    )

    if normalized in preferred:

        return {
            "name": "Referrer-Policy",
            "status": "PASS",
            "score": 10,
            "max_score": 10,
            "value": value,
            "message": (
                "A restrictive referrer policy "
                "is configured."
            ),
            "recommendation": None,
            "details": []
        }

    return {
        "name": "Referrer-Policy",
        "status": "WARN",
        "score": 5,
        "max_score": 10,
        "value": value,
        "message": (
            "Referrer-Policy exists, but this analyzer "
            "considers it less restrictive."
        ),
        "recommendation": (
            "Review whether a more restrictive "
            "policy is suitable."
        ),
        "details": []
    }


# =========================================================
# PERMISSIONS POLICY
# =========================================================

def check_permissions_policy(headers):

    value = headers.get(
        "Permissions-Policy"
    )

    if not value:

        return {
            "name": "Permissions-Policy",
            "status": "FAIL",
            "score": 0,
            "max_score": 10,
            "value": None,
            "message": (
                "Permissions-Policy is missing."
            ),
            "recommendation": (
                "Consider restricting unnecessary "
                "browser capabilities."
            ),
            "details": []
        }

    return {
        "name": "Permissions-Policy",
        "status": "PASS",
        "score": 10,
        "max_score": 10,
        "value": value,
        "message": (
            "Permissions-Policy is present."
        ),
        "recommendation": None,
        "details": []
    }


# =========================================================
# X-XSS-PROTECTION
# =========================================================

def check_x_xss_protection(headers):

    value = headers.get(
        "X-XSS-Protection"
    )

    if value is None:

        return {
            "name": "X-XSS-Protection",
            "status": "INFO",
            "score": 0,
            "max_score": 0,
            "value": None,
            "message": (
                "Legacy XSS filter header is not present."
            ),
            "recommendation": None,
            "details": []
        }

    if value.strip() == "0":

        return {
            "name": "X-XSS-Protection",
            "status": "INFO",
            "score": 0,
            "max_score": 0,
            "value": value,
            "message": (
                "Legacy browser XSS filtering "
                "is explicitly disabled."
            ),
            "recommendation": None,
            "details": []
        }

    return {
        "name": "X-XSS-Protection",
        "status": "WARN",
        "score": 0,
        "max_score": 0,
        "value": value,
        "message": (
            "Legacy X-XSS-Protection behavior "
            "is enabled."
        ),
        "recommendation": (
            "Prioritize CSP instead of legacy "
            "browser XSS filtering."
        ),
        "details": []
    }


# =========================================================
# INFORMATION DISCLOSURE
# =========================================================

def analyze_information_disclosure(headers):

    watched_headers = {
        "Server": "Web server information",
        "X-Powered-By": "Application technology",
        "X-AspNet-Version": ".NET version",
        "X-AspNetMvc-Version": (
            "ASP.NET MVC version"
        )
    }

    findings = []

    for header, description in (
        watched_headers.items()
    ):

        value = headers.get(
            header
        )

        if value:

            severity = "LOW"

            if any(
                char.isdigit()
                for char in value
            ):
                severity = "MEDIUM"

            findings.append({
                "severity": severity,
                "header": header,
                "value": value,
                "description": description
            })

    if findings:

        return {
            "status": "WARN",
            "message": (
                f"{len(findings)} technology "
                f"information disclosure finding(s) "
                f"detected."
            ),
            "findings": findings
        }

    return {
        "status": "PASS",
        "message": (
            "No common technology disclosure "
            "headers were detected."
        ),
        "findings": []
    }


# =========================================================
# CORS ANALYSIS
# =========================================================

def analyze_cors(headers):

    origin = headers.get(
        "Access-Control-Allow-Origin"
    )

    credentials = headers.get(
        "Access-Control-Allow-Credentials"
    )

    if origin is None:

        return {
            "status": "INFO",
            "origin": None,
            "credentials": credentials,
            "message": (
                "No Access-Control-Allow-Origin "
                "header was observed."
            ),
            "findings": []
        }

    findings = []

    if origin.strip() == "*":

        findings.append({
            "severity": "INFO",
            "finding": (
                "Wildcard CORS origin (*) detected"
            )
        })

        if (
            credentials
            and credentials.lower().strip()
            == "true"
        ):

            findings.append({
                "severity": "MEDIUM",
                "finding": (
                    "Wildcard origin is combined "
                    "with credential allowance"
                )
            })

    else:

        findings.append({
            "severity": "INFO",
            "finding": (
                f"Allowed origin: {origin}"
            )
        })

    status = "INFO"

    if any(
        item["severity"] == "MEDIUM"
        for item in findings
    ):
        status = "WARN"

    return {
        "status": status,
        "origin": origin,
        "credentials": credentials,
        "message": (
            "CORS configuration was detected "
            "and reviewed."
        ),
        "findings": findings
    }


# =========================================================
# HTTP -> HTTPS REDIRECT
# =========================================================

def test_https_redirect(url):

    http_url = build_http_url(
        url
    )

    try:

        response = session.get(
            http_url,
            timeout=TIMEOUT,
            allow_redirects=False,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        location = response.headers.get(
            "Location"
        )

        if (
            response.status_code
            in {
                301,
                302,
                303,
                307,
                308
            }
            and location
        ):

            target = urljoin(
                http_url,
                location
            )

            if target.startswith(
                "https://"
            ):

                return {
                    "status": "PASS",
                    "http_url": http_url,
                    "status_code": (
                        response.status_code
                    ),
                    "location": target,
                    "message": (
                        "HTTP redirects to HTTPS."
                    )
                }

            return {
                "status": "WARN",
                "http_url": http_url,
                "status_code": (
                    response.status_code
                ),
                "location": target,
                "message": (
                    "HTTP redirects, but the first "
                    "target is not HTTPS."
                )
            }

        return {
            "status": "FAIL",
            "http_url": http_url,
            "status_code": (
                response.status_code
            ),
            "location": location,
            "message": (
                "The HTTP endpoint did not redirect "
                "to HTTPS."
            )
        }

    except requests.RequestException as error:

        return {
            "status": "INFO",
            "http_url": http_url,
            "status_code": None,
            "location": None,
            "message": (
                "The HTTP endpoint could not "
                f"be tested: {error}"
            )
        }


# =========================================================
# COOKIE ANALYSIS
# =========================================================

def get_set_cookie_headers(response):

    try:

        return (
            response.raw.headers
            .getlist(
                "Set-Cookie"
            )
        )

    except AttributeError:

        value = response.headers.get(
            "Set-Cookie"
        )

        return (
            [value]
            if value
            else []
        )


def analyze_cookie(cookie_header):

    parts = [
        part.strip()
        for part in (
            cookie_header.split(";")
        )
    ]

    first = parts[0]

    if "=" in first:

        name = first.split(
            "=",
            1
        )[0]

    else:

        name = "Unknown"

    lower_parts = [
        part.lower()
        for part in parts[1:]
    ]

    secure = (
        "secure"
        in lower_parts
    )

    httponly = (
        "httponly"
        in lower_parts
    )

    samesite = None

    for part in parts[1:]:

        if (
            part.lower()
            .startswith(
                "samesite="
            )
        ):

            samesite = (
                part
                .split(
                    "=",
                    1
                )[1]
                .strip()
            )

    findings = []

    findings.append({
        "status": (
            "PASS"
            if secure
            else "WARN"
        ),
        "message": (
            "Secure attribute is present."
            if secure
            else "Secure attribute is missing."
        )
    })

    findings.append({
        "status": (
            "PASS"
            if httponly
            else "WARN"
        ),
        "message": (
            "HttpOnly attribute is present."
            if httponly
            else "HttpOnly attribute is missing."
        )
    })

    if samesite:

        normalized = (
            samesite.lower()
        )

        if normalized in {
            "strict",
            "lax"
        }:

            findings.append({
                "status": "PASS",
                "message": (
                    f"SameSite={samesite}"
                )
            })

        elif normalized == "none":

            findings.append({
                "status": (
                    "INFO"
                    if secure
                    else "FAIL"
                ),
                "message": (
                    "SameSite=None with Secure."
                    if secure
                    else (
                        "SameSite=None without Secure."
                    )
                )
            })

        else:

            findings.append({
                "status": "WARN",
                "message": (
                    f"Unrecognized SameSite "
                    f"value: {samesite}"
                )
            })

    else:

        findings.append({
            "status": "WARN",
            "message": (
                "SameSite attribute is missing."
            )
        })

    return {
        "name": name,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite,
        "findings": findings
    }


def analyze_cookies(response):

    return [
        analyze_cookie(cookie)
        for cookie in (
            get_set_cookie_headers(
                response
            )
        )
    ]


# =========================================================
# TLS ANALYSIS
# =========================================================

def analyze_tls(url):

    hostname = get_hostname(
        url
    )

    if not hostname:

        return {
            "status": "FAIL",
            "message": (
                "Could not determine hostname."
            )
        }

    context = ssl.create_default_context(
        cafile=certifi.where()
    )

    try:

        with socket.create_connection(
            (
                hostname,
                443
            ),
            timeout=TIMEOUT
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname
            ) as tls_socket:

                certificate = (
                    tls_socket
                    .getpeercert()
                )

                tls_version = (
                    tls_socket.version()
                )

                cipher_info = (
                    tls_socket.cipher()
                )

        expires_text = (
            certificate.get(
                "notAfter"
            )
        )

        expires_at = None
        days_remaining = None

        if expires_text:

            expires_at = (
                datetime.strptime(
                    expires_text,
                    "%b %d %H:%M:%S %Y %Z"
                )
                .replace(
                    tzinfo=timezone.utc
                )
            )

            now = datetime.now(
                timezone.utc
            )

            days_remaining = (
                expires_at - now
            ).days

        issuer = {}

        for item in certificate.get(
            "issuer",
            []
        ):

            for key, value in item:
                issuer[key] = value

        subject = {}

        for item in certificate.get(
            "subject",
            []
        ):

            for key, value in item:
                subject[key] = value

        san_entries = (
            certificate.get(
                "subjectAltName",
                []
            )
        )

        status = "PASS"
        findings = []

        if days_remaining is not None:

            if days_remaining < 0:

                status = "FAIL"

                findings.append({
                    "severity": "HIGH",
                    "finding": (
                        "TLS certificate appears expired"
                    )
                })

            elif days_remaining < 30:

                status = "WARN"

                findings.append({
                    "severity": "MEDIUM",
                    "finding": (
                        "TLS certificate expires "
                        "within 30 days"
                    )
                })

        return {
            "status": status,
            "message": (
                "TLS connection and certificate "
                "inspection completed."
            ),
            "hostname": hostname,
            "tls_version": tls_version,
            "cipher": (
                cipher_info[0]
                if cipher_info
                else None
            ),
            "certificate_subject": subject,
            "certificate_issuer": issuer,
            "expires_at": (
                expires_at.isoformat()
                if expires_at
                else None
            ),
            "days_remaining": (
                days_remaining
            ),
            "san_count": (
                len(san_entries)
            ),
            "findings": findings
        }

    except ssl.SSLCertVerificationError as error:

        return {
            "status": "FAIL",
            "message": (
                "TLS certificate verification "
                f"failed: {error}"
            ),
            "hostname": hostname
        }

    except (
        socket.timeout,
        socket.error,
        ssl.SSLError
    ) as error:

        return {
            "status": "FAIL",
            "message": (
                f"TLS connection failed: {error}"
            ),
            "hostname": hostname
        }


# =========================================================
# PASSIVE SURFACE DISCOVERY
# =========================================================

INTERESTING_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "account",
    "profile",
    "settings",
    "admin",
    "dashboard",
    "api",
    "auth",
    "oauth",
    "upload",
    "uploads",
    "download",
    "search",
    "register",
    "signup",
    "user",
    "users",
    "developer",
    "developers",
    "console",
    "portal"
}


def classify_interesting_path(path):

    lowered = path.lower()

    matched = []

    for keyword in INTERESTING_KEYWORDS:

        if keyword in lowered:
            matched.append(
                keyword
            )

    return sorted(
        set(
            matched
        )
    )


def discover_html_links(
    response
):

    content_type = (
        response.headers.get(
            "Content-Type",
            ""
        )
        .lower()
    )

    if "html" not in content_type:

        return []

    soup = BeautifulSoup(
        response.text,
        "html.parser"
    )

    links = set()

    for tag in soup.find_all(
        ["a", "form"]
    ):

        value = (
            tag.get("href")
            or tag.get("action")
        )

        if not value:
            continue

        value = value.strip()

        if value.startswith(
            (
                "mailto:",
                "tel:",
                "javascript:",
                "#"
            )
        ):
            continue

        absolute = clean_url(
            urljoin(
                response.url,
                value
            )
        )

        if same_domain(
            response.url,
            absolute
        ):
            links.add(
                absolute
            )

    return sorted(
        links
    )


def discover_robots(
    base_url
):

    parsed = urlparse(
        base_url
    )

    robots_url = (
        f"{parsed.scheme}://"
        f"{parsed.netloc}/robots.txt"
    )

    result = {
        "url": robots_url,
        "found": False,
        "status_code": None,
        "paths": []
    }

    try:

        response = session.get(
            robots_url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        result[
            "status_code"
        ] = response.status_code

        if (
            response.status_code == 200
            and "text" in (
                response.headers.get(
                    "Content-Type",
                    ""
                )
                .lower()
            )
        ):

            result[
                "found"
            ] = True

            paths = set()

            for line in (
                response.text
                .splitlines()
            ):

                line = (
                    line.strip()
                )

                if not line:
                    continue

                lower_line = (
                    line.lower()
                )

                if (
                    lower_line.startswith(
                        "allow:"
                    )
                    or lower_line.startswith(
                        "disallow:"
                    )
                ):

                    value = (
                        line.split(
                            ":",
                            1
                        )[1]
                        .strip()
                    )

                    if value:
                        paths.add(
                            value
                        )

            result[
                "paths"
            ] = sorted(
                paths
            )

    except requests.RequestException:
        pass

    return result


def discover_sitemap(
    base_url
):

    parsed = urlparse(
        base_url
    )

    sitemap_url = (
        f"{parsed.scheme}://"
        f"{parsed.netloc}/sitemap.xml"
    )

    result = {
        "url": sitemap_url,
        "found": False,
        "status_code": None,
        "urls": []
    }

    try:

        response = session.get(
            sitemap_url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        result[
            "status_code"
        ] = response.status_code

        if response.status_code == 200:

            soup = BeautifulSoup(
                response.text,
                "xml"
            )

            urls = set()

            for loc in soup.find_all(
                "loc"
            ):

                if not loc.text:
                    continue

                discovered = (
                    loc.text.strip()
                )

                if same_domain(
                    base_url,
                    discovered
                ):
                    urls.add(
                        clean_url(
                            discovered
                        )
                    )

            if urls:

                result[
                    "found"
                ] = True

                result[
                    "urls"
                ] = sorted(
                    urls
                )

    except requests.RequestException:
        pass

    return result


def analyze_surface(
    response
):

    html_links = (
        discover_html_links(
            response
        )
    )

    robots = (
        discover_robots(
            response.url
        )
    )

    sitemap = (
        discover_sitemap(
            response.url
        )
    )

    all_paths = set()

    for link in html_links:

        all_paths.add(
            path_from_url(
                link
            )
        )

    for path in robots[
        "paths"
    ]:

        all_paths.add(
            path
        )

    for link in sitemap[
        "urls"
    ]:

        all_paths.add(
            path_from_url(
                link
            )
        )

    interesting = []

    for path in sorted(
        all_paths
    ):

        keywords = (
            classify_interesting_path(
                path
            )
        )

        if keywords:

            interesting.append({
                "path": path,
                "keywords": keywords
            })

    return {
        "html_link_count": (
            len(
                html_links
            )
        ),
        "html_links": (
            html_links
        ),
        "robots": robots,
        "sitemap": sitemap,
        "total_unique_paths": (
            len(
                all_paths
            )
        ),
        "paths": sorted(
            all_paths
        ),
        "interesting_paths": (
            interesting
        )
    }


# =========================================================
# HEADER ANALYSIS
# =========================================================

def analyze_headers(
    headers,
    final_url
):

    checks = [
        check_csp(
            headers
        ),
        check_hsts(
            headers,
            final_url
        ),
        check_clickjacking(
            headers
        ),
        check_content_type_options(
            headers
        ),
        check_referrer_policy(
            headers
        ),
        check_permissions_policy(
            headers
        ),
        check_x_xss_protection(
            headers
        )
    ]

    score = sum(
        check["score"]
        for check in checks
    )

    maximum = sum(
        check["max_score"]
        for check in checks
    )

    return (
        score,
        maximum,
        checks
    )


def get_posture(
    score,
    maximum
):

    if maximum == 0:
        return "UNKNOWN"

    percentage = (
        score
        / maximum
        * 100
    )

    if percentage >= 80:
        return "STRONG"

    if percentage >= 50:
        return "NEEDS REVIEW"

    return "NEEDS IMPROVEMENT"


# =========================================================
# SCAN URL
# =========================================================

def scan_url(url):

    requested_url = (
        normalize_url(
            url
        )
    )

    try:

        response = session.get(
            requested_url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        (
            score,
            maximum,
            checks
        ) = analyze_headers(
            response.headers,
            response.url
        )

        percentage = round(
            score
            / maximum
            * 100
        )

        return {
            "success": True,
            "requested_url": (
                requested_url
            ),
            "final_url": (
                response.url
            ),
            "status_code": (
                response.status_code
            ),
            "content_type": (
                response.headers.get(
                    "Content-Type"
                )
            ),
            "redirect_count": (
                len(
                    response.history
                )
            ),
            "score": score,
            "maximum_score": maximum,
            "percentage": percentage,
            "posture": (
                get_posture(
                    score,
                    maximum
                )
            ),
            "checks": checks,
            "https_redirect": (
                test_https_redirect(
                    requested_url
                )
            ),
            "cookies": (
                analyze_cookies(
                    response
                )
            ),
            "information_disclosure": (
                analyze_information_disclosure(
                    response.headers
                )
            ),
            "cors": (
                analyze_cors(
                    response.headers
                )
            ),
            "tls": (
                analyze_tls(
                    response.url
                )
            ),
            "surface_discovery": (
                analyze_surface(
                    response
                )
            ),
            "scanned_at": (
                datetime.now()
                .isoformat(
                    timespec="seconds"
                )
            )
        }

    except requests.exceptions.SSLError as error:

        return {
            "success": False,
            "requested_url": requested_url,
            "error": (
                f"TLS/SSL error: {error}"
            )
        }

    except requests.exceptions.Timeout:

        return {
            "success": False,
            "requested_url": requested_url,
            "error": (
                "The HTTP request timed out."
            )
        }

    except requests.exceptions.ConnectionError:

        return {
            "success": False,
            "requested_url": requested_url,
            "error": (
                "Could not connect to the server."
            )
        }

    except requests.RequestException as error:

        return {
            "success": False,
            "requested_url": requested_url,
            "error": str(error)
        }


# =========================================================
# TERMINAL STYLES
# =========================================================

def status_style(status):

    styles = {
        "PASS": "bold green",
        "WARN": "bold yellow",
        "FAIL": "bold red",
        "INFO": "bold cyan"
    }

    return styles.get(
        status,
        "white"
    )


def posture_style(posture):

    styles = {
        "STRONG": "green",
        "NEEDS REVIEW": "yellow",
        "NEEDS IMPROVEMENT": "red",
        "UNKNOWN": "white"
    }

    return styles.get(
        posture,
        "white"
    )


# =========================================================
# HEADER DISPLAY
# =========================================================

def show_header_analysis(report):

    table = Table(
        title="HTTP Security Controls"
    )

    table.add_column(
        "Status",
        justify="center"
    )

    table.add_column(
        "Control",
        style="bold"
    )

    table.add_column(
        "Finding"
    )

    table.add_column(
        "Score",
        justify="right"
    )

    for check in report[
        "checks"
    ]:

        score_text = (
            "-"
            if check[
                "max_score"
            ] == 0
            else (
                f"{check['score']}/"
                f"{check['max_score']}"
            )
        )

        table.add_row(
            Text(
                check["status"],
                style=status_style(
                    check["status"]
                )
            ),
            check["name"],
            check["message"],
            score_text
        )

    console.print(
        table
    )

    detailed = []

    for check in report[
        "checks"
    ]:

        for detail in check.get(
            "details",
            []
        ):

            detailed.append({
                "control": (
                    check["name"]
                ),
                "severity": (
                    detail["severity"]
                ),
                "finding": (
                    detail["finding"]
                )
            })

    if detailed:

        console.print(
            "\n[bold]"
            "Detailed Findings"
            "[/bold]"
        )

        table = Table()

        table.add_column(
            "Severity"
        )

        table.add_column(
            "Control"
        )

        table.add_column(
            "Finding"
        )

        severity_styles = {
            "HIGH": "bold red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim"
        }

        for item in detailed:

            table.add_row(
                Text(
                    item["severity"],
                    style=(
                        severity_styles
                        .get(
                            item[
                                "severity"
                            ],
                            "white"
                        )
                    )
                ),
                item["control"],
                item["finding"]
            )

        console.print(
            table
        )


# =========================================================
# TRANSPORT DISPLAY
# =========================================================

def show_https_redirect(test):

    console.print(
        "\n[bold]"
        "HTTP → HTTPS Test"
        "[/bold]"
    )

    console.print(
        Text(
            (
                f"[{test['status']}] "
                f"{test['message']}"
            ),
            style=status_style(
                test["status"]
            )
        )
    )

    if test[
        "location"
    ]:

        console.print(
            f"Redirect target: "
            f"{test['location']}"
        )


# =========================================================
# TLS DISPLAY
# =========================================================

def show_tls(tls):

    console.print(
        "\n[bold]"
        "TLS / Certificate Analysis"
        "[/bold]"
    )

    console.print(
        Text(
            (
                f"[{tls['status']}] "
                f"{tls['message']}"
            ),
            style=status_style(
                tls["status"]
            )
        )
    )

    if tls.get(
        "tls_version"
    ):

        table = Table(
            show_header=False,
            box=None
        )

        table.add_row(
            "TLS Version",
            str(
                tls.get(
                    "tls_version"
                )
            )
        )

        table.add_row(
            "Cipher",
            str(
                tls.get(
                    "cipher"
                )
            )
        )

        table.add_row(
            "Certificate Expires",
            str(
                tls.get(
                    "expires_at"
                )
            )
        )

        table.add_row(
            "Days Remaining",
            str(
                tls.get(
                    "days_remaining"
                )
            )
        )

        issuer = tls.get(
            "certificate_issuer",
            {}
        )

        table.add_row(
            "Issuer",
            str(
                issuer.get(
                    "organizationName",
                    issuer.get(
                        "commonName",
                        "Unknown"
                    )
                )
            )
        )

        table.add_row(
            "SAN Entries",
            str(
                tls.get(
                    "san_count"
                )
            )
        )

        console.print(
            table
        )


# =========================================================
# INFORMATION DISCLOSURE DISPLAY
# =========================================================

def show_information_disclosure(
    analysis
):

    console.print(
        "\n[bold]"
        "Information Disclosure"
        "[/bold]"
    )

    console.print(
        Text(
            (
                f"[{analysis['status']}] "
                f"{analysis['message']}"
            ),
            style=status_style(
                analysis["status"]
            )
        )
    )

    if analysis[
        "findings"
    ]:

        table = Table()

        table.add_column(
            "Severity"
        )

        table.add_column(
            "Header"
        )

        table.add_column(
            "Value"
        )

        for finding in analysis[
            "findings"
        ]:

            table.add_row(
                finding[
                    "severity"
                ],
                finding[
                    "header"
                ],
                finding[
                    "value"
                ]
            )

        console.print(
            table
        )


# =========================================================
# CORS DISPLAY
# =========================================================

def show_cors(cors):

    console.print(
        "\n[bold]"
        "CORS Analysis"
        "[/bold]"
    )

    console.print(
        Text(
            (
                f"[{cors['status']}] "
                f"{cors['message']}"
            ),
            style=status_style(
                cors["status"]
            )
        )
    )

    if cors[
        "origin"
    ]:

        console.print(
            f"Allowed Origin: "
            f"{cors['origin']}"
        )

    if cors[
        "credentials"
    ]:

        console.print(
            f"Credentials: "
            f"{cors['credentials']}"
        )

    for finding in cors[
        "findings"
    ]:

        console.print(
            f"- "
            f"{finding['severity']}: "
            f"{finding['finding']}"
        )


# =========================================================
# COOKIE DISPLAY
# =========================================================

def show_cookie_analysis(
    cookies
):

    console.print(
        "\n[bold]"
        "Cookie Security Analysis"
        "[/bold]"
    )

    if not cookies:

        console.print(
            "[cyan]"
            "No Set-Cookie headers were observed "
            "in this response."
            "[/cyan]"
        )

        return

    table = Table()

    table.add_column(
        "Cookie"
    )

    table.add_column(
        "Secure"
    )

    table.add_column(
        "HttpOnly"
    )

    table.add_column(
        "SameSite"
    )

    for cookie in cookies:

        table.add_row(
            cookie[
                "name"
            ],
            (
                "YES"
                if cookie[
                    "secure"
                ]
                else "NO"
            ),
            (
                "YES"
                if cookie[
                    "httponly"
                ]
                else "NO"
            ),
            (
                cookie[
                    "samesite"
                ]
                or "Missing"
            )
        )

    console.print(
        table
    )


# =========================================================
# SURFACE DISCOVERY DISPLAY
# =========================================================

def show_surface_discovery(
    surface
):

    console.print(
        "\n[bold]"
        "Passive Surface Discovery"
        "[/bold]"
    )

    summary = Table(
        show_header=False,
        box=None
    )

    summary.add_row(
        "Same-domain HTML links",
        str(
            surface[
                "html_link_count"
            ]
        )
    )

    summary.add_row(
        "Unique paths discovered",
        str(
            surface[
                "total_unique_paths"
            ]
        )
    )

    summary.add_row(
        "robots.txt",
        (
            "FOUND"
            if surface[
                "robots"
            ][
                "found"
            ]
            else "Not found"
        )
    )

    summary.add_row(
        "sitemap.xml",
        (
            "FOUND"
            if surface[
                "sitemap"
            ][
                "found"
            ]
            else "Not found"
        )
    )

    summary.add_row(
        "Interesting paths",
        str(
            len(
                surface[
                    "interesting_paths"
                ]
            )
        )
    )

    console.print(
        summary
    )

    interesting = surface[
        "interesting_paths"
    ]

    if interesting:

        console.print(
            "\n[bold]"
            "Interesting Public Paths"
            "[/bold]"
        )

        table = Table()

        table.add_column(
            "Path"
        )

        table.add_column(
            "Matched Keywords"
        )

        for item in interesting[
            :30
        ]:

            table.add_row(
                item[
                    "path"
                ],
                ", ".join(
                    item[
                        "keywords"
                    ]
                )
            )

        console.print(
            table
        )

    paths = surface[
        "paths"
    ]

    if paths:

        console.print(
            "\n[bold]"
            "Discovered Paths"
            "[/bold]"
        )

        table = Table()

        table.add_column(
            "Path"
        )

        for path in paths[
            :40
        ]:

            table.add_row(
                path
            )

        console.print(
            table
        )

        if len(
            paths
        ) > 40:

            console.print(
                f"[dim]"
                f"Showing first 40 of "
                f"{len(paths)} discovered paths."
                f"[/dim]"
            )


# =========================================================
# RECOMMENDATIONS
# =========================================================

def show_recommendations(
    report
):

    recommendations = [
        check
        for check in report[
            "checks"
        ]
        if check.get(
            "recommendation"
        )
    ]

    if not recommendations:
        return

    console.print(
        "\n[bold]"
        "Recommendations"
        "[/bold]"
    )

    for index, check in enumerate(
        recommendations,
        start=1
    ):

        console.print(
            f"{index}. "
            f"[bold]"
            f"{check['name']}"
            f"[/bold]\n"
            f"   "
            f"{check['recommendation']}"
        )


# =========================================================
# FULL TERMINAL REPORT
# =========================================================

def show_single_report(
    report
):

    if not report[
        "success"
    ]:

        console.print(
            Panel(
                report[
                    "error"
                ],
                title=(
                    "[bold red]"
                    "Scan Failed"
                    "[/bold red]"
                ),
                border_style="red"
            )
        )

        return

    console.print()

    console.print(
        Panel.fit(
            "[bold cyan]"
            "SECURITY HEADER ANALYZER"
            "[/bold cyan]\n"
            "Passive Web Security Posture Assessment",
            border_style="cyan"
        )
    )

    summary = Table(
        show_header=False,
        box=None
    )

    summary.add_row(
        "Requested URL",
        report[
            "requested_url"
        ]
    )

    summary.add_row(
        "Final URL",
        report[
            "final_url"
        ]
    )

    summary.add_row(
        "HTTP Status",
        str(
            report[
                "status_code"
            ]
        )
    )

    summary.add_row(
        "Content Type",
        str(
            report[
                "content_type"
            ]
        )
    )

    summary.add_row(
        "Redirects",
        str(
            report[
                "redirect_count"
            ]
        )
    )

    summary.add_row(
        "Scanned At",
        report[
            "scanned_at"
        ]
    )

    console.print(
        summary
    )

    console.print()

    show_header_analysis(
        report
    )

    posture = report[
        "posture"
    ]

    console.print()

    console.print(
        Panel.fit(
            (
                f"[bold]"
                f"{report['percentage']}%"
                f"[/bold]\n"
                f"Header posture: "
                f"[{posture_style(posture)}]"
                f"{posture}"
                f"[/{posture_style(posture)}]"
            ),
            title="Header Assessment"
        )
    )

    show_https_redirect(
        report[
            "https_redirect"
        ]
    )

    show_tls(
        report[
            "tls"
        ]
    )

    show_information_disclosure(
        report[
            "information_disclosure"
        ]
    )

    show_cors(
        report[
            "cors"
        ]
    )

    show_cookie_analysis(
        report[
            "cookies"
        ]
    )

    show_surface_discovery(
        report[
            "surface_discovery"
        ]
    )

    show_recommendations(
        report
    )

    console.print()

    console.print(
        "[dim]"
        "Scope: passive analysis of selected HTTP "
        "headers, HTTPS behavior, TLS metadata, "
        "CORS configuration, technology disclosure, "
        "cookie attributes, and publicly exposed "
        "surface information. This is not an overall "
        "vulnerability assessment."
        "[/dim]"
    )


# =========================================================
# MULTI SITE SUMMARY
# =========================================================

def show_multi_summary(
    reports
):

    table = Table(
        title=(
            "Multi-Site Scan Summary"
        )
    )

    table.add_column(
        "Website"
    )

    table.add_column(
        "Headers"
    )

    table.add_column(
        "Posture"
    )

    table.add_column(
        "HTTPS"
    )

    table.add_column(
        "TLS"
    )

    table.add_column(
        "Paths"
    )

    for report in reports:

        if report[
            "success"
        ]:

            table.add_row(
                report[
                    "final_url"
                ],
                (
                    f"{report['percentage']}%"
                ),
                report[
                    "posture"
                ],
                report[
                    "https_redirect"
                ][
                    "status"
                ],
                report[
                    "tls"
                ][
                    "status"
                ],
                str(
                    report[
                        "surface_discovery"
                    ][
                        "total_unique_paths"
                    ]
                )
            )

        else:

            table.add_row(
                report[
                    "requested_url"
                ],
                "-",
                "FAILED",
                "-",
                "-",
                "-"
            )

    console.print()
    console.print(
        table
    )


# =========================================================
# EXPORT HELPERS
# =========================================================

def safe_filename(
    url
):

    return (
        url
        .replace(
            "https://",
            ""
        )
        .replace(
            "http://",
            ""
        )
        .replace(
            "/",
            "_"
        )
        .replace(
            ":",
            "_"
        )
    )


def export_report(
    reports
):

    REPORTS_FOLDER.mkdir(
        exist_ok=True
    )

    timestamp = (
        datetime.now()
        .strftime(
            "%Y%m%d_%H%M%S"
        )
    )

    if len(
        reports
    ) == 1:

        name = safe_filename(
            reports[0][
                "requested_url"
            ]
        )

        filename = (
            REPORTS_FOLDER
            / (
                f"{name}_"
                f"{timestamp}.json"
            )
        )

    else:

        filename = (
            REPORTS_FOLDER
            / (
                "multi_scan_"
                f"{timestamp}.json"
            )
        )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            reports,
            file,
            indent=4
        )

    return filename


# =========================================================
# HTML EXPORT
# =========================================================

def export_html_report(
    reports
):

    REPORTS_FOLDER.mkdir(
        exist_ok=True
    )

    timestamp = (
        datetime.now()
        .strftime(
            "%Y%m%d_%H%M%S"
        )
    )

    if len(
        reports
    ) == 1:

        name = safe_filename(
            reports[0][
                "requested_url"
            ]
        )

        filename = (
            REPORTS_FOLDER
            / (
                f"{name}_"
                f"{timestamp}.html"
            )
        )

    else:

        filename = (
            REPORTS_FOLDER
            / (
                "multi_scan_"
                f"{timestamp}.html"
            )
        )

    html_parts = []

    html_parts.append("""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width, initial-scale=1.0"
>

<title>
Security Header Analyzer Report
</title>

<style>

body {
    font-family: Arial, sans-serif;
    background: #0f1117;
    color: #e6e6e6;
    margin: 0;
    padding: 30px;
}

.container {
    max-width: 1100px;
    margin: auto;
}

h1,
h2,
h3 {
    color: #ffffff;
}

.subtitle {
    color: #9aa4b2;
    margin-bottom: 30px;
}

.card {
    background: #181c24;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
    border: 1px solid #2b3240;
}

.score {
    font-size: 42px;
    font-weight: bold;
}

.pass {
    color: #4ade80;
}

.warn {
    color: #facc15;
}

.fail {
    color: #f87171;
}

.info {
    color: #60a5fa;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
}

th,
td {
    padding: 12px;
    border-bottom: 1px solid #2b3240;
    text-align: left;
    vertical-align: top;
}

th {
    color: #cbd5e1;
}

.badge {
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: bold;
}

.badge-pass {
    background: #163f2b;
    color: #4ade80;
}

.badge-warn {
    background: #4a3f10;
    color: #facc15;
}

.badge-fail {
    background: #4a2020;
    color: #f87171;
}

.badge-info {
    background: #173557;
    color: #60a5fa;
}

code {
    word-break: break-word;
    color: #cbd5e1;
}

.recommendation {
    background: #121720;
    padding: 12px;
    border-left: 3px solid #60a5fa;
    margin-top: 10px;
}

.footer {
    margin-top: 40px;
    color: #7c8797;
    font-size: 13px;
}

</style>

</head>

<body>

<div class="container">

<h1>
Security Header Analyzer
</h1>

<p class="subtitle">
Passive Web Security Posture Assessment
</p>
""")

    for report in reports:

        if not report.get(
            "success"
        ):

            html_parts.append(
                f"""
<div class="card">

<h2>
{escape(report.get("requested_url", "Unknown"))}
</h2>

<p class="fail">
Scan failed:
{escape(report.get("error", "Unknown error"))}
</p>

</div>
"""
            )

            continue

        posture = report[
            "posture"
        ]

        posture_class = (
            "pass"
            if posture == "STRONG"
            else "warn"
            if posture == "NEEDS REVIEW"
            else "fail"
        )

        html_parts.append(
            f"""
<div class="card">

<h2>
{escape(report["final_url"])}
</h2>

<p>
<strong>Requested URL:</strong>
{escape(report["requested_url"])}
</p>

<p>
<strong>HTTP Status:</strong>
{report["status_code"]}
</p>

<p>
<strong>Content Type:</strong>
{escape(str(report["content_type"]))}
</p>

<p>
<strong>Redirects:</strong>
{report["redirect_count"]}
</p>

<p>
<strong>Scanned At:</strong>
{escape(report["scanned_at"])}
</p>

<div class="score">
{report["percentage"]}%
</div>

<p class="{posture_class}">
Header posture:
<strong>
{escape(posture)}
</strong>
</p>

</div>
"""
        )

        html_parts.append("""
<div class="card">

<h3>
HTTP Security Controls
</h3>

<table>

<tr>
<th>Status</th>
<th>Control</th>
<th>Finding</th>
<th>Score</th>
</tr>
""")

        for check in report[
            "checks"
        ]:

            status = check[
                "status"
            ]

            badge_class = (
                "badge-pass"
                if status == "PASS"
                else "badge-warn"
                if status == "WARN"
                else "badge-fail"
                if status == "FAIL"
                else "badge-info"
            )

            score_text = (
                "-"
                if check[
                    "max_score"
                ] == 0
                else (
                    f"{check['score']}/"
                    f"{check['max_score']}"
                )
            )

            html_parts.append(
                f"""
<tr>

<td>
<span class="badge {badge_class}">
{escape(status)}
</span>
</td>

<td>
{escape(check["name"])}
</td>

<td>
{escape(check["message"])}
</td>

<td>
{escape(score_text)}
</td>

</tr>
"""
            )

        html_parts.append("""
</table>
</div>
""")

        detailed_findings = []

        for check in report[
            "checks"
        ]:

            for detail in check.get(
                "details",
                []
            ):

                detailed_findings.append(
                    (
                        check[
                            "name"
                        ],
                        detail[
                            "severity"
                        ],
                        detail[
                            "finding"
                        ]
                    )
                )

        if detailed_findings:

            html_parts.append("""
<div class="card">

<h3>
Detailed Findings
</h3>

<table>

<tr>
<th>Severity</th>
<th>Control</th>
<th>Finding</th>
</tr>
""")

            for (
                control,
                severity,
                finding
            ) in detailed_findings:

                severity_class = (
                    "fail"
                    if severity in {
                        "HIGH",
                        "MEDIUM"
                    }
                    else "warn"
                    if severity == "LOW"
                    else "info"
                )

                html_parts.append(
                    f"""
<tr>

<td class="{severity_class}">
{escape(severity)}
</td>

<td>
{escape(control)}
</td>

<td>
{escape(finding)}
</td>

</tr>
"""
                )

            html_parts.append("""
</table>
</div>
""")

        https_test = report[
            "https_redirect"
        ]

        html_parts.append(
            f"""
<div class="card">

<h3>
HTTP → HTTPS Test
</h3>

<p>
<strong>Status:</strong>
{escape(https_test["status"])}
</p>

<p>
{escape(https_test["message"])}
</p>
"""
        )

        if https_test.get(
            "location"
        ):

            html_parts.append(
                f"""
<p>
<strong>Redirect target:</strong>

<code>
{escape(https_test["location"])}
</code>

</p>
"""
            )

        html_parts.append(
            "</div>"
        )

        tls = report[
            "tls"
        ]

        html_parts.append(
            f"""
<div class="card">

<h3>
TLS / Certificate Analysis
</h3>

<p>
<strong>Status:</strong>
{escape(tls.get("status", "UNKNOWN"))}
</p>

<p>
{escape(tls.get("message", ""))}
</p>
"""
        )

        if tls.get(
            "tls_version"
        ):

            issuer = tls.get(
                "certificate_issuer",
                {}
            )

            issuer_name = issuer.get(
                "organizationName",
                issuer.get(
                    "commonName",
                    "Unknown"
                )
            )

            html_parts.append(
                f"""
<table>

<tr>
<td>TLS Version</td>
<td>
{escape(str(tls.get("tls_version")))}
</td>
</tr>

<tr>
<td>Cipher</td>
<td>
{escape(str(tls.get("cipher")))}
</td>
</tr>

<tr>
<td>Certificate Expires</td>
<td>
{escape(str(tls.get("expires_at")))}
</td>
</tr>

<tr>
<td>Days Remaining</td>
<td>
{escape(str(tls.get("days_remaining")))}
</td>
</tr>

<tr>
<td>Issuer</td>
<td>
{escape(str(issuer_name))}
</td>
</tr>

<tr>
<td>SAN Entries</td>
<td>
{escape(str(tls.get("san_count")))}
</td>
</tr>

</table>
"""
            )

        html_parts.append(
            "</div>"
        )

        disclosure = report[
            "information_disclosure"
        ]

        html_parts.append(
            f"""
<div class="card">

<h3>
Information Disclosure
</h3>

<p>
<strong>Status:</strong>
{escape(disclosure["status"])}
</p>

<p>
{escape(disclosure["message"])}
</p>
"""
        )

        if disclosure[
            "findings"
        ]:

            html_parts.append("""
<table>

<tr>
<th>Severity</th>
<th>Header</th>
<th>Value</th>
</tr>
""")

            for finding in disclosure[
                "findings"
            ]:

                html_parts.append(
                    f"""
<tr>

<td>
{escape(finding["severity"])}
</td>

<td>
{escape(finding["header"])}
</td>

<td>
<code>
{escape(finding["value"])}
</code>
</td>

</tr>
"""
                )

            html_parts.append(
                "</table>"
            )

        html_parts.append(
            "</div>"
        )

        cors = report[
            "cors"
        ]

        html_parts.append(
            f"""
<div class="card">

<h3>
CORS Analysis
</h3>

<p>
<strong>Status:</strong>
{escape(cors["status"])}
</p>

<p>
{escape(cors["message"])}
</p>
"""
        )

        if cors.get(
            "origin"
        ):

            html_parts.append(
                f"""
<p>

<strong>
Allowed Origin:
</strong>

<code>
{escape(cors["origin"])}
</code>

</p>
"""
            )

        if cors.get(
            "credentials"
        ):

            html_parts.append(
                f"""
<p>

<strong>
Credentials:
</strong>

{escape(cors["credentials"])}

</p>
"""
            )

        html_parts.append(
            "</div>"
        )

        cookies = report[
            "cookies"
        ]

        html_parts.append("""
<div class="card">

<h3>
Cookie Security Analysis
</h3>
""")

        if not cookies:

            html_parts.append("""
<p class="info">
No Set-Cookie headers were observed
in this response.
</p>
""")

        else:

            html_parts.append("""
<table>

<tr>
<th>Cookie</th>
<th>Secure</th>
<th>HttpOnly</th>
<th>SameSite</th>
</tr>
""")

            for cookie in cookies:

                html_parts.append(
                    f"""
<tr>

<td>
{escape(cookie["name"])}
</td>

<td>
{"YES" if cookie["secure"] else "NO"}
</td>

<td>
{"YES" if cookie["httponly"] else "NO"}
</td>

<td>
{escape(cookie["samesite"] or "Missing")}
</td>

</tr>
"""
                )

            html_parts.append(
                "</table>"
            )

        html_parts.append(
            "</div>"
        )

        # =================================================
        # SURFACE DISCOVERY HTML
        # =================================================

        surface = report[
            "surface_discovery"
        ]

        html_parts.append(
            f"""
<div class="card">

<h3>
Passive Surface Discovery
</h3>

<table>

<tr>
<td>Same-domain HTML links</td>
<td>{surface["html_link_count"]}</td>
</tr>

<tr>
<td>Unique paths discovered</td>
<td>{surface["total_unique_paths"]}</td>
</tr>

<tr>
<td>robots.txt</td>
<td>
{"FOUND" if surface["robots"]["found"] else "Not found"}
</td>
</tr>

<tr>
<td>sitemap.xml</td>
<td>
{"FOUND" if surface["sitemap"]["found"] else "Not found"}
</td>
</tr>

<tr>
<td>Interesting paths</td>
<td>
{len(surface["interesting_paths"])}
</td>
</tr>

</table>
"""
        )

        if surface[
            "interesting_paths"
        ]:

            html_parts.append("""
<h3>
Interesting Public Paths
</h3>

<table>

<tr>
<th>Path</th>
<th>Matched Keywords</th>
</tr>
""")

            for item in surface[
                "interesting_paths"
            ][
                :50
            ]:

                html_parts.append(
                    f"""
<tr>

<td>
<code>
{escape(item["path"])}
</code>
</td>

<td>
{escape(", ".join(item["keywords"]))}
</td>

</tr>
"""
                )

            html_parts.append(
                "</table>"
            )

        if surface[
            "paths"
        ]:

            html_parts.append("""
<h3>
Discovered Paths
</h3>

<table>

<tr>
<th>Path</th>
</tr>
""")

            for path in surface[
                "paths"
            ][
                :100
            ]:

                html_parts.append(
                    f"""
<tr>

<td>
<code>
{escape(path)}
</code>
</td>

</tr>
"""
                )

            html_parts.append(
                "</table>"
            )

        html_parts.append(
            "</div>"
        )

        recommendations = [
            check
            for check in report[
                "checks"
            ]
            if check.get(
                "recommendation"
            )
        ]

        if recommendations:

            html_parts.append("""
<div class="card">

<h3>
Recommendations
</h3>
""")

            for index, check in enumerate(
                recommendations,
                start=1
            ):

                html_parts.append(
                    f"""
<div class="recommendation">

<strong>
{index}. {escape(check["name"])}
</strong>

<p>
{escape(check["recommendation"])}
</p>

</div>
"""
                )

            html_parts.append(
                "</div>"
            )

    html_parts.append("""
<div class="footer">

Scope: passive analysis of selected HTTP headers,
HTTPS behavior, TLS metadata, CORS configuration,
technology disclosure, cookie attributes, robots.txt,
sitemap.xml, and publicly referenced same-domain links.

This report is not an overall vulnerability assessment.

</div>

</div>

</body>

</html>
""")

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "".join(
                html_parts
            )
        )

    return filename


# =========================================================
# USER INTERFACE
# =========================================================

def scan_one_site():

    url = Prompt.ask(
        "Enter a website URL"
    )

    console.print(
        "\n[cyan]"
        "Running passive security checks..."
        "[/cyan]"
    )

    report = scan_url(
        url
    )

    show_single_report(
        report
    )

    return [
        report
    ]


def scan_multiple_sites():

    console.print(
        "\nEnter websites separated by commas."
    )

    raw_urls = Prompt.ask(
        "Websites"
    )

    urls = [
        item.strip()
        for item in (
            raw_urls.split(",")
        )
        if item.strip()
    ]

    reports = []

    for index, url in enumerate(
        urls,
        start=1
    ):

        console.print(
            f"\n[cyan]"
            f"Scanning "
            f"{index}/{len(urls)}: "
            f"{url}"
            f"[/cyan]"
        )

        reports.append(
            scan_url(
                url
            )
        )

    show_multi_summary(
        reports
    )

    return reports


# =========================================================
# MAIN
# =========================================================

def main():

    console.print(
        Panel.fit(
            "[bold cyan]"
            "SECURITY HEADER ANALYZER"
            "[/bold cyan]\n"
            "Passive Web Security Posture Scanner",
            border_style="cyan"
        )
    )

    console.print(
        "\n[bold]"
        "Choose a scan mode:"
        "[/bold]\n"
        "1. Scan one website\n"
        "2. Scan multiple websites\n"
        "Q. Quit"
    )

    choice = Prompt.ask(
        "Select",
        choices=[
            "1",
            "2",
            "q",
            "Q"
        ],
        default="1"
    )

    if choice.lower() == "q":

        console.print(
            "Goodbye."
        )

        return

    if choice == "1":

        reports = (
            scan_one_site()
        )

    else:

        reports = (
            scan_multiple_sites()
        )

    export_choice = Prompt.ask(
        "\nExport results?",
        choices=[
            "json",
            "html",
            "both",
            "none"
        ],
        default="both"
    )

    if export_choice in {
        "json",
        "both"
    }:

        json_file = (
            export_report(
                reports
            )
        )

        console.print(
            f"\n[green]"
            f"JSON report saved to: "
            f"{json_file}"
            f"[/green]"
        )

    if export_choice in {
        "html",
        "both"
    }:

        html_file = (
            export_html_report(
                reports
            )
        )

        console.print(
            f"\n[green]"
            f"HTML report saved to: "
            f"{html_file}"
            f"[/green]"
        )


if __name__ == "__main__":
    main()