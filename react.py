import base64
import os
import re

import requests
from dotenv import load_dotenv
from langchain_openrouter import ChatOpenRouter

load_dotenv()

FOFA_API_URL = "https://fofa.info/api/v1/search/all"
FETCH_TIMEOUT_SECONDS = 15
FETCH_MAX_BYTES = 10_000
REPORTS_DIR = "reports"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"


FOFA_QUERY = '"Press & hold the Windows Key"'


def fofa_search(size: int = 5) -> str:
    """
    Search FOFA for ClickFix pages. The query is fixed to the ClickFix fingerprint.
    param size: Number of results (max 10 on free tier).
    returns: Raw JSON response from Fofa, or error message string."""
    email = os.getenv("FOFA_EMAIL")
    key = os.getenv("FOFA_KEY")
    if not email or not key:
        return "ERROR: FOFA_EMAIL and FOFA_KEY must be set in .env"

    qbase64 = base64.b64encode(FOFA_QUERY.encode()).decode()
    params = {
        "email": email,
        "key": key,
        "qbase64": qbase64,
        "size": size,
        "fields": "host,ip,port,title,server",
    }
    response = requests.get(FOFA_API_URL, params=params, timeout=30)
    return response.text


def fetch_url(url: str) -> str:
    """
    param url: Full URL (must start with http:// or https://).
    returns: HTML content truncated to 50KB. Static read only, no JS execution."""
    if not url.startswith(("http://", "https://")):
        return "ERROR: URL must start with http:// or https://"
    try:
        response = requests.get(
            url,
            timeout=FETCH_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
        return response.text[:FETCH_MAX_BYTES]
    except requests.exceptions.RequestException as e:
        return f"ERROR: Could not fetch {url}: {e}"


def extract_powershell(content: str) -> str:
    """
    param content: HTML or JS source to scan for ClickFix payloads.
    returns: Newline-separated unique matches, or 'No PowerShell patterns found.'"""
    patterns = [
        r"""clipboard\.writeText\(\s*["'`]([^"'`]+)["'`]""",
        r"""powershell(?:\.exe)?\s+(?:-\w+\s+)*-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}""",
        r"""(?:iex|Invoke-Expression)\s*\(?[^)\n]+\)?""",
        r"""mshta(?:\.exe)?\s+https?://\S+""",
        r"""(?:curl|Invoke-WebRequest|iwr)\s+[^|\n]+\|\s*(?:iex|Invoke-Expression)""",
    ]
    findings = []
    for pat in patterns:
        for match in re.finditer(pat, content, re.IGNORECASE):
            findings.append(match.group(0).strip())
    unique = list(dict.fromkeys(findings))
    if not unique:
        return "No PowerShell patterns found."
    return "\n".join(unique)


def defang(text: str) -> str:
    """
    param text: Text containing URLs and/or IPs.
    returns: Same text with URLs as hxxp(s) and IPs/domains dotted with [.]."""
    text = re.sub(r"http(s?)://", r"hxxp\1://", text, flags=re.IGNORECASE)
    text = re.sub(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", r"\1[.]\2[.]\3[.]\4", text)
    text = re.sub(r"\.(?=[a-zA-Z]{2,}\b)", "[.]", text)
    return text


def write_report(filename: str, content: str) -> str:
    """
    param filename: Markdown filename (e.g. 'clickfix-2026-04-28.md').
    param content: Full markdown body to write.
    returns: Absolute path of the written report."""
    if not filename.endswith(".md"):
        filename += ".md"
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return os.path.abspath(path)


tools = [
    fofa_search,
    fetch_url,
    extract_powershell,
    defang,
    write_report,
]

llm = ChatOpenRouter(model="moonshotai/kimi-k2.6", temperature=0).bind_tools(tools)
