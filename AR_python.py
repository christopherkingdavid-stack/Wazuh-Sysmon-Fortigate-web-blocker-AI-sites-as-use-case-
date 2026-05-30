#!/var/ossec/framework/python/bin/python3
"""
fortigate_block_ai.py
SOAR Active Response: Wazuh → FortiGate AI Domain Blocker
Triggered by Wazuh on Sysmon Event 22 (DNS) or Event 13 (Registry)
"""

import sys
import json
import socket
import requests
import urllib3
import logging
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
FORTIGATE_IP   = "Your IP"
FORTIGATE_PORT = 443
API_KEY        = "YOUR_FORTIGATE_API_KEY_HERE"   # replace with your REST API key
VDOM           = "root"
LAN_INTERFACE  = "RX-VLAN"
WAN_INTERFACE  = "port1"
LOG_FILE       = "/tmp/fortigate_ar.log"

AI_KEYWORDS = [
    "openai", "anthropic", "claude", "gemini", "copilot",
    "grok", "perplexity", "mistral", "huggingface", "chatgpt"
]

DOMAIN_MAP = {
    "openai":       "chat.openai.com",
    "chatgpt":      "chat.openai.com",
    "anthropic":    "claude.ai",
    "claude":       "claude.ai",
    "gemini":       "gemini.google.com",
    "copilot":      "copilot.microsoft.com",
    "grok":         "grok.x.ai",
    "perplexity":   "perplexity.ai",
    "mistral":      "chat.mistral.ai",
    "huggingface":  "huggingface.co",
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ── Helpers ───────────────────────────────────────────────────────────────────
BASE_URL = f"https://{FORTIGATE_IP}:{FORTIGATE_PORT}/api/v2/cmdb"
HEADERS  = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type":  "application/json"
}
PARAMS   = {"vdom": VDOM}


def api_post(endpoint: str, payload: dict) -> dict:
    url = f"{BASE_URL}/{endpoint}"
    try:
        r = requests.post(url, headers=HEADERS, params=PARAMS,
                          json=payload, verify=False, timeout=10)
        log.info("POST %s → HTTP %s | %s", endpoint, r.status_code, r.text[:200])
        return r.json()
    except Exception as exc:
        log.error("API call failed (%s): %s", endpoint, exc)
        return {}


def resolve_domain(domain: str) -> str | None:
    try:
        ip = socket.gethostbyname(domain)
        log.info("Resolved %s → %s", domain, ip)
        return ip
    except socket.gaierror as exc:
        log.warning("DNS resolution failed for %s: %s", domain, exc)
        return None


def create_address_object(name: str, ip: str) -> None:
    payload = {
        "name":    name,
        "type":    "ipmask",
        "subnet":  f"{ip}/32",
        "comment": f"Auto-blocked by Wazuh SOAR — {datetime.utcnow().isoformat()}Z"
    }
    api_post("firewall/address", payload)


def create_deny_policy(name: str, addr_name: str) -> None:
    payload = {
        "name":      name,
        "srcintf":   [{"name": LAN_INTERFACE}],
        "dstintf":   [{"name": WAN_INTERFACE}],
        "srcaddr":   [{"name": "all"}],
        "dstaddr":   [{"name": addr_name}],
        "action":    "deny",
        "schedule":  "always",
        "service":   [{"name": "ALL"}],
        "logtraffic": "all",
        "comments":  f"SOAR auto-deny — {datetime.utcnow().isoformat()}Z"
    }
    api_post("firewall/policy", payload)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log.info("=== fortigate_block_ai.py triggered ===")

    try:
        raw = sys.stdin.read()
        log.debug("Raw alert input: %s", raw[:500])
    except Exception as exc:
        log.error("Failed to read stdin: %s", exc)
        sys.exit(1)

    raw_lower = raw.lower()
    matched_keyword = None

    for kw in AI_KEYWORDS:
        if kw in raw_lower:
            matched_keyword = kw
            log.info("Matched AI keyword: %s", kw)
            break

    if not matched_keyword:
        log.info("No AI keyword matched — exiting.")
        sys.exit(0)

    domain = DOMAIN_MAP.get(matched_keyword)
    if not domain:
        log.warning("No domain mapping for keyword: %s", matched_keyword)
        sys.exit(0)

    ip = resolve_domain(domain)
    if not ip:
        log.error("Could not resolve domain %s — aborting block.", domain)
        sys.exit(1)

    safe_kw   = matched_keyword.upper()
    safe_ip   = ip.replace(".", "_")
    addr_name = f"WAZUH_{safe_kw}_{safe_ip}"
    pol_name  = f"BLOCK_WAZUH_{safe_kw}_{safe_ip}"

    log.info("Creating address object: %s → %s", addr_name, ip)
    create_address_object(addr_name, ip)

    log.info("Creating deny policy: %s", pol_name)
    create_deny_policy(pol_name, addr_name)

    log.info("=== Block complete for %s (%s) ===", domain, ip)


if __name__ == "__main__":
    main()
