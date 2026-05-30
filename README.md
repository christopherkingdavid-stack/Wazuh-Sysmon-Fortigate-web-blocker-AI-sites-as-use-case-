# Wazuh-Sysmon-Fortigate-web-blocker-AI-sites-as-use-case-

A detection and response pipeline that watches for AI platform access on Windows endpoints, then automatically pushes deny rules to a FortiGate VM. When Sysmon catches a DNS query to something like chat.openai.com, Wazuh fires a Python script that resolves the domain, calls the FortiGate REST API, and drops in a block policy — no clicks required.
Table of Contents
	∙	Overview
	∙	Architecture
	∙	How It Works
	∙	Monitored AI Platforms
	∙	Prerequisites
	∙	Environment Setup
	∙	Active Response Script
	∙	Wazuh Rules & Configuration
	∙	FortiGate API Setup
	∙	Deployment
	∙	Troubleshooting
	∙	Security Notes
  The goal is simple: stop endpoints from reaching AI platforms without needing anyone to manually update firewall rules. Sysmon does the watching, Wazuh does the detection, and a Python active-response script handles the FortiGate side over its REST API.

  One thing worth knowing upfront: AI platforms run on CDN infrastructure with rotating IPs. Blocking a resolved IP works, but it’s not permanent — the IP can change. For stronger enforcement, pair this with FortiGate’s URL filtering or DNS sinkholing. This pipeline is a good first layer, not a complete solution on its own.

  How It Works
	1.	Sysmon on the Windows endpoint logs:
	∙	Event ID 22 when a process queries a DNS name matching an AI domain
	∙	Event ID 13 when a registry value gets written by an AI-related app or browser extension
	2.	The Wazuh agent ships the event to the Wazuh Manager.
	3.	The Wazuh decoder parses the Sysmon XML. Two custom rules handle this:
	∙	Rule 61650 fires on Event 22 DNS queries matching AI hostnames
	∙	Rule 61640 fires on Event 13 registry writes with AI-related paths
	4.	Active Response runs the Python script, passing the full alert JSON via stdin.
	5.	The Python script (fortigate_block_ai.py):
	∙	Reads the raw alert JSON and scans it for AI keyword matches
	∙	Calls socket.gethostbyname() to resolve the matched domain to an IP
	∙	POSTs to /api/v2/cmdb/firewall/address to create a WAZUH_{KEYWORD}_{IP} address object
	∙	POSTs to /api/v2/cmdb/firewall/policy to create a BLOCK_WAZUH_{KEYWORD}_{IP} deny policy
	∙	Logs everything to /tmp/fortigate_ar.log
	6.	FortiGate applies the deny policy immediately — traffic from RX-VLAN (LAN) to the resolved IP on port1 (WAN) gets dropped.

  Infrastructure:
	∙	VMware Workstation/Fusion, NAT network 192.168.176.0/24
	∙	Wazuh OVA at 192.168.176.130
	∙	FortiGate VM (v7.4.11+) at 192.168.176.128, VDOM root, LAN on RX-VLAN, WAN on port1
	∙	Windows endpoint running both the Wazuh agent and Sysmon
Software on Wazuh Manager:
	∙	Python 3 at /var/ossec/framework/python/bin/python3
	∙	requests library (present system-wide and inside Wazuh’s bundled Python)
	∙	Wazuh Manager 4.x

  Environment Setup
Sysmon configuration (Windows endpoint)
The Sysmon config needs to include DNS and registry filters for the AI domains you care about. Minimum working excerpt:

Active Response Script
Path: /var/ossec/active-response/bin/fortigate_block_ai.py

Fix line endings before deploying
If you edited this file on Windows, it will silently fail with CRLF line endings. Fix it first:

FortiGate API Setup
1. Create a restricted admin profile
In the FortiGate GUI: System → Admin Profiles → Create New
	∙	Profile name: wazuh_api_profile
	∙	Permissions: Read/Write on Firewall and Address only — nothing else needs access here
2. Create the API user
System → Administrators → Create New → REST API Admin
	∙	Username: wazuh_soar
	∙	Admin profile: wazuh_api_profile
	∙	Trusted hosts: 192.xx.xxx.xxx/xx (Wazuh Manager only — don’t leave this open)
	∙	Generate and save the API key
3. Test it before wiring up the script
4. You should get a JSON list of address objects back. If you get a 401 or 403, sort that out before touching the script config — it’s always an auth or trusted-host issue.

5. Manual test
You can simulate an active response trigger without waiting for a real event:
Then check FortiGate under Policy & Objects → Addresses for a WAZUH_OPENAI_* entry and Firewall Policy for BLOCK_WAZUH_OPENAI_*.

Security Notes
API key scope — The FortiGate API key only needs write access to firewall/address and firewall/policy. Don’t use a global admin account for this.
Trusted hosts — Lock the API user to 192.168.176.130/32. If that IP ever changes, update it in FortiGate before the script breaks.
TLS — The script sets verify=False because the FortiGate VM uses a self-signed cert. That’s fine for a lab. In production, replace the cert with a trusted one and flip verification back on.
Duplicate objects — If the same domain resolves to the same IP twice, FortiGate will reject the second address object with an error. The script handles it gracefully — logged, not fatal.
IP rotation — This is the main limitation. CDN-backed AI platforms can resolve to a different IP on the next query. The block is real but not permanent. Combine with FortiGate URL filtering or DNS sinkholing if you need persistent enforcement.
Rule level — Level 3 on DNS events is broad. You’ll likely want to raise that threshold in production once you’ve verified the rules aren’t firing on false positives.
Log rotation — /tmp/fortigate_ar.log has no rotation configured. Add one for anything running long-term:

