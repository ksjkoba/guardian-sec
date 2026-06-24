"""MITRE ATT&CK technique mapper — zero-inference, pattern-based."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence


@dataclass(frozen=True)
class Technique:
    id: str          # e.g. "T1059.001"
    name: str        # e.g. "PowerShell"
    tactic: str      # e.g. "Execution"
    kill_chain_pos: int  # 0=Recon … 9=Impact (for kill-chain ordering)


# Kill-chain phase ordering (MITRE 14-phase model collapsed to 10)
_PHASE_ORDER = {
    "Reconnaissance": 0,
    "Resource Development": 1,
    "Initial Access": 2,
    "Execution": 3,
    "Persistence": 4,
    "Privilege Escalation": 5,
    "Defense Evasion": 5,
    "Credential Access": 6,
    "Discovery": 6,
    "Lateral Movement": 7,
    "Collection": 8,
    "Command and Control": 8,
    "Exfiltration": 9,
    "Impact": 9,
}


def _phase(tactic: str) -> int:
    return _PHASE_ORDER.get(tactic, 5)


# (compiled_pattern, Technique)
_RULES: list[tuple[re.Pattern, Technique]] = []


def _r(pattern: str, tid: str, name: str, tactic: str) -> None:
    _RULES.append((
        re.compile(pattern, re.IGNORECASE),
        Technique(id=tid, name=name, tactic=tactic, kill_chain_pos=_phase(tactic)),
    ))


# ── Reconnaissance ────────────────────────────────────────────────────────────
_r(r"(nmap|masscan|zmap|unicornscan|port.?scan|SYN.?scan)", "T1046", "Network Service Discovery", "Reconnaissance")
_r(r"(nikto|dirb|gobuster|ffuf|dirsearch|wfuzz)", "T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance")
_r(r"(whois|nslookup|dig\s|host\s.*lookup)", "T1590", "Gather Victim Network Information", "Reconnaissance")
_r(r"(shodan|censys|fofa)", "T1596", "Search Open Technical Databases", "Reconnaissance")

# ── Initial Access ────────────────────────────────────────────────────────────
_r(r"(phishing|malicious.?attach|spear.?phish)", "T1566", "Phishing", "Initial Access")
_r(r"(exploit.*public|public.?exploit|CVE-\d{4}-\d+)", "T1190", "Exploit Public-Facing Application", "Initial Access")
_r(r"(brute.?force|credential.?stuff|password.?spray|hydra|medusa|john.?the)", "T1110", "Brute Force", "Initial Access")
_r(r"(valid.?account|stolen.?credential|compromised.?account)", "T1078", "Valid Accounts", "Initial Access")
_r(r"(drive.?by|watering.?hole|malicious.?url)", "T1189", "Drive-by Compromise", "Initial Access")

# ── Execution ─────────────────────────────────────────────────────────────────
_r(r"(powershell|pwsh)\s*(-enc|-exec|bypass|nop|w\s*hidden)", "T1059.001", "PowerShell", "Execution")
_r(r"(cmd\.exe|command\s+shell|/c\s+\")", "T1059.003", "Windows Command Shell", "Execution")
_r(r"(bash\s+-[ci]|sh\s+-[ci]|/bin/(ba)?sh\s+-c)", "T1059.004", "Unix Shell", "Execution")
_r(r"(python\s+-[ce]|perl\s+-e|ruby\s+-e|php\s+-r)", "T1059.006", "Python/Scripting", "Execution")
_r(r"(eval\s*\(|exec\s*\(|base64.*decode.*exec)", "T1059", "Command and Scripting Interpreter", "Execution")
_r(r"(cron(tab)?|at\s+-f|scheduled.?task|schtask)", "T1053", "Scheduled Task/Job", "Execution")
_r(r"(mshta|wscript|cscript|regsvr32|rundll32)", "T1218", "System Binary Proxy Execution", "Execution")

# ── Persistence ───────────────────────────────────────────────────────────────
_r(r"(\.bashrc|\.bash_profile|\.zshrc|\.profile)\s*(modified|written|changed)", "T1546.004", "Unix Shell Configuration Modification", "Persistence")
_r(r"(crontab\s+-[le]|/etc/cron)", "T1053.003", "Cron Job", "Persistence")
_r(r"(systemctl\s+enable|\.service\s+created|/etc/init\.d)", "T1543.002", "Systemd Service", "Persistence")
_r(r"(HKLM\\.*\\Run|HKCU\\.*\\Run|registry.*autorun)", "T1547.001", "Registry Run Keys", "Persistence")
_r(r"(ssh.?authorized.?keys|\.ssh/authorized)", "T1098.004", "SSH Authorized Keys", "Persistence")
_r(r"(webshell|php.?shell|jsp.?shell|aspx.?shell)", "T1505.003", "Web Shell", "Persistence")
_r(r"(LD_PRELOAD|/etc/ld\.so\.conf)", "T1574.006", "Dynamic Linker Hijacking", "Persistence")

# ── Privilege Escalation ──────────────────────────────────────────────────────
_r(r"(sudo\s+-l|sudo.*NOPASSWD|sudoers)", "T1548.003", "Sudo and Sudo Caching", "Privilege Escalation")
_r(r"(chmod\s+[u+]*s|setuid|setgid|SUID)", "T1548.001", "Setuid/Setgid", "Privilege Escalation")
_r(r"(kernel.?exploit|dirty.?cow|local.?priv.?esc)", "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation")
_r(r"(docker.*--privileged|docker.*root|escape.?container)", "T1611", "Escape to Host", "Privilege Escalation")
_r(r"(polkit|pkexec|CVE-2021-4034)", "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation")

# ── Defense Evasion ───────────────────────────────────────────────────────────
_r(r"(history\s+-c|unset\s+HISTFILE|HISTSIZE=0|shred.*bash_history)", "T1070.003", "Clear Command History", "Defense Evasion")
_r(r"(rm\s+-rf.*log|truncate.*\.log|>/var/log)", "T1070.002", "Clear Linux Logs", "Defense Evasion")
_r(r"(base64\s+-d|xxd\s+-r|openssl\s+enc.*-d)", "T1140", "Deobfuscate/Decode Files", "Defense Evasion")
_r(r"(disable.*firewall|ufw\s+disable|iptables\s+-F|setenforce\s+0)", "T1562.004", "Disable/Modify System Firewall", "Defense Evasion")
_r(r"(kill.*antivirus|disable.*av|tamper.*defender)", "T1562.001", "Disable Security Tools", "Defense Evasion")
_r(r"(chmod\s+777|world.?writable|o\+w)", "T1222", "File Permissions Modification", "Defense Evasion")

# ── Credential Access ─────────────────────────────────────────────────────────
_r(r"(/etc/shadow|/etc/passwd\s+read|unshadow)", "T1003.008", "/etc/passwd and /etc/shadow", "Credential Access")
_r(r"(mimikatz|sekurlsa|lsass.*dump|procdump.*lsass)", "T1003.001", "LSASS Memory", "Credential Access")
_r(r"(keylog|keyboard.?capture|input.?capture)", "T1056.001", "Keylogging", "Credential Access")
_r(r"(credential.*file|\.aws/credentials|\.netrc|id_rsa\b)", "T1552.001", "Credentials in Files", "Credential Access")
_r(r"(hardcoded.?(password|secret|key|token)|api_key\s*=\s*[\"'])", "T1552", "Unsecured Credentials", "Credential Access")
_r(r"(hashcat|john\s+--wordlist|crack.?password)", "T1110.002", "Password Cracking", "Credential Access")

# ── Discovery ─────────────────────────────────────────────────────────────────
_r(r"(ifconfig|ip\s+addr|ipconfig|network.?interface)", "T1016", "System Network Configuration Discovery", "Discovery")
_r(r"(ps\s+(aux|ef)|tasklist|process.?list)", "T1057", "Process Discovery", "Discovery")
_r(r"(whoami|id\s*$|getuid|current.?user)", "T1033", "System Owner/User Discovery", "Discovery")
_r(r"(find\s+/.*-perm|locate\s+|which\s+)", "T1083", "File and Directory Discovery", "Discovery")
_r(r"(uname\s+-[ar]|systeminfo|sw_vers|os.?version)", "T1082", "System Information Discovery", "Discovery")
_r(r"(arp\s+-[an]|netstat|ss\s+-[tlnp]|open.?port)", "T1049", "System Network Connections Discovery", "Discovery")
_r(r"(cat\s+/etc/passwd|getent\s+passwd|enumerate.*user)", "T1087.001", "Local Account Discovery", "Discovery")

# ── Lateral Movement ──────────────────────────────────────────────────────────
_r(r"(ssh\s+-[oiL]|ssh\s+root@|scp\s+root@)", "T1021.004", "SSH", "Lateral Movement")
_r(r"(psexec|wmic.*process|winrm|evil-winrm)", "T1021.006", "Windows Remote Management", "Lateral Movement")
_r(r"(pivot|port.?forward|tunnel.*ssh|ssh\s+-[RL])", "T1572", "Protocol Tunneling", "Lateral Movement")
_r(r"(rdp|mstsc|xfreerdp|rdesktop)", "T1021.001", "Remote Desktop Protocol", "Lateral Movement")

# ── Collection ────────────────────────────────────────────────────────────────
_r(r"(tar\s+-czf|zip\s+-r|7z\s+a|archive.*exfil)", "T1560", "Archive Collected Data", "Collection")
_r(r"(clipboard|xclip|xdotool|pbpaste)", "T1115", "Clipboard Data", "Collection")
_r(r"(screenshot|scrot|import\s+-window)", "T1113", "Screen Capture", "Collection")
_r(r"(keychain|secret.?store|pass.?manager.*dump)", "T1555", "Credentials from Password Stores", "Collection")

# ── Command and Control ───────────────────────────────────────────────────────
_r(r"(beacon|c2.?callback|command.?and.?control|implant)", "T1071", "Application Layer Protocol C2", "Command and Control")
_r(r"(dns.?tunnel|iodine|dns2tcp|dnscat)", "T1071.004", "DNS C2", "Command and Control")
_r(r"(reverse.?shell|bind.?shell|netcat.*-[le]|nc\s+-[le])", "T1059", "Interactive Shell", "Command and Control")
_r(r"(tor\b|onion.*proxy|anonymi[sz]|proxychains)", "T1090.003", "Proxy: Multi-hop", "Command and Control")
_r(r"(cobalt.?strike|metasploit|empire|sliver|havoc|covenant)", "T1587.001", "Malware C2 Framework", "Command and Control")
_r(r"(4444|5555|6666|6667|31337|1337)\b", "T1571", "Non-Standard Port", "Command and Control")

# ── Exfiltration ──────────────────────────────────────────────────────────────
_r(r"(curl|wget).*(http|ftp).*upload|exfil|data.?leak", "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration")
_r(r"(large.*transfer|high.?volume.*upload|megabytes.*sent)", "T1030", "Data Transfer Size Limits", "Exfiltration")
_r(r"(pastebin|transfer\.sh|file\.io|gofile\.io)", "T1567.002", "Exfiltration to Code Repository", "Exfiltration")
_r(r"(ftp.*put|sftp.*put|scp.*remote)", "T1048.003", "Exfiltration Over Unencrypted Protocol", "Exfiltration")

# ── Impact ────────────────────────────────────────────────────────────────────
_r(r"(ransomware|encrypt.*file|\.(locked|enc|crypt)$)", "T1486", "Data Encrypted for Impact", "Impact")
_r(r"(dd\s+if=/dev/zero|shred\s+-[uzn]|wipe.*disk)", "T1561", "Disk Wipe", "Impact")
_r(r"(fork.?bomb|:()\{.*\}|kill\s+-9\s+-1)", "T1499", "Endpoint Denial of Service", "Impact")
_r(r"(rm\s+-rf\s+/|deltree|format\s+[cde]:)", "T1485", "Data Destruction", "Impact")


def map_techniques(text: str) -> list[Technique]:
    """Return all ATT&CK techniques matching text. Deduped by technique ID."""
    seen: set[str] = set()
    results: list[Technique] = []
    for pattern, tech in _RULES:
        if tech.id not in seen and pattern.search(text):
            seen.add(tech.id)
            results.append(tech)
    return results


def top_technique(text: str) -> Technique | None:
    """Return the highest-kill-chain-position technique found (most advanced stage)."""
    techs = map_techniques(text)
    if not techs:
        return None
    return max(techs, key=lambda t: t.kill_chain_pos)
