#!/usr/bin/env python3
"""
=====================================================================
 NozeWhisper  v1 (OFFLINE)
=====================================================================
Reads the output of your recon tools and tells you your NEXT MOVE,
plus flags what you skipped. It advises -- YOU hack.

It understands:
  - nmap        (port scans, incl. -sV service/version output)
  - gobuster / ffuf / feroxbuster / dirb   (web directory brute force)
  - nikto       (web server scan findings)
  - whatweb     (tech fingerprint)


USAGE
  python3 nozewhisper.py                 # runs the built-in example scans
  python3 nozewhisper.py scan.txt        # auto-detects the tool and advises
  python3 nozewhisper.py out.txt --type nmap     # force a parser
  cat scan.txt | python3 nozewhisper.py -         # read from a pipe

=====================================================================
"""

import argparse
import re
import sys
from urllib.parse import urlparse


# =====================================================================
# 1) SERVICE RULES  --  the "brain". keyword -> (nice label, next move)
#    Matched by nmap's service name (via aliases) OR resolved from a port.
# =====================================================================
SERVICE_RULES = {
    "ftp":        ("FTP", "Try anonymous:anonymous. Note version (searchsploit). If writable, upload a webshell."),
    "ssh":        ("SSH", "Note version for CVEs. Try weak/default & reused creds. Hunt for exposed private keys."),
    "telnet":     ("Telnet", "Cleartext -- try default creds and sniff traffic. Grab the banner for device/version."),
    "smtp":       ("SMTP", "Enumerate users (smtp-user-enum: VRFY/EXPN/RCPT). Check for open relay. Grab banner."),
    "dns":        ("DNS", "Try a zone transfer: dig axfr @IP domain. Bruteforce subdomains. Note BIND version."),
    "http":       ("HTTP", "Fuzz dirs & vhosts (feroxbuster/ffuf). Read source + robots.txt. whatweb + nikto."),
    "https":      ("HTTPS", "Same as HTTP + read the TLS cert for hostnames/emails (add them to /etc/hosts)."),
    "pop3":       ("POP3", "Grab banner. Try known creds. Enum caps (nmap pop3-capabilities)."),
    "imap":       ("IMAP", "Grab banner. Try known creds. Enumerate capabilities."),
    "snmp":       ("SNMP", "Bruteforce community strings (onesixtyone). snmpwalk/snmp-check -- leaks users/procs/routes."),
    "ldap":       ("LDAP", "Try anonymous bind (ldapsearch -x -b). Dump naming contexts. In AD -> feed BloodHound."),
    "smb":        ("SMB", "nxc smb IP (netexec) + enum4linux-ng. smbclient -L -N for shares. Check null sessions, signing, MS17-010."),
    "nfs":        ("NFS", "showmount -e IP to list exports. Mount readable shares. no_root_squash = privesc path."),
    "mssql":      ("MSSQL", "Try sa/weak creds (nxc mssql). If in, check xp_cmdshell. nmap ms-sql-* scripts."),
    "mysql":      ("MySQL", "Try root/blank & reused web creds. Note version. Check LOAD_FILE for file read."),
    "postgresql": ("PostgreSQL", "Try postgres/weak creds. If in, COPY ... PROGRAM for command execution."),
    "oracle":     ("Oracle TNS", "Guess the SID (odat sidguesser). Try default creds. Use odat for further attacks."),
    "rdp":        ("RDP", "Try known creds carefully (lockouts!). Check NLA + legacy vulns (nmap rdp-*, MS12-020). xfreerdp to connect."),
    "vnc":        ("VNC", "Try no-auth and common passwords. Check CVE bypasses. Connect with vncviewer."),
    "redis":      ("Redis", "Often no auth -- redis-cli then INFO. RCE via SSH-key/webshell write or module load. Or just dump data."),
    "mongodb":    ("MongoDB", "Try unauthenticated mongosh. List DBs and dump. Check version for CVEs."),
    "memcached":  ("Memcached", "Unauth -- 'stats' then 'stats items' to dump cached secrets/tokens."),
    "elasticsearch": ("Elasticsearch", "Hit /_cat/indices and /_search for exposed data. Check version for RCE CVEs."),
    "winrm":      ("WinRM", "With creds: evil-winrm for a shell. Validate creds with nxc winrm."),
    "kerberos":   ("Kerberos", "AD present. Spray/enumerate users (kerbrute). Try AS-REP roasting + Kerberoasting later."),
    "rpcbind":    ("RPCbind", "rpcinfo -p IP to list RPC services. Often reveals NFS -> showmount -e."),
    "rsync":      ("rsync", "List modules: rsync IP:: . Pull readable modules. Sometimes writable -> plant a payload."),
    "tftp":       ("TFTP", "No auth, blind. GET common config/backup filenames (need to know names)."),
    "sip":        ("SIP/VoIP", "Enumerate extensions (svwar). Grab banner. Check PBX default creds."),
    "ajp":        ("AJP", "Tomcat AJP -- test Ghostcat (CVE-2020-1938) for file read/inclusion."),
    "tomcat":     ("Tomcat", "Hit /manager/html -- try tomcat:tomcat, admin:admin. If in, deploy a WAR shell."),
    "jenkins":    ("Jenkins", "/script console = RCE if unauth. Check version. Try default/weak creds."),
    "docker":     ("Docker API", "Exposed API = host takeover. docker -H tcp://IP:2375 ps, then run a privileged container to escape."),
    "irc":        ("IRC", "Grab banner -- some UnrealIRCd builds carry a backdoor CVE. Enumerate."),
    "x11":        ("X11", "Test open access (xdpyinfo). If open: xwd screenshots + keylogging."),
    "finger":     ("Finger", "finger @IP and finger user@IP to enumerate valid users."),
    "ntp":        ("NTP", "ntpq -c readvar for host info. Check monlist (amplification/info leak)."),
    "ident":      ("Ident", "Query the user owning a connection -- can reveal service accounts."),
    "couchdb":    ("CouchDB", "Hit /_utils and /_all_dbs. Check version for privesc/RCE CVEs."),
    "git":        ("Git daemon", "git clone git://IP/repo -- grab source for secrets."),
    "ipp":        ("IPP/CUPS", "Check CUPS version (recent RCE CVEs). Enumerate printers."),
    "mqtt":       ("MQTT", "Subscribe to '#' (mosquitto_sub) to sniff all topics -- often unauth IoT data."),
    "vmware":     ("VMware", "Check for known ESXi/vCenter CVEs by version. Try default creds."),
    "ldaps":      ("LDAPS", "Same as LDAP over TLS. Try anonymous bind; dump directory; feed BloodHound in AD."),
}

# nmap service string -> canonical keyword above
ALIASES = {
    "microsoft-ds": "smb", "netbios-ssn": "smb", "netbios-ns": "smb", "ms-ds": "smb",
    "ms-wbt-server": "rdp", "ms-wbt": "rdp",
    "domain": "dns", "domain-s": "dns",
    "ms-sql-s": "mssql", "ms-sql": "mssql", "mssql": "mssql",
    "http-proxy": "http", "http-alt": "http", "www": "http", "www-http": "http",
    "ssl/http": "https", "ssl/https": "https", "https-alt": "https", "http-mgmt": "http",
    "imaps": "imap", "pop3s": "pop3", "smtps": "smtp", "submission": "smtp",
    "ldapssl": "ldaps", "ldaps": "ldaps", "globalcatldap": "ldap", "globalcatldapssl": "ldaps",
    "rpcbind": "rpcbind", "nfs": "nfs", "nfs_acl": "nfs", "mountd": "nfs",
    "vnc-http": "vnc", "wsman": "winrm", "wsmans": "winrm",
    "kerberos-sec": "kerberos", "kpasswd5": "kerberos", "kerberos": "kerberos",
    "ajp13": "ajp", "mongod": "mongodb", "memcache": "memcached",
    "oracle-tns": "oracle", "ircs": "irc", "sip-tls": "sip",
    "snmptrap": "snmp", "ntp": "ntp", "auth": "ident",
}

# =====================================================================
# 2) PORT MAP  --  big list of well-known + non-default ports -> service
#    Used when nmap gave no service name, or to identify a bare port.
# =====================================================================
PORT_SERVICE = {
    20: "ftp", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "ntp",
    43: "whois", 49: "tacacs", 53: "dns", 67: "dhcp", 69: "tftp", 79: "finger",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 113: "ident",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "smb", 138: "smb", 139: "smb",
    143: "imap", 161: "snmp", 162: "snmp", 179: "bgp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtp", 500: "ike", 512: "rexec", 513: "rlogin", 514: "rsh",
    515: "printer", 520: "rip", 523: "db2", 548: "afp", 554: "rtsp", 587: "smtp",
    593: "msrpc", 623: "ipmi", 631: "ipp", 636: "ldaps", 660: "smb", 873: "rsync",
    902: "vmware", 993: "imap", 995: "pop3", 1080: "socks", 1099: "java-rmi",
    1194: "openvpn", 1352: "lotus", 1433: "mssql", 1434: "mssql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 1900: "upnp", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel", 2100: "oracle", 2181: "zookeeper", 2222: "ssh", 2323: "telnet",
    2375: "docker", 2376: "docker", 2379: "etcd", 2483: "oracle", 2484: "oracle",
    3000: "http", 3128: "http", 3260: "iscsi", 3268: "ldap", 3269: "ldaps",
    3306: "mysql", 3339: "http", 3389: "rdp", 3690: "svn", 4369: "epmd",
    4443: "https", 4444: "http", 4505: "salt", 4506: "salt", 4786: "cisco-smi",
    5000: "http", 5001: "http", 5060: "sip", 5061: "sip", 5222: "xmpp",
    5353: "dns", 5432: "postgresql", 5555: "adb", 5601: "kibana", 5672: "amqp",
    5800: "vnc", 5900: "vnc", 5901: "vnc", 5902: "vnc", 5984: "couchdb",
    5985: "winrm", 5986: "winrm", 6000: "x11", 6001: "x11", 6379: "redis",
    6443: "https", 6660: "irc", 6667: "irc", 6668: "irc", 6697: "irc",
    7001: "http", 7070: "http", 7077: "spark", 7199: "cassandra", 7443: "https",
    7474: "neo4j", 7687: "neo4j", 7777: "http", 8000: "http", 8005: "tomcat",
    8008: "http", 8009: "ajp", 8010: "http", 8020: "hadoop", 8025: "smtp",
    8060: "http", 8069: "http", 8080: "http", 8081: "http", 8083: "http",
    8086: "influxdb", 8088: "http", 8089: "http", 8090: "http", 8091: "couchdb",
    8161: "http", 8180: "http", 8200: "vault", 8291: "mikrotik", 8333: "bitcoin",
    8384: "http", 8443: "https", 8500: "consul", 8530: "http", 8686: "java-jmx",
    8834: "nessus", 8880: "http", 8888: "http", 8983: "solr", 9000: "http",
    9001: "http", 9042: "cassandra", 9060: "http", 9080: "http", 9090: "http",
    9091: "transmission", 9092: "kafka", 9100: "printer", 9200: "elasticsearch",
    9300: "elasticsearch", 9389: "ldap", 9418: "git", 9443: "https",
    9600: "logstash", 9990: "http", 9999: "http", 10000: "http", 10250: "kubelet",
    11211: "memcached", 15672: "amqp", 16992: "http", 27017: "mongodb",
    27018: "mongodb", 28017: "mongodb", 44818: "ethernetip", 49152: "msrpc",
    50000: "jenkins", 50030: "hadoop", 50070: "hadoop", 61616: "amqp",
}

# =====================================================================
# 3) WEB PATH HINTS  --  keyword found in a URL/path -> next move
# =====================================================================
WEB_PATH_HINTS = {
    ".git":        "Source leak! Dump it: git-dumper http://TARGET/.git out/ -> read for creds/logic.",
    ".svn":        "SVN leak -- extract with svn-extractor / dvcs-ripper for source & secrets.",
    ".env":        "Env file -- likely DB creds, API keys, secrets. Open it directly.",
    ".ds_store":   ".DS_Store -- parse it (ds_store_exp) to reveal hidden filenames.",
    ".htpasswd":   "May contain hashed HTTP-auth creds -- crack with hashcat/john.",
    "web.config":  "ASP.NET config -- often connection strings & secrets.",
    "backup":      "Backup dir -- download everything; look for source, DB dumps, creds.",
    ".bak":        "Backup file -- download and inspect for source/creds.",
    "old":         "'old' path -- legacy code, often more vulnerable. Explore.",
    "config":      "Config path -- hunt for creds, keys, connection strings.",
    "phpmyadmin":  "phpMyAdmin -- try root:blank/root:root; check version for RCE CVEs.",
    "adminer":     "Adminer -- single-file DB client. Try DB creds; check for known CVEs.",
    "wp-login":    "WordPress -- run wpscan --enumerate u,vp. Try weak creds; check plugins.",
    "wp-admin":    "WordPress admin -- wpscan for users/plugins. Weak-cred + plugin RCE paths.",
    "wp-content":  "WordPress -- enumerate plugins/themes here (wpscan) for known vulns.",
    "administrator": "Joomla admin -- joomscan. Try default creds; check component CVEs.",
    "manager":     "Tomcat manager? -- default creds (tomcat:tomcat) -> WAR deploy shell.",
    "admin":       "Admin panel -- try default/weak creds; look for auth bypass & upload.",
    "login":       "Login page -- test SQLi, default creds, and username enumeration.",
    "dashboard":   "Dashboard -- likely post-auth. Find creds or a bypass to reach it.",
    "portal":      "Portal -- enumerate further; test auth and IDOR once inside.",
    "upload":      "Upload feature -- test unrestricted file upload -> webshell (great RCE path).",
    "files":       "File area -- test for path traversal / IDOR to read other files.",
    "api":         "API -- look for /api-docs, swagger, or graphql. Test authz & IDOR.",
    "swagger":     "Swagger/OpenAPI -- read it to map every endpoint, then test each.",
    "graphql":     "GraphQL -- run introspection to dump the schema, then abuse queries.",
    "actuator":    "Spring Boot Actuator -- /env, /heapdump, /jolokia can leak secrets or give RCE.",
    "phpinfo":     "phpinfo() -- leaks full config, paths, and modules. Read it for recon.",
    "server-status": "Apache server-status -- live requests, IPs, sometimes tokens in URLs.",
    "robots.txt":  "robots.txt -- read the Disallow entries; they point to hidden paths.",
    "sitemap":     "sitemap.xml -- enumerate every listed URL.",
    "cgi-bin":     "cgi-bin -- test for Shellshock and old CGI RCE.",
    "console":     "Web console -- possible RCE (Jenkins/JMX/etc). Check what it is.",
    "jenkins":     "Jenkins -- /script = RCE if unauth. Check version + default creds.",
    "debug":       "Debug endpoint -- may expose stack traces, config, or a debug shell.",
    "test":        "Test path -- often unfinished/unsecured. Explore for shortcuts.",
    "dev":         "Dev path -- staging code, weaker auth. Explore.",
    "install":     "Installer left in place -- may allow re-config/takeover. Check it.",
    "setup":       "Setup wizard exposed -- can reset creds or reconfigure the app.",
    "id_rsa":      "SSH private key exposed -- download, chmod 600, log in.",
    "credentials": "File literally named credentials -- open it.",
    "passwd":      "Possible password file -- open it.",
    "dump":        "Data dump -- download; often full DB export with creds/PII.",
    ".well-known": "Check for security.txt / config that reveals contacts or endpoints.",
}


# =====================================================================
#  Canonicalise a (port, service) pair to a rulebook keyword
# =====================================================================
JUNK_SERVICES = {"", "unknown", "tcpwrapped", "filtered", "closed", "?"}

def canon(port, service):
    s = (service or "").strip().lower()
    if s in ALIASES:
        return ALIASES[s]
    if s in SERVICE_RULES:
        return s
    # service name unhelpful -> fall back to the port map
    by_port = PORT_SERVICE.get(port)
    if by_port:
        return by_port
    return None


# =====================================================================
#  PARSERS
# =====================================================================
def parse_nmap(text):
    """Return list of {port, proto, service, version}."""
    out = []
    pat = re.compile(
        r"^(\d{1,5})/(tcp|udp)[ \t]+(?:open|open\|filtered)[ \t]+(\S+)(?:[ \t]+(\S.*))?$",
        re.MULTILINE,
    )
    for m in pat.finditer(text):
        out.append({
            "port": int(m.group(1)),
            "proto": m.group(2),
            "service": m.group(3),
            "version": (m.group(4) or "").strip(),
        })
    return out


def parse_web(text):
    """Return list of {path, status} from gobuster/ffuf/feroxbuster/dirb."""
    hits = []
    seen = set()

    def add(path, status):
        if not path:
            return
        if path.startswith("http://") or path.startswith("https://"):
            path = urlparse(path).path or "/"
        if not path.startswith("/"):
            path = "/" + path
        key = (path, status)
        if key not in seen:
            seen.add(key)
            hits.append({"path": path, "status": status})

    for line in text.splitlines():
        line = line.rstrip()

        # gobuster:  /admin  (Status: 301) [Size: 312]
        m = re.match(r"^(/\S*)\s+\(Status:\s*(\d+)\)", line)
        if m:
            add(m.group(1), int(m.group(2))); continue

        # dirb:  + http://h/admin (CODE:200|SIZE:1234)
        m = re.search(r"(https?://\S+)\s+\(CODE:(\d+)", line)
        if m:
            add(m.group(1), int(m.group(2))); continue
        m = re.search(r"==>\s*DIRECTORY:\s*(https?://\S+)", line)
        if m:
            add(m.group(1), 301); continue

        # feroxbuster:  200      GET      1l   2w  200c http://h/admin
        m = re.match(r"^(\d{3})\s+\w+\s+.*?\s(https?://\S+)", line)
        if m:
            add(m.group(2), int(m.group(1))); continue

        # ffuf default:  admin   [Status: 200, Size: 4242, ...]
        m = re.match(r"^(\S+)\s+\[Status:\s*(\d+)", line)
        if m and "Progress" not in line:
            add(m.group(1), int(m.group(2))); continue

        # ffuf -v style:  | URL | http://h/admin
        m = re.search(r"\|\s*URL\s*\|\s*(https?://\S+)", line)
        if m:
            add(m.group(1), 200); continue

    return hits


def parse_nikto(text):
    """Return list of interesting Nikto finding lines."""
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("+ ") and len(line) > 4:
            low = line.lower()
            if any(k in low for k in (
                "osvdb", "cve", "outdated", "server:", "x-powered-by",
                "might", "vulnerab", "default", "backup", "admin",
                "directory indexing", "cookie", "header",
            )):
                findings.append(line[2:].strip())
    return findings


def parse_whatweb(text):
    """Return list of detected technologies from whatweb output."""
    techs = set()
    known = [
        "WordPress", "Joomla", "Drupal", "Apache", "nginx", "IIS", "PHP",
        "Tomcat", "Jenkins", "jQuery", "Bootstrap", "Laravel", "Django",
        "Express", "Node.js", "ASP.NET", "OpenSSL", "Python", "Ruby",
        "MySQL", "PhpMyAdmin", "Magento", "GitLab", "Grafana", "Kibana",
    ]
    for k in known:
        if re.search(re.escape(k), text, re.IGNORECASE):
            techs.add(k)
    return sorted(techs)


# =====================================================================
#  TOOL DETECTION
# =====================================================================
def detect_tool(text):
    t = text.lower()
    if "nmap scan report" in t or re.search(r"^\d{1,5}/(tcp|udp)\s+open", text, re.MULTILINE):
        return "nmap"
    if "whatweb" in t or (re.search(r"\[\d{3} [A-Za-z]", text) and re.search(r"[A-Za-z]+\[[^\]]{1,40}\]", text)):
        return "whatweb"
    if re.search(r"^\+ ", text, re.MULTILINE) and ("nikto" in t or "osvdb" in t or "target ip" in t):
        return "nikto"
    if "(status:" in t or "ffuf" in t or ":: progress:" in t or re.search(r"^\d{3}\s+GET", text, re.MULTILINE) or "(code:" in t:
        return "web"
    if re.search(r"^/\S+", text, re.MULTILINE):
        return "web"
    return "nmap"


# =====================================================================
#  ADVICE PRINTERS
# =====================================================================
def hr():
    print("-" * 69)

def advise_nmap(rows):
    if not rows:
        print("[-] No open ports found in that output.\n"); return
    print(f"[+] nmap: {len(rows)} open port(s) found\n")
    services_present = set()
    versions_seen = False
    for r in rows:
        key = canon(r["port"], r["service"])
        if r["version"]:
            versions_seen = True
        if key in SERVICE_RULES:
            label, move = SERVICE_RULES[key]
            services_present.add(key)
        else:
            label = (r["service"] if r["service"] not in JUNK_SERVICES else (key or "unknown"))
            move = "Grab the banner (nc / nmap -sV) and searchsploit the version."
        tag = f"{r['port']}/{r['proto']}"
        print(f"  {tag:<10} {label:<12} -> {move}")
        if r["version"]:
            print(f"  {'':<10} {'':<12}    version: {r['version']}")
    # ---- reminders ----
    print()
    rem = []
    if all(r["proto"] == "tcp" for r in rows):
        rem.append("You scanned TCP only -- run UDP too: sudo nmap -sU --top-ports 100 IP")
    rem.append("Did you scan ALL ports? nmap -p- IP  (services love hiding on high ports).")
    if not versions_seen:
        rem.append("No versions shown -- re-run with -sV -sC to fingerprint and auto-script.")
    if services_present & {"http", "https"}:
        rem.append("Web is open -- fuzz VHOSTS/subdomains too, not just directories.")
    if "smb" in services_present:
        rem.append("SMB is open -- run: nxc smb IP  and  enum4linux-ng IP")
    if services_present & {"kerberos", "ldap", "ldaps"}:
        rem.append("Kerberos/LDAP = Active Directory -- plan BloodHound + user spraying.")
    if "snmp" in services_present:
        rem.append("SNMP is UDP -- easy to miss but very leaky. snmpwalk it.")
    for x in rem:
        print(f"[!] {x}")
    print()

def advise_web(hits):
    if not hits:
        print("[-] No web paths found in that output.\n"); return
    print(f"[+] web brute force: {len(hits)} path(s) found\n")
    interesting = 0
    for h in hits:
        path, status = h["path"], h["status"]
        low = path.lower()
        hint = None
        for kw, advice in WEB_PATH_HINTS.items():
            if kw in low:
                hint = advice; break
        snote = {
            401: "401 -- auth required. Try default creds / header bypass.",
            403: "403 -- forbidden. Try bypass tricks (/./ , //, %2e, X-Forwarded-For, verb change).",
            500: "500 -- server error. Poke inputs here; often an injection point.",
            405: "405 -- method not allowed. Try other verbs (PUT/DELETE/OPTIONS).",
        }.get(status)
        line = f"  [{status}] {path}"
        if hint:
            interesting += 1
            line += f"\n         -> {hint}"
        if snote:
            line += f"\n         -> {snote}"
        print(line)
    print()
    if interesting == 0:
        print("[!] Nothing jumped out by name -- manually browse the 200s and diff sizes.\n")
    else:
        print("[!] Chase the flagged paths first -- they're the likely footholds.\n")

def advise_nikto(findings):
    if not findings:
        print("[-] No notable Nikto findings parsed.\n"); return
    print(f"[+] nikto: {len(findings)} notable finding(s)\n")
    for f in findings:
        print(f"  * {f}")
    print()
    print("[!] Prioritise: outdated software (searchsploit the version), exposed")
    print("    admin/backup paths, and missing security headers.\n")

def advise_whatweb(techs):
    if not techs:
        print("[-] No known technologies fingerprinted.\n"); return
    print(f"[+] whatweb: detected {len(techs)} technolog(ies)\n")
    tips = {
        "WordPress": "wpscan --url URL --enumerate u,vp,vt",
        "Joomla": "joomscan --url URL",
        "Drupal": "droopescan scan drupal -u URL",
        "Tomcat": "try /manager/html with default creds -> WAR shell",
        "Jenkins": "check /script for unauth RCE; try default creds",
        "phpMyAdmin": "try root:blank; check version for RCE",
        "PhpMyAdmin": "try root:blank; check version for RCE",
        "GitLab": "check version for known CVEs (some pre-auth RCE)",
        "Grafana": "check for CVE-2021-43798 path traversal",
    }
    for t in techs:
        extra = tips.get(t)
        if extra:
            print(f"  * {t:<12} -> {extra}")
        else:
            print(f"  * {t:<12} -> searchsploit '{t}' and note the version")
    print()
    print("[!] Pin exact versions, then searchsploit each for a quick win.\n")


# =====================================================================
#  EXAMPLES (used when no file is given)
# =====================================================================
EX_NMAP = """Nmap scan report for 10.10.10.5
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 7.6p1 Ubuntu
80/tcp   open  http          Apache httpd 2.4.29
445/tcp  open  microsoft-ds  Samba smbd 4.7.6
2222/tcp open  ssh           OpenSSH 8.2
8000/tcp open  http          Werkzeug httpd 1.0.1
6379/tcp open  redis         Redis 5.0.7
"""

EX_WEB = """/admin                (Status: 301) [Size: 312]
/index.html           (Status: 200) [Size: 10701]
/uploads              (Status: 301) [Size: 314]
/.git/HEAD            (Status: 200) [Size: 23]
/backup               (Status: 403) [Size: 277]
/login.php            (Status: 200) [Size: 1543]
"""


def run(text, forced=None):
    tool = forced or detect_tool(text)
    hr()
    print("  NozeWhisper  ::  it whispers, you strike")
    print(f"  parser: {tool}")
    hr(); print()
    if tool == "nmap":
        advise_nmap(parse_nmap(text))
    elif tool == "web":
        advise_web(parse_web(text))
    elif tool == "nikto":
        advise_nikto(parse_nikto(text))
    elif tool == "whatweb":
        advise_whatweb(parse_whatweb(text))
    else:
        print(f"[-] Unknown parser: {tool}")


def main():
    ap = argparse.ArgumentParser(description="NozeWhisper -- advises your next move from recon output.")
    ap.add_argument("file", nargs="?", help="tool output file, or - for stdin. Omit to run examples.")
    ap.add_argument("--type", choices=["nmap", "web", "nikto", "whatweb"], help="force a parser instead of auto-detect")
    args = ap.parse_args()

    if args.file == "-":
        run(sys.stdin.read(), args.type)
    elif args.file:
        with open(args.file) as f:
            run(f.read(), args.type)
    else:
        print(">>> No file given -- running built-in EXAMPLE scans.\n")
        run(EX_NMAP, "nmap")
        run(EX_WEB, "web")


if __name__ == "__main__":
    main()
