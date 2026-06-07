# -*- coding: utf-8 -*-
"""
scanner.py - Motore di scansione della rete locale.

Funzioni principali:
  - rilevamento della/e subnet locale/i
  - host discovery (ping sweep parallelo + tabella ARP)
  - port scan TCP connect (non intrusivo) sulle porte comuni
  - banner grabbing leggero per identificare i servizi
  - controlli di sicurezza mirati e SICURI (anonymous FTP, Redis no-auth,
    Telnet aperto, ecc.) per evidenziare misconfigurazioni reali

Tutto usa SOLO la libreria standard di Python: nessuna installazione.
Pensato per scansionare LA PROPRIA rete (uso difensivo/autovalutazione).
"""

import socket
import ipaddress
import subprocess
import re
import threading
import platform
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from vuln_db import COMMON_PORTS, get_port_info, SEVERITY_WEIGHT
import recon


# ---------------------------------------------------------------------------
# Strutture dati
# ---------------------------------------------------------------------------

class Finding:
    """Una singola osservazione di sicurezza su un host."""
    def __init__(self, port, service, severity, issue, remediation, evidence=""):
        self.port = port
        self.service = service
        self.severity = severity
        self.issue = issue
        self.remediation = remediation
        self.evidence = evidence  # eventuale prova concreta (es. banner)


class HostResult:
    """Risultato della scansione di un singolo host."""
    def __init__(self, ip):
        self.ip = ip
        self.hostname = ""
        self.mac = ""
        self.open_ports = []      # lista di int
        self.findings = []        # lista di Finding
        self.banners = {}         # porta -> banner string
        self.recon = []           # lista di recon.ReconItem (info ricavate)

    @property
    def max_severity(self):
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_WEIGHT[f.severity]).severity

    @property
    def risk_score(self):
        return sum(SEVERITY_WEIGHT[f.severity] for f in self.findings)


# ---------------------------------------------------------------------------
# Scoperta della rete locale
# ---------------------------------------------------------------------------

def get_local_subnets():
    """
    Ritorna una lista di reti IPv4 (ipaddress.IPv4Network) a cui appartiene
    questa macchina, assumendo /24 dove non disponibile la netmask.
    """
    subnets = []
    seen = set()

    # Metodo 1: IP usato per uscire verso Internet (no traffico reale inviato)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_network(local_ip + "/24", strict=False)
        if str(net) not in seen:
            subnets.append(net)
            seen.add(str(net))
    except OSError:
        pass

    # Metodo 2: tutti gli IP associati all'hostname
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ":" in ip:  # salta IPv6
                continue
            if ip.startswith("127."):
                continue
            net = ipaddress.ip_network(ip + "/24", strict=False)
            if str(net) not in seen:
                subnets.append(net)
                seen.add(str(net))
    except socket.gaierror:
        pass

    return subnets


def _ping(ip, timeout_ms=600):
    """Esegue un singolo ping verso ip. Ritorna True se risponde."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), str(ip)]
    try:
        # CREATE_NO_WINDOW per non far lampeggiare console su Windows
        creationflags = 0x08000000 if system == "windows" else 0
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 1,
            creationflags=creationflags,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _tcp_alive(ip, ports=(80, 443, 445, 22, 139), timeout=0.4):
    """Fallback: l'host e' considerato vivo se una porta comune accetta TCP."""
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((str(ip), port)) == 0:
                    return True
        except OSError:
            continue
    return False


def _read_arp_table():
    """Legge la tabella ARP del sistema -> dict {ip: mac}."""
    mapping = {}
    try:
        system = platform.system().lower()
        creationflags = 0x08000000 if system == "windows" else 0
        out = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=5,
            creationflags=creationflags,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return mapping

    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    mac_re = re.compile(r"([0-9a-fA-F]{2}([:-])[0-9a-fA-F]{2}(\2[0-9a-fA-F]{2}){4})")
    for line in out.splitlines():
        ip_m = ip_re.search(line)
        mac_m = mac_re.search(line)
        if ip_m and mac_m:
            mapping[ip_m.group(1)] = mac_m.group(1).replace("-", ":").lower()
    return mapping


def discover_hosts(subnet, progress=None, stop_event=None, max_workers=80):
    """
    Ping sweep parallelo su una subnet. Ritorna lista di IP (str) vivi.
    progress(done, total) e' un callback opzionale.
    """
    hosts = [str(h) for h in subnet.hosts()]
    total = len(hosts)
    alive = []
    done = 0
    lock = threading.Lock()

    def check(ip):
        if stop_event and stop_event.is_set():
            return None
        if _ping(ip) or _tcp_alive(ip):
            return ip
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check, ip): ip for ip in hosts}
        for fut in as_completed(futures):
            if stop_event and stop_event.is_set():
                break
            res = fut.result()
            with lock:
                done += 1
                if progress:
                    progress(done, total)
            if res:
                alive.append(res)

    # Aggiungi host noti dalla tabella ARP (gia' contattati di recente)
    arp = _read_arp_table()
    for ip in arp:
        try:
            if ipaddress.ip_address(ip) in subnet and ip not in alive:
                alive.append(ip)
        except ValueError:
            continue

    return sorted(set(alive), key=lambda x: tuple(int(p) for p in x.split(".")))


# ---------------------------------------------------------------------------
# Port scan + banner grabbing
# ---------------------------------------------------------------------------

def scan_port(ip, port, timeout=0.6):
    """Ritorna True se la porta TCP e' aperta (connect scan)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def grab_banner(ip, port, timeout=1.2):
    """
    Tenta di leggere un banner dal servizio. Per HTTP invia una HEAD minimale.
    Ritorna stringa (eventualmente vuota).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return ""
            # Per servizi web, sollecita una risposta
            if port in (80, 8080, 8000, 8888, 8008, 3000, 5000, 9000):
                req = ("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip).encode()
                sock.sendall(req)
            try:
                data = sock.recv(256)
            except socket.timeout:
                return ""
            return data.decode("latin-1", errors="replace").strip()
    except OSError:
        return ""


def scan_host_ports(ip, ports=None, timeout=0.6, max_workers=60, stop_event=None):
    """Scansiona le porte di un host. Ritorna lista di porte aperte (int)."""
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []

    def check(port):
        if stop_event and stop_event.is_set():
            return None
        return port if scan_port(ip, port, timeout) else None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(check, p) for p in ports]
        for fut in as_completed(futures):
            res = fut.result()
            if res is not None:
                open_ports.append(res)
    return sorted(open_ports)


# ---------------------------------------------------------------------------
# Controlli di sicurezza mirati (sicuri e non distruttivi)
# ---------------------------------------------------------------------------

def _check_ftp_anonymous(ip, port=21, timeout=2.0):
    """Verifica se l'FTP consente il login anonimo. Ritorna evidence o ''."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return ""
            s.recv(256)
            s.sendall(b"USER anonymous\r\n")
            s.recv(256)
            s.sendall(b"PASS anonymous@test.com\r\n")
            resp = s.recv(256).decode("latin-1", errors="replace")
            if resp.startswith("230"):
                return "Login anonimo ACCETTATO (risposta: %s)" % resp.strip()
    except OSError:
        pass
    return ""


def _check_redis_noauth(ip, port=6379, timeout=2.0):
    """Verifica se Redis risponde senza autenticazione. Ritorna evidence o ''."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return ""
            s.sendall(b"PING\r\n")
            resp = s.recv(64).decode("latin-1", errors="replace")
            if "PONG" in resp:
                return "Redis risponde a PING SENZA autenticazione"
            if "NOAUTH" in resp:
                return ""  # protetto: ok
    except OSError:
        pass
    return ""


def _check_telnet_open(ip, port=23, timeout=2.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return "Servizio Telnet raggiungibile (protocollo in chiaro)"
    except OSError:
        pass
    return ""


def _check_mongo_noauth(ip, port=27017, timeout=2.0):
    """Sonda MongoDB: se accetta TCP e non chiude subito, probabile esposizione."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return "MongoDB raggiungibile in rete (verifica che l'autenticazione sia attiva)"
    except OSError:
        pass
    return ""


# Mappa porta -> funzione di controllo attivo (sicuro)
ACTIVE_CHECKS = {
    21: _check_ftp_anonymous,
    23: _check_telnet_open,
    6379: _check_redis_noauth,
    27017: _check_mongo_noauth,
}


def analyze_host(ip, ports=None, stop_event=None, log=None):
    """
    Scansiona un host completo: porte, banner, controlli attivi.
    Ritorna un HostResult. log(str) e' un callback opzionale per il diario.
    """
    if ports is None:
        ports = COMMON_PORTS

    result = HostResult(ip)

    # Hostname inverso
    try:
        result.hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        result.hostname = ""

    # MAC da ARP
    result.mac = _read_arp_table().get(ip, "")

    if log:
        log("Scansione porte su %s ..." % ip)

    result.open_ports = scan_host_ports(ip, ports, stop_event=stop_event)

    for port in result.open_ports:
        if stop_event and stop_event.is_set():
            break

        info = get_port_info(port)
        banner = grab_banner(ip, port)
        if banner:
            result.banners[port] = banner

        # Controllo attivo specifico, se disponibile
        evidence = ""
        severity = info["severity"]
        issue = info["issue"]
        if port in ACTIVE_CHECKS:
            ev = ACTIVE_CHECKS[port](ip)
            if ev:
                evidence = ev
                # Una misconfig confermata alza la severita' al massimo sensato
                if port == 21:
                    severity = "CRITICAL"
                    issue = "FTP con accesso anonimo ATTIVO: chiunque puo' leggere/scrivere file."
                elif port == 6379:
                    severity = "CRITICAL"
                    issue = "Redis ESPOSTO senza password: lettura/scrittura dati e rischio RCE."

        if banner:
            evidence = (evidence + "  |  " if evidence else "") + "Banner: " + banner[:120]

        result.findings.append(Finding(
            port=port,
            service=info["service"],
            severity=severity,
            issue=issue,
            remediation=info["remediation"],
            evidence=evidence,
        ))

    # --- Fase di enumerazione: "cosa si puo' ottenere" ---
    if not (stop_event and stop_event.is_set()):
        _run_recon(ip, result, log=log)

    # Ordina i finding per severita' decrescente
    result.findings.sort(key=lambda f: SEVERITY_WEIGHT[f.severity], reverse=True)
    return result


# Porte web in chiaro / cifrate per l'enumerazione HTTP
_HTTP_PORTS = (80, 8080, 8000, 8888, 8008, 3000, 5000, 9000, 8081)
_HTTPS_PORTS = (443, 8443)


def _add_recon(result, item):
    """Aggiunge un ReconItem e, se porta un rischio, anche un Finding."""
    if item is None:
        return
    result.recon.append(item)
    if item.risk:
        severity, issue, remediation, evidence = item.risk
        # porta 'logica' per il finding: 0 = informazione da enumerazione
        result.findings.append(Finding(
            port=0,
            service=item.source,
            severity=severity,
            issue=issue,
            remediation=remediation,
            evidence=evidence,
        ))


def _run_recon(ip, result, log=None):
    """Esegue l'enumerazione dei servizi e popola result.recon / findings."""
    ports = set(result.open_ports)

    if log:
        log("  Enumerazione su %s ..." % ip)

    # NetBIOS (UDP 137) - sempre, anche se 139/445 non risultano in scan TCP
    try:
        nb = recon.recon_netbios(ip)
        if nb:
            item, info = nb
            _add_recon(result, item)
            if not result.hostname and info.get("computer"):
                result.hostname = info["computer"]
            if not result.mac and info.get("mac"):
                result.mac = info["mac"]
    except Exception:
        pass

    # SNMP (UDP 161) - sempre (la scan TCP non rileva UDP)
    try:
        _add_recon(result, recon.recon_snmp(ip))
    except Exception:
        pass

    # SMB / SMBv1
    if 445 in ports or 139 in ports:
        port = 445 if 445 in ports else 139
        try:
            _add_recon(result, recon.recon_smb(ip, port))
        except Exception:
            pass

    # HTTP
    for p in _HTTP_PORTS:
        if p in ports:
            try:
                _add_recon(result, recon.http_info(ip, p, use_tls=False))
            except Exception:
                pass

    # HTTPS
    for p in _HTTPS_PORTS:
        if p in ports:
            try:
                _add_recon(result, recon.http_info(ip, p, use_tls=True))
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Orchestrazione completa
# ---------------------------------------------------------------------------

def full_scan(subnet, progress=None, log=None, stop_event=None):
    """
    Esegue una scansione completa di una subnet.
    Ritorna lista di HostResult (solo host con almeno una porta aperta o vivi).
    """
    if log:
        log("Ricerca host attivi su %s ..." % subnet)

    alive = discover_hosts(subnet, progress=progress, stop_event=stop_event)
    if log:
        log("Trovati %d host attivi." % len(alive))

    results = []
    total = len(alive)
    for i, ip in enumerate(alive, 1):
        if stop_event and stop_event.is_set():
            break
        if progress:
            progress(i, total, phase="scan")
        res = analyze_host(ip, stop_event=stop_event, log=log)
        results.append(res)
        if log:
            n = len(res.findings)
            log("  %s: %d porte aperte, %d osservazioni." % (ip, len(res.open_ports), n))

    # Ordina: host piu' a rischio in cima
    results.sort(key=lambda r: r.risk_score, reverse=True)
    return results
