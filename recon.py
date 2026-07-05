# -*- coding: utf-8 -*-
"""
recon.py - Modulo di enumerazione: "cosa si puo' ottenere dalle porte aperte".

Estrae informazioni REALI dai servizi esposti, in modo NON distruttivo e usando
solo la libreria standard di Python. Pensato per l'autovalutazione della propria
rete: mostra concretamente quali dati un attaccante potrebbe raccogliere.

Tecniche implementate:
  - NetBIOS  : query NBSTAT (UDP 137) -> nome host, dominio/workgroup, utente,
               MAC, presenza di condivisioni (come 'nbtstat -A')
  - SMB      : negoziazione SMBv1 (TCP 445/139) -> rileva SMBv1 abilitato
  - SNMP     : GET sysDescr con community 'public' (UDP 161)
  - HTTP(S)  : header Server, tecnologia, titolo pagina, login, versione TLS
"""

import socket
import ssl
import struct
import re


# ---------------------------------------------------------------------------
# Strutture risultato
# ---------------------------------------------------------------------------

class ReconItem:
    """Una informazione ricavata + eventuale segnalazione di rischio."""
    def __init__(self, source, lines, risk=None):
        self.source = source        # es. "NetBIOS", "SMB", "HTTP :80"
        self.lines = lines          # lista di stringhe leggibili
        # risk = (severity, issue, remediation, evidence) oppure None
        self.risk = risk


# ---------------------------------------------------------------------------
# NetBIOS  (UDP 137)  -  equivalente di "nbtstat -A <ip>"
# ---------------------------------------------------------------------------

# Significato del "suffisso" (ultimo byte) di un nome NetBIOS
_NB_SUFFIX = {
    0x00: "Workstation",
    0x03: "Messenger / utente",
    0x06: "RAS Server",
    0x1B: "Domain Master Browser",
    0x1C: "Domain Controller / gruppo dominio",
    0x1D: "Master Browser",
    0x1E: "Browser Election",
    0x20: "File/Print Server (condivisioni attive)",
    0x21: "RAS Client",
}


def nbstat(ip, timeout=2.0):
    """
    Interroga il name service NetBIOS (UDP 137).
    Ritorna un dict con le info ricavate, o None se l'host non risponde.
    """
    # --- costruzione query NBSTAT (node status request) ---
    tid = b"\x13\x37"
    header = tid + b"\x00\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    # nome "*" codificato (first-level encoding): '*' -> 'CK', poi 30 'A' (null)
    encoded_name = b"\x20" + b"CK" + b"A" * 30 + b"\x00"
    question = encoded_name + b"\x00\x21" + b"\x00\x01"  # type NBSTAT, class IN
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(2048)
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()

    try:
        return _parse_nbstat(data)
    except (IndexError, struct.error):
        return None


def _parse_nbstat(resp):
    if len(resp) < 57:
        return None
    ptr = 12                 # salta header
    ptr += 34                # salta il nome echeggiato (0x20 + 32 + 0x00)
    ptr += 2 + 2 + 4 + 2     # type, class, ttl, rdlength
    num = resp[ptr]
    ptr += 1

    names = []
    for _ in range(num):
        raw = resp[ptr:ptr + 15]
        suffix = resp[ptr + 15]
        flags = (resp[ptr + 16] << 8) | resp[ptr + 17]
        ptr += 18
        name = raw.decode("latin-1", errors="replace").rstrip(" \x00")
        is_group = bool(flags & 0x8000)
        names.append({"name": name, "suffix": suffix, "group": is_group})

    mac = ""
    if ptr + 6 <= len(resp):
        mac = ":".join("%02x" % b for b in resp[ptr:ptr + 6])
        if mac == "00:00:00:00:00:00":
            mac = ""

    info = {
        "computer": "",
        "domain": "",
        "user": "",
        "file_sharing": False,
        "mac": mac,
        "names": names,
    }
    for n in names:
        s = n["suffix"]
        if s == 0x00 and not n["group"] and not info["computer"]:
            info["computer"] = n["name"]
        if (s in (0x00, 0x1C, 0x1E, 0x1B)) and n["group"] and not info["domain"]:
            info["domain"] = n["name"]
        if s == 0x03 and n["name"] and n["name"] != info["computer"]:
            info["user"] = n["name"]
        if s == 0x20:
            info["file_sharing"] = True
    return info


def recon_netbios(ip):
    """Versione 'ReconItem' del NBSTAT, pronta per l'interfaccia."""
    info = nbstat(ip)
    if not info:
        return None
    lines = []
    if info["computer"]:
        lines.append("Nome computer: %s" % info["computer"])
    if info["domain"]:
        lines.append("Dominio/Workgroup: %s" % info["domain"])
    if info["user"]:
        lines.append("Nome/utente registrato: %s" % info["user"])
    if info["mac"]:
        lines.append("MAC address: %s" % info["mac"])
    if info["file_sharing"]:
        lines.append("Condivisioni file/stampa ATTIVE (suffisso <20>)")
    # dettaglio tabella nomi
    for n in info["names"]:
        tag = _NB_SUFFIX.get(n["suffix"], "?")
        kind = "GRUPPO" if n["group"] else "unico"
        lines.append("  • %-16s <%02X> %-7s %s" % (n["name"], n["suffix"], kind, tag))

    risk = None
    if info["file_sharing"]:
        risk = ("MEDIUM",
                "Il name service NetBIOS rivela nome host, dominio e l'esistenza "
                "di condivisioni: utile per la ricognizione e attacchi mirati.",
                "Disabilita NetBIOS over TCP/IP se non necessario; non esporlo "
                "verso reti non fidate.",
                "NetBIOS espone: " + ", ".join(
                    x for x in [info["computer"], info["domain"]] if x))
    return ReconItem("NetBIOS (UDP 137)", lines, risk), info


# ---------------------------------------------------------------------------
# SMB  (TCP 445/139)  -  rileva se SMBv1 e' abilitato
# ---------------------------------------------------------------------------

def smb_check_v1(ip, port=445, timeout=3.0):
    """
    Invia un Negotiate Protocol SMBv1 e verifica come risponde il server.
    Ritorna: "v1"  -> SMBv1 abilitato (rischio)
             "v2"  -> server SMB attivo ma risponde in SMBv2/3 (buono)
             None  -> nessuna risposta / non determinabile
    """
    dialects = b"".join(b"\x02" + d + b"\x00" for d in (
        b"PC NETWORK PROGRAM 1.0",
        b"LANMAN1.0",
        b"NT LM 0.12",
    ))
    smb_header = (
        b"\xffSMB"            # protocollo SMB
        b"\x72"               # comando: Negotiate Protocol
        b"\x00\x00\x00\x00"   # status
        b"\x18"               # flags
        b"\x01\x28"           # flags2
        b"\x00\x00"           # PID high
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # signature
        b"\x00\x00"           # reserved
        b"\x00\x00"           # TID
        b"\x2f\x4b"           # PID low
        b"\x00\x00"           # UID
        b"\xc5\x5e"           # MID
    )
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
    smb = smb_header + body
    netbios = b"\x00" + struct.pack(">I", len(smb))[1:]  # session header (3 byte len)
    packet = netbios + smb

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            s.sendall(packet)
            resp = s.recv(512)
    except OSError:
        return None

    if len(resp) < 9:
        return None
    if resp[4:8] == b"\xfeSMB" or resp[4:8] == b"\xfdSMB":
        return "v2"   # risposta SMB2/3 (transform) -> SMBv1 non usato
    if resp[4:8] != b"\xffSMB":
        return None
    # status DWORD a offset 9..13: 0 = OK (dialetto selezionato => SMBv1 attivo)
    status = resp[9:13]
    return "v1" if status == b"\x00\x00\x00\x00" else "v2"


def recon_smb(ip, port=445):
    v1 = smb_check_v1(ip, port)
    if v1 is None:
        return None
    if v1 == "v1":
        lines = ["SMBv1 (CIFS) ABILITATO sul servizio.",
                 "Condivisione file Windows raggiungibile in rete."]
        risk = ("CRITICAL",
                "SMBv1 e' un protocollo obsoleto e vulnerabile (EternalBlue / "
                "WannaCry). Abilitarlo espone a worm e ransomware.",
                "Disabilita SMBv1 (su Windows: 'Disinstalla SMB 1.0/CIFS'). "
                "Usa solo SMBv2/SMBv3 con firme abilitate.",
                "Il server ha negoziato un dialetto SMBv1")
        return ReconItem("SMB (porta %d)" % port, lines, risk)
    return ReconItem("SMB (porta %d)" % port,
                     ["Servizio SMB attivo, risponde in SMBv2/3 (SMBv1 non abilitato).",
                      "Condivisione file Windows raggiungibile in rete."], None)


# ---------------------------------------------------------------------------
# SNMP  (UDP 161)  -  GET sysDescr con community 'public'
# ---------------------------------------------------------------------------

def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag, value):
    return bytes([tag]) + _ber_len(len(value)) + value


def snmp_sysdescr(ip, community="public", timeout=1.5):
    """GET di sysDescr.0 (1.3.6.1.2.1.1.1.0). Ritorna la stringa o None."""
    version = _tlv(0x02, b"\x00")                  # SNMPv1
    comm = _tlv(0x04, community.encode())
    reqid = _tlv(0x02, b"\x2f")
    err = _tlv(0x02, b"\x00")
    erridx = _tlv(0x02, b"\x00")
    oid = _tlv(0x06, b"\x2b\x06\x01\x02\x01\x01\x01\x00")
    nullval = _tlv(0x05, b"")
    varbind = _tlv(0x30, oid + nullval)
    varlist = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, reqid + err + erridx + varlist)
    msg = _tlv(0x30, version + comm + pdu)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, (ip, 161))
        data, _ = sock.recvfrom(2048)
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()

    oid_bytes = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
    idx = data.find(oid_bytes)
    if idx < 0:
        return None
    p = idx + len(oid_bytes)
    if p >= len(data):
        return None
    tag = data[p]
    p += 1
    length = data[p]
    p += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[p:p + nbytes], "big")
        p += nbytes
    value = data[p:p + length]
    if tag == 0x04:
        return value.decode("latin-1", errors="replace").strip()
    return None


def recon_snmp(ip):
    desc = snmp_sysdescr(ip, "public")
    if not desc:
        return None
    lines = [
        "Community 'public' VALIDA (accesso in lettura SNMP).",
        "sysDescr: " + desc[:200],
    ]
    risk = ("HIGH",
            "SNMP risponde con la community di default 'public': espone "
            "informazioni dettagliate sul dispositivo (modello, OS, interfacce) "
            "e talvolta consente modifiche.",
            "Cambia le community di default, passa a SNMPv3 con autenticazione, "
            "limita l'accesso per IP o disabilita SNMP.",
            "sysDescr ottenuto con community 'public'")
    return ReconItem("SNMP (UDP 161)", lines, risk)


# ---------------------------------------------------------------------------
# HTTP / HTTPS
# ---------------------------------------------------------------------------

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def http_info(ip, port, use_tls=False, timeout=3.0):
    """Raccoglie header del server, tecnologia, titolo e info di login/TLS."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    tls_version = ""
    tls_cipher = ""
    chunks = b""
    try:
        if raw.connect_ex((ip, port)) != 0:
            raw.close()
            return None
        sock = raw
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)
            tls_version = sock.version() or ""
            cipher = sock.cipher()
            tls_cipher = cipher[0] if cipher else ""
        req = ("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Sentry-Scanner\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n" % ip)
        sock.sendall(req.encode())
        while len(chunks) < 16384:
            try:
                part = sock.recv(4096)
            except socket.timeout:
                break
            if not part:
                break
            chunks += part
        sock.close()
    except (OSError, ssl.SSLError):
        try:
            raw.close()
        except OSError:
            pass
        # Se almeno l'handshake TLS e' riuscito, riportiamo comunque l'info TLS
        if not (tls_version or chunks):
            return None

    head, _, _ = chunks.partition(b"\r\n\r\n")
    header_text = head.decode("latin-1", errors="replace")
    lines_in = header_text.split("\r\n")
    status = lines_in[0] if lines_in else ""
    headers = {}
    for ln in lines_in[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    out_lines = []
    if status:
        out_lines.append("Risposta: " + status)
    if use_tls:
        out_lines.append("TLS: %s  (%s)" % (tls_version or "?", tls_cipher or "?"))
    if "server" in headers:
        out_lines.append("Server: " + headers["server"])
    if "x-powered-by" in headers:
        out_lines.append("Tecnologia: " + headers["x-powered-by"])
    if "location" in headers:
        out_lines.append("Redirect a: " + headers["location"])
    if "www-authenticate" in headers:
        out_lines.append("Autenticazione richiesta: " + headers["www-authenticate"])

    title_m = _TITLE_RE.search(chunks)
    title = ""
    if title_m:
        title = title_m.group(1).decode("latin-1", errors="replace").strip()
        title = re.sub(r"\s+", " ", title)[:120]
        if title:
            out_lines.append("Titolo pagina: " + title)

    # Valutazione rischio
    risk = None
    weak_tls = use_tls and tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
    login_like = bool(re.search(r"login|admin|password|accedi|sign in",
                                (title + " " + headers.get("www-authenticate", "")),
                                re.IGNORECASE))
    if weak_tls:
        risk = ("HIGH",
                "Il server usa una versione TLS obsoleta (%s) considerata insicura."
                % tls_version,
                "Disabilita SSLv3/TLS 1.0/1.1; abilita solo TLS 1.2+.",
                "Handshake negoziato a " + tls_version)
    elif login_like and not use_tls:
        risk = ("MEDIUM",
                "Pannello di accesso/amministrazione servito in HTTP non cifrato: "
                "credenziali trasmesse in chiaro e a rischio intercettazione.",
                "Servi il pannello solo via HTTPS e limita l'accesso per IP.",
                ("Login rilevato: " + title) if title else "Pagina di login HTTP")
    elif login_like:
        risk = ("LOW",
                "Pannello di amministrazione raggiungibile: verifica che non usi "
                "credenziali di default.",
                "Cambia le credenziali di default e abilita autenticazione forte.",
                ("Login: " + title) if title else "Pagina di login")

    label = "HTTPS :%d" % port if use_tls else "HTTP :%d" % port
    if not out_lines:
        return None
    return ReconItem(label, out_lines, risk)


# ---------------------------------------------------------------------------
# MongoDB  (TCP 27017)  -  verifica REALE se l'accesso e' senza autenticazione
# ---------------------------------------------------------------------------

def _bson(fields):
    """Serializza un documento BSON minimale.
    fields = lista di (tipo, nome, valore_gia'_serializzato)."""
    body = b""
    for tag, name, value in fields:
        body += bytes([tag]) + name.encode() + b"\x00" + value
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _bson_int32(value):
    return struct.pack("<i", value)


def _bson_str(value):
    raw = value.encode()
    return struct.pack("<i", len(raw) + 1) + raw + b"\x00"


def _op_msg(doc, req_id=1):
    """Incapsula un documento BSON in un messaggio OP_MSG (opcode 2013)."""
    body = struct.pack("<I", 0) + b"\x00" + doc      # flagBits=0, section kind 0
    header = struct.pack("<iiii", 16 + len(body), req_id, 0, 2013)
    return header + body


def _recv_exact(sock, n):
    """Legge esattamente n byte (o meno se la connessione si chiude)."""
    buf = b""
    while len(buf) < n:
        try:
            part = sock.recv(n - len(buf))
        except socket.timeout:
            break
        if not part:
            break
        buf += part
    return buf


def _mongo_command(sock, name, req_id):
    """Invia un comando OP_MSG '{name:1, $db:admin}' e ritorna il BSON di risposta."""
    doc = _bson([(0x10, name, _bson_int32(1)), (0x02, "$db", _bson_str("admin"))])
    sock.sendall(_op_msg(doc, req_id))
    head = _recv_exact(sock, 4)
    if len(head) < 4:
        return b""
    length = struct.unpack("<i", head)[0]
    if length < 4 or length > 48 * 1024 * 1024:
        return b""
    rest = _recv_exact(sock, length - 4)
    full = head + rest
    # header(16) + flagBits(4) + section kind(1) = 21 byte prima del documento
    return full[21:] if len(full) > 21 else b""


def _bson_find_str(doc, key):
    """Estrae il valore di un campo stringa BSON (tipo 0x02) dato il nome."""
    marker = b"\x02" + key.encode() + b"\x00"
    idx = doc.find(marker)
    if idx < 0:
        return ""
    p = idx + len(marker)
    if p + 4 > len(doc):
        return ""
    strlen = struct.unpack("<i", doc[p:p + 4])[0]
    p += 4
    if strlen < 1 or p + strlen > len(doc):
        return ""
    return doc[p:p + strlen - 1].decode("latin-1", errors="replace")


_MONGO_AUTH_MARKERS = (b"requires authentication", b"not authorized",
                       b"Unauthorized", b"authentication", b"AuthenticationFailed")


def mongo_probe(ip, port=27017, timeout=2.5):
    """
    Interroga MongoDB col wire protocol (OP_MSG) per determinare se l'accesso
    e' senza autenticazione. Ritorna un ReconItem o None se non e' MongoDB.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            # 1) handshake 'hello': conferma che parliamo davvero con MongoDB
            hello = _mongo_command(s, "hello", 1)
            if not hello or not (b"maxWireVersion" in hello or
                                 b"isWritablePrimary" in hello or b"ismaster" in hello):
                return None
            # 2) buildInfo: versione (best-effort, puo' richiedere auth)
            version = _bson_find_str(_mongo_command(s, "buildInfo", 2), "version")
            # 3) listDatabases: richiede privilegi -> distingue no-auth da auth
            dbs = _mongo_command(s, "listDatabases", 3)
    except OSError:
        return None

    no_auth = bool(dbs) and b"totalSize" in dbs and not any(
        m in dbs for m in _MONGO_AUTH_MARKERS)
    auth_enabled = any(m in dbs for m in _MONGO_AUTH_MARKERS)

    lines = ["MongoDB raggiungibile in rete (handshake wire protocol riuscito)."]
    if version:
        lines.append("Versione server: " + version)

    if no_auth:
        lines.append("listDatabases ESEGUITO senza credenziali: accesso ai dati aperto.")
        risk = ("CRITICAL",
                "MongoDB accessibile SENZA autenticazione: lettura/scrittura di tutti "
                "i database e rischio concreto di data breach.",
                "Abilita l'autenticazione (--auth / security.authorization), crea "
                "utenti applicativi, bind su localhost e usa il firewall.",
                "listDatabases eseguito con successo senza credenziali")
        return ReconItem("MongoDB (porta %d)" % port, lines, risk)

    if auth_enabled:
        lines.append("L'autenticazione e' attiva (listDatabases negato senza credenziali).")
    else:
        lines.append("Stato autenticazione non determinabile con certezza.")
    return ReconItem("MongoDB (porta %d)" % port, lines, None)


# ---------------------------------------------------------------------------
# Banner generico (FTP/SSH/SMTP/Telnet ...)
# ---------------------------------------------------------------------------

def service_banner(ip, port, timeout=2.0):
    """Legge un banner testuale dal servizio (versione, prodotto)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            data = s.recv(256)
            text = data.decode("latin-1", errors="replace").strip()
            return text or None
    except OSError:
        return None
