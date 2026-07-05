# -*- coding: utf-8 -*-
"""
vuln_db.py - Knowledge base dei servizi/porte potenzialmente rischiosi.

Per ogni porta TCP "interessante" definiamo:
  - service:      nome del servizio tipico
  - severity:     CRITICAL / HIGH / MEDIUM / LOW / INFO
  - issue:        descrizione del rischio se la porta e' esposta in rete
  - remediation:  azioni concrete per sanare/mitigare

NB: l'esposizione di una porta NON e' di per se' una vulnerabilita'.
Lo strumento segnala servizi che, se raggiungibili e mal configurati,
sono le cause piu' comuni di compromissione su una rete domestica/PMI.
"""

# Livelli di severita' con un peso numerico (per ordinamento/score)
SEVERITY_WEIGHT = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

SEVERITY_COLOR = {
    "CRITICAL": "#b71c1c",
    "HIGH": "#e64a19",
    "MEDIUM": "#f9a825",
    "LOW": "#558b2f",
    "INFO": "#1565c0",
}

# Porte comuni che vale la pena scansionare (Standard)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 631, 993, 995, 1433, 1521, 1883, 1900, 2049, 2375,
    3000, 3306, 3389, 5000, 5060, 5432, 5601, 5900, 5985, 6379, 7547,
    8000, 8008, 8080, 8081, 8443, 8888, 9000, 9100, 9200, 11211, 27017,
]

# Mappa porta -> informazioni di rischio
PORT_DB = {
    21: {
        "service": "FTP",
        "severity": "HIGH",
        "issue": "FTP trasmette credenziali e dati in chiaro e spesso consente l'accesso anonimo.",
        "remediation": "Disabilita FTP o sostituiscilo con SFTP/FTPS. Disattiva l'accesso anonimo.",
    },
    22: {
        "service": "SSH",
        "severity": "LOW",
        "issue": "SSH esposto: rischio di brute-force se sono permesse password deboli o login di root.",
        "remediation": "Usa autenticazione a chiave, disabilita il login di root, limita l'accesso per IP, valuta fail2ban.",
    },
    23: {
        "service": "Telnet",
        "severity": "CRITICAL",
        "issue": "Telnet invia tutto (password incluse) in chiaro. Protocollo obsoleto e insicuro.",
        "remediation": "Disabilita Telnet immediatamente e usa SSH al suo posto.",
    },
    25: {
        "service": "SMTP",
        "severity": "MEDIUM",
        "issue": "Server mail esposto: rischio di open relay o invio di credenziali in chiaro.",
        "remediation": "Limita il relay, imponi TLS (STARTTLS) e autenticazione.",
    },
    53: {
        "service": "DNS",
        "severity": "MEDIUM",
        "issue": "DNS esposto puo' essere sfruttato per amplification DDoS o cache poisoning.",
        "remediation": "Disabilita la ricorsione aperta verso l'esterno; esponilo solo sulla LAN.",
    },
    110: {
        "service": "POP3",
        "severity": "MEDIUM",
        "issue": "POP3 in chiaro espone le credenziali della posta.",
        "remediation": "Usa POP3S (995) con TLS o passa a IMAPS.",
    },
    111: {
        "service": "RPCbind",
        "severity": "MEDIUM",
        "issue": "Portmapper RPC esposto: utile per la ricognizione e attacchi NFS.",
        "remediation": "Blocca verso l'esterno; esponi solo internamente se strettamente necessario.",
    },
    135: {
        "service": "MS RPC",
        "severity": "MEDIUM",
        "issue": "Endpoint mapper RPC Windows: vettore comune per movimenti laterali.",
        "remediation": "Blocca 135 dal traffico non fidato tramite il firewall di Windows.",
    },
    139: {
        "service": "NetBIOS",
        "severity": "HIGH",
        "issue": "NetBIOS/SMB legacy: information disclosure e vettore di attacchi datati.",
        "remediation": "Disabilita NetBIOS over TCP/IP; usa solo SMBv2/3 e blocca dall'esterno.",
    },
    143: {
        "service": "IMAP",
        "severity": "MEDIUM",
        "issue": "IMAP in chiaro espone le credenziali della posta.",
        "remediation": "Usa IMAPS (993) con TLS.",
    },
    161: {
        "service": "SNMP",
        "severity": "HIGH",
        "issue": "SNMP usa spesso community string di default ('public'/'private') e v1/v2c senza cifratura.",
        "remediation": "Passa a SNMPv3 con autenticazione, cambia le community, limita per IP.",
    },
    389: {
        "service": "LDAP",
        "severity": "MEDIUM",
        "issue": "LDAP in chiaro puo' esporre dati di directory e credenziali.",
        "remediation": "Imponi LDAPS/StartTLS e limita l'accesso.",
    },
    443: {
        "service": "HTTPS",
        "severity": "INFO",
        "issue": "Servizio web cifrato. Verifica validita' del certificato e versioni TLS.",
        "remediation": "Mantieni TLS 1.2+, certificati validi, e aggiorna l'applicazione web.",
    },
    445: {
        "service": "SMB",
        "severity": "CRITICAL",
        "issue": "Condivisione file SMB esposta: bersaglio di EternalBlue/WannaCry e ransomware.",
        "remediation": "Non esporre SMB in rete non fidata. Disabilita SMBv1, applica le patch, usa il firewall.",
    },
    465: {
        "service": "SMTPS",
        "severity": "INFO",
        "issue": "SMTP su TLS. Verifica configurazione e autenticazione.",
        "remediation": "Mantieni TLS aggiornato e autenticazione obbligatoria.",
    },
    514: {
        "service": "Syslog",
        "severity": "LOW",
        "issue": "Syslog esposto puo' ricevere log falsificati o perdere informazioni.",
        "remediation": "Limita le sorgenti consentite e usa TLS dove possibile.",
    },
    587: {
        "service": "SMTP (submission)",
        "severity": "LOW",
        "issue": "Porta di submission mail: deve sempre richiedere autenticazione+TLS.",
        "remediation": "Imponi STARTTLS e autenticazione.",
    },
    631: {
        "service": "IPP/CUPS",
        "severity": "MEDIUM",
        "issue": "Servizio di stampa esposto: in passato afflitto da RCE (es. CUPS 2024).",
        "remediation": "Aggiorna CUPS, limita l'accesso alla LAN, disabilita se non serve.",
    },
    993: {
        "service": "IMAPS",
        "severity": "INFO",
        "issue": "IMAP su TLS. Configurazione corretta consigliata.",
        "remediation": "Mantieni TLS aggiornato.",
    },
    995: {
        "service": "POP3S",
        "severity": "INFO",
        "issue": "POP3 su TLS.",
        "remediation": "Mantieni TLS aggiornato.",
    },
    1433: {
        "service": "MS SQL Server",
        "severity": "HIGH",
        "issue": "Database SQL Server esposto: bersaglio di brute-force e password 'sa' deboli.",
        "remediation": "Non esporre il DB in rete; usa password robuste, firewall e cifratura.",
    },
    1521: {
        "service": "Oracle DB",
        "severity": "HIGH",
        "issue": "Listener Oracle esposto: ricognizione ed eventuale accesso non autorizzato.",
        "remediation": "Limita l'accesso al listener, usa password robuste e cifratura.",
    },
    1883: {
        "service": "MQTT",
        "severity": "HIGH",
        "issue": "Broker MQTT (IoT) spesso senza autenticazione: controllo di dispositivi e dati esposti.",
        "remediation": "Abilita autenticazione+TLS, limita topic e accesso per IP.",
    },
    1900: {
        "service": "UPnP/SSDP",
        "severity": "MEDIUM",
        "issue": "UPnP puo' aprire porte automaticamente sul router e abilitare amplification DDoS.",
        "remediation": "Disabilita UPnP sul router se non strettamente necessario.",
    },
    2049: {
        "service": "NFS",
        "severity": "HIGH",
        "issue": "Condivisione NFS esposta: spesso senza autenticazione adeguata.",
        "remediation": "Limita gli export per host, usa NFSv4 con Kerberos, firewall.",
    },
    2375: {
        "service": "Docker API",
        "severity": "CRITICAL",
        "issue": "API Docker non cifrata: equivale a root sull'host: takeover completo.",
        "remediation": "Non esporre mai 2375. Usa il socket locale o TLS mutuo (2376) con accesso ristretto.",
    },
    3000: {
        "service": "App web (dev)",
        "severity": "LOW",
        "issue": "Porta di sviluppo (Node/Grafana): possibili pannelli senza autenticazione.",
        "remediation": "Non esporre ambienti di sviluppo; aggiungi autenticazione.",
    },
    3306: {
        "service": "MySQL/MariaDB",
        "severity": "HIGH",
        "issue": "Database esposto: brute-force e talvolta accesso senza password.",
        "remediation": "Bind su localhost, password robuste, firewall, niente utenti anonimi.",
    },
    3389: {
        "service": "RDP",
        "severity": "CRITICAL",
        "issue": "Desktop Remoto esposto: bersaglio principale di ransomware (brute-force, BlueKeep).",
        "remediation": "Non esporre RDP a Internet; usa VPN/Network Level Authentication, MFA, patch.",
    },
    5000: {
        "service": "App web (dev/UPnP)",
        "severity": "LOW",
        "issue": "Porta usata da app di sviluppo e alcuni servizi: possibili interfacce non protette.",
        "remediation": "Verifica cosa risponde; aggiungi autenticazione o chiudi.",
    },
    5060: {
        "service": "SIP/VoIP",
        "severity": "MEDIUM",
        "issue": "Centralino VoIP esposto: toll fraud e brute-force degli interni.",
        "remediation": "Limita per IP, password robuste, fail2ban, aggiorna il PBX.",
    },
    5432: {
        "service": "PostgreSQL",
        "severity": "HIGH",
        "issue": "Database PostgreSQL esposto: brute-force e configurazioni 'trust' insicure.",
        "remediation": "Bind su localhost, pg_hba.conf restrittivo, password robuste, firewall.",
    },
    5601: {
        "service": "Kibana",
        "severity": "HIGH",
        "issue": "Kibana spesso senza autenticazione: accesso completo ai dati Elasticsearch.",
        "remediation": "Abilita la sicurezza dello stack Elastic e limita l'accesso.",
    },
    5900: {
        "service": "VNC",
        "severity": "CRITICAL",
        "issue": "VNC spesso senza password o con password deboli: controllo remoto totale.",
        "remediation": "Disabilita VNC o usalo solo via VPN, con password forte e cifratura.",
    },
    5985: {
        "service": "WinRM",
        "severity": "HIGH",
        "issue": "Gestione remota Windows esposta: vettore di movimento laterale.",
        "remediation": "Limita WinRM alla rete di gestione, usa HTTPS e autenticazione robusta.",
    },
    6379: {
        "service": "Redis",
        "severity": "CRITICAL",
        "issue": "Redis di default NON ha autenticazione: lettura/scrittura dati e spesso RCE.",
        "remediation": "Imposta 'requirepass', bind su localhost, abilita protected-mode, firewall.",
    },
    7547: {
        "service": "TR-069 (CWMP)",
        "severity": "HIGH",
        "issue": "Gestione remota del router/modem: storicamente sfruttata in massa (Mirai).",
        "remediation": "Disabilita la gestione remota dal lato WAN; aggiorna il firmware.",
    },
    8000: {
        "service": "HTTP alternativo",
        "severity": "LOW",
        "issue": "Servizio web su porta alternativa: possibili pannelli admin senza HTTPS.",
        "remediation": "Verifica autenticazione e passa a HTTPS.",
    },
    8008: {
        "service": "HTTP alternativo",
        "severity": "LOW",
        "issue": "Servizio web/IoT su porta alternativa.",
        "remediation": "Verifica autenticazione e cifratura.",
    },
    8080: {
        "service": "HTTP-proxy/admin",
        "severity": "MEDIUM",
        "issue": "Pannelli di amministrazione e proxy spesso esposti senza HTTPS o con credenziali di default.",
        "remediation": "Aggiungi autenticazione forte, HTTPS e limita l'accesso.",
    },
    8081: {
        "service": "HTTP alternativo",
        "severity": "LOW",
        "issue": "Servizio web su porta alternativa.",
        "remediation": "Verifica autenticazione e cifratura.",
    },
    8443: {
        "service": "HTTPS alternativo",
        "severity": "LOW",
        "issue": "Pannello di amministrazione su HTTPS: verifica credenziali e patch.",
        "remediation": "Cambia le credenziali di default e aggiorna l'applicazione.",
    },
    8888: {
        "service": "HTTP (Jupyter/dev)",
        "severity": "MEDIUM",
        "issue": "Jupyter e tool simili possono esporre esecuzione di codice senza token.",
        "remediation": "Richiedi token/password, non esporre in rete non fidata.",
    },
    9000: {
        "service": "App web (Portainer/PHP-FPM)",
        "severity": "MEDIUM",
        "issue": "Pannelli (es. Portainer) o PHP-FPM esposti: possibile controllo di container o RCE.",
        "remediation": "Aggiungi autenticazione e limita l'accesso alla rete di gestione.",
    },
    9100: {
        "service": "Stampante (RAW/JetDirect)",
        "severity": "MEDIUM",
        "issue": "Porta di stampa esposta: invio di job arbitrari e exfiltrazione.",
        "remediation": "Limita l'accesso alla LAN, aggiorna il firmware della stampante.",
    },
    9200: {
        "service": "Elasticsearch",
        "severity": "CRITICAL",
        "issue": "Elasticsearch di default senza autenticazione: data breach e RCE noti.",
        "remediation": "Abilita la sicurezza Elastic, bind su localhost, firewall.",
    },
    11211: {
        "service": "Memcached",
        "severity": "CRITICAL",
        "issue": "Memcached senza autenticazione: data leak e amplification DDoS enorme.",
        "remediation": "Bind su localhost, disabilita UDP, firewall.",
    },
    27017: {
        "service": "MongoDB",
        "severity": "CRITICAL",
        "issue": "MongoDB storicamente esposto senza autenticazione: data breach di massa.",
        "remediation": "Abilita autenticazione, bind su localhost, firewall.",
    },
}


def get_port_info(port):
    """Ritorna le info di rischio per una porta, o un default generico."""
    return PORT_DB.get(port, {
        "service": "Sconosciuto",
        "severity": "INFO",
        "issue": "Porta aperta non classificata. Verifica quale servizio risponde.",
        "remediation": "Identifica il servizio e chiudi la porta se non necessaria.",
    })
