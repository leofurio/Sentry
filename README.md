# 🛡️ Sentry — La sentinella della tua rete

Applicazione desktop (GUI) per **scansionare la tua rete locale** e individuare
servizi esposti e misconfigurazioni comuni da sanare. Scritta in **Python puro**
(solo libreria standard): nessuna installazione di pacchetti richiesta.

> ⚠️ **Uso responsabile.** Esegui la scansione **solo sulla tua rete** o dove hai
> autorizzazione esplicita. La scansione di reti altrui può essere illegale.

---

## Avvio

**Windows (modo semplice):** doppio click su `Sentry.bat`

**macOS (modo semplice):** doppio click su `Sentry.command`

**Da terminale:**
```bash
# macOS / Linux
python3 app.py

# Windows
python app.py
```

> Su macOS il comando è **`python3`**, non `python`: lanciare `python app.py`
> dà `command not found` e l'app non si apre.

Richiede **Python 3.8+** con **Tkinter**. Su Windows è incluso di serie; su macOS
e Linux può servire installarlo (es. `brew install python-tk` su macOS,
`sudo apt install python3-tk` su Debian/Ubuntu). L'app è cross-platform: rileva
il sistema operativo e adatta comandi (`ping`, `arp`) e font.

---

## Come si usa

1. All'avvio l'app rileva automaticamente la tua rete (es. `192.168.1.0/24`).
   Puoi sceglierne un'altra dal menu a tendina o digitarla a mano.
2. Premi **▶ Avvia scansione**. L'app:
   - cerca gli host attivi (ping + tabella ARP);
   - scansiona le porte comuni di ciascun host;
   - identifica i servizi (banner) ed esegue controlli di sicurezza mirati;
   - mostra i risultati ordinati per **gravità**.
3. Seleziona una riga per leggere **rischio** ed **azione di rimedio** consigliata.
4. **⤓ Esporta report HTML** per salvare un report navigabile da condividere.

Puoi interrompere in qualsiasi momento con **■ Stop**.

---

## Cosa controlla

- **Host discovery** della/e subnet locale/i (ping sweep parallelo + ARP).
- **Port scan TCP** non intrusivo (~49 porte comuni: web, DB, RDP, SMB, SSH...).
- **Identificazione servizi** tramite banner grabbing leggero.
- **Controlli attivi sicuri** su misconfigurazioni frequenti:
  - FTP con **accesso anonimo** attivo;
  - **Redis** esposto senza password;
  - **MongoDB** senza autenticazione (verifica reale via wire protocol:
    prova a eseguire `listDatabases` e distingue no-auth da auth attiva).
- Ogni risultato include **gravità** (CRITICAL → INFO), **descrizione del rischio**
  e **rimedio concreto**.

### ✔ Confermato vs Esposizione
Per evitare falsi allarmi, Sentry distingue due tipi di osservazione:

- **✔ Confermato** — una debolezza **verificata attivamente** sul servizio
  (FTP anonimo accettato, Redis/Mongo senza password, SMBv1 negoziato, community
  SNMP `public` valida, TLS obsoleto): è azionabile subito.
- **Esposizione** — la porta è aperta ma **non è stata provata** alcuna debolezza:
  va verificata, non è di per sé una vulnerabilità.

Riepilogo e report mostrano i due conteggi separati, così i problemi reali non si
perdono nel rumore delle porte semplicemente aperte.

### 🔎 Enumerazione — "cosa si può ottenere dalle porte aperte"
Oltre a elencare le porte, Sentry mostra **quali dati un attaccante può ricavare**
da ciascun servizio (le righe `🔎` nell'albero e nel report):

| Servizio | Informazioni estratte |
|---|---|
| **NetBIOS** (UDP 137) | nome computer, **dominio/workgroup**, utente, MAC, condivisioni attive (come `nbtstat -A`) |
| **SMB** (445/139) | rilevamento **SMBv1 abilitato** (rischio EternalBlue/WannaCry) |
| **SNMP** (UDP 161) | descrizione del dispositivo se la community `public` è valida |
| **HTTP/HTTPS** | header `Server`, tecnologia, **titolo pagina**, pannelli di login, **versione TLS** debole |
| **FTP/SSH/Telnet** | versione e banner del servizio |

### Livelli di gravità
| Livello | Significato |
|---|---|
| 🔴 CRITICAL | Esposizione grave, sfruttabile facilmente (es. RDP, SMB, Redis no-auth) |
| 🟠 HIGH | Servizio rischioso esposto (DB, SNMP, NFS...) |
| 🟡 MEDIUM | Da verificare/limitare |
| 🟢 LOW | Buona pratica di hardening |
| 🔵 INFO | Solo informativo |

---

## Note importanti

- **Una porta aperta non è di per sé una vulnerabilità.** Lo strumento evidenzia i
  servizi che, se mal configurati o non aggiornati, sono le cause più comuni di
  compromissione. Verifica sempre configurazione e patch dei servizi segnalati.
- I controlli sono **non distruttivi**: non vengono tentati attacchi, brute-force
  o exploit. Le sonde su FTP/Redis verificano solo se l'accesso è aperto.
- Per un'analisi più approfondita (CVE specifiche, fingerprint avanzato) si può in
  futuro integrare `nmap`. Questa versione è autosufficiente e non lo richiede.

---

## File del progetto

| File | Ruolo |
|---|---|
| `app.py` | Interfaccia grafica (Tkinter) |
| `scanner.py` | Motore: discovery, port scan, controlli |
| `recon.py` | Enumerazione servizi (NetBIOS, SMB, SNMP, HTTP/TLS) |
| `vuln_db.py` | Knowledge base porte/servizi + rimedi |
| `Sentry.bat` | Avvio rapido su Windows |
