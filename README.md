# 🛡️ Sentry — La sentinella della tua rete

Applicazione desktop (GUI) per **scansionare la tua rete locale** e individuare
servizi esposti e misconfigurazioni comuni da sanare. Scritta in **Python puro**
(solo libreria standard): nessuna installazione di pacchetti richiesta.

> ⚠️ **Uso responsabile.** Esegui la scansione **solo sulla tua rete** o dove hai
> autorizzazione esplicita. La scansione di reti altrui può essere illegale.

---

## Avvio

**Modo semplice:** doppio click su `Sentry.bat`

**Da terminale:**
```powershell
python app.py
```

Richiede Python 3.8+ (testato su 3.14) con Tkinter, incluso di serie in Windows.

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
  - **Telnet** in chiaro raggiungibile;
  - **MongoDB** raggiungibile in rete.
- Ogni risultato include **gravità** (CRITICAL → INFO), **descrizione del rischio**
  e **rimedio concreto**.

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
| `vuln_db.py` | Knowledge base porte/servizi + rimedi |
| `Sentry.bat` | Avvio rapido su Windows |
