# -*- coding: utf-8 -*-
"""
app.py - Interfaccia grafica (Tkinter) del Network Vulnerability Checker.

Avvio:
    python app.py

Solo libreria standard di Python. Pensato per scansionare LA PROPRIA rete.
"""

import threading
import datetime
import webbrowser
import os
import html
import ipaddress
import platform
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import scanner
from vuln_db import SEVERITY_COLOR, SEVERITY_WEIGHT


APP_TITLE = "Sentry — Network Vulnerability Checker"


def _ui_font(size, bold=False):
    """Font proporzionale adatto alla piattaforma (Segoe UI e' solo Windows)."""
    system = platform.system()
    if system == "Windows":
        family = "Segoe UI"
    elif system == "Darwin":
        family = "Helvetica Neue"
    else:
        family = "DejaVu Sans"
    return (family, size, "bold") if bold else (family, size)


def _mono_font(size):
    """Font monospazio adatto alla piattaforma."""
    system = platform.system()
    if system == "Windows":
        return ("Consolas", size)
    if system == "Darwin":
        return ("Menlo", size)
    return ("DejaVu Sans Mono", size)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1000x680")
        self.minsize(840, 560)

        self.stop_event = threading.Event()
        self.scan_thread = None
        self.results = []          # lista di HostResult
        self._row_to_finding = {}  # id riga albero -> (host, finding)
        self._row_to_recon = {}    # id riga albero -> (host, ReconItem)

        self._build_ui()
        self._populate_subnets()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=24)
        style.configure("Header.TLabel", font=_ui_font(14, bold=True))

        # --- Intestazione marchio ----------------------------------------
        header = tk.Frame(self, background="#1565c0")
        header.pack(fill="x")
        tk.Label(header, text="🛡️  Sentry", background="#1565c0",
                 foreground="#ffffff", font=_ui_font(16, bold=True),
                 padx=14, pady=8).pack(side="left")
        tk.Label(header, text="La sentinella della tua rete", background="#1565c0",
                 foreground="#cfe0f5", font=_ui_font(10)).pack(side="left", pady=(2, 0))

        # --- Barra superiore ---------------------------------------------
        top = ttk.Frame(self, padding=(12, 10))
        top.pack(fill="x")

        ttk.Label(top, text="Rete da scansionare:").pack(side="left")
        self.subnet_var = tk.StringVar()
        self.subnet_combo = ttk.Combobox(top, textvariable=self.subnet_var, width=26)
        self.subnet_combo.pack(side="left", padx=(6, 12))

        self.scan_btn = ttk.Button(top, text="▶  Avvia scansione", command=self.start_scan)
        self.scan_btn.pack(side="left")

        self.stop_btn = ttk.Button(top, text="■  Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=(6, 0))

        self.report_btn = ttk.Button(top, text="⤓  Esporta report HTML",
                                     command=self.export_report, state="disabled")
        self.report_btn.pack(side="right")

        # --- Barra di stato / progresso ----------------------------------
        prog = ttk.Frame(self, padding=(12, 0))
        prog.pack(fill="x")
        self.progress = ttk.Progressbar(prog, mode="determinate")
        self.progress.pack(fill="x", side="left", expand=True)
        self.status_var = tk.StringVar(value="Pronto.")
        ttk.Label(prog, textvariable=self.status_var, width=40,
                  anchor="e").pack(side="right", padx=(10, 0))

        # --- Riepilogo severita' -----------------------------------------
        self.summary_var = tk.StringVar(value="")
        summ = ttk.Label(self, textvariable=self.summary_var, padding=(14, 6),
                         font=_ui_font(10))
        summ.pack(fill="x")

        # --- Area centrale: albero risultati + dettaglio -----------------
        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        tree_frame = ttk.Frame(paned)
        paned.add(tree_frame, weight=3)

        cols = ("severity", "service", "port", "issue")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="tree headings",
                                 selectmode="browse")
        self.tree.heading("#0", text="Host")
        self.tree.heading("severity", text="Gravità")
        self.tree.heading("service", text="Servizio")
        self.tree.heading("port", text="Porta")
        self.tree.heading("issue", text="Rischio")
        self.tree.column("#0", width=230, anchor="w")
        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("service", width=140, anchor="w")
        self.tree.column("port", width=60, anchor="center")
        self.tree.column("issue", width=420, anchor="w")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        for sev, color in SEVERITY_COLOR.items():
            self.tree.tag_configure(sev, foreground=color)

        # Pannello dettaglio
        detail_frame = ttk.LabelFrame(paned, text="Dettaglio e rimedio", padding=8)
        paned.add(detail_frame, weight=1)
        self.detail = tk.Text(detail_frame, height=8, wrap="word",
                              font=_ui_font(10), state="disabled",
                              background="#fbfbfb")
        self.detail.pack(fill="both", expand=True)

        # --- Diario in basso ---------------------------------------------
        log_frame = ttk.LabelFrame(self, text="Diario", padding=6)
        log_frame.pack(fill="x", padx=12, pady=(0, 10))
        self.log_text = tk.Text(log_frame, height=6, wrap="word",
                                font=_mono_font(9), state="disabled",
                                background="#1e1e1e", foreground="#d4d4d4")
        self.log_text.pack(fill="both", expand=True)

        # Disclaimer
        ttk.Label(self,
                  text="Usa questo strumento solo sulla TUA rete o con autorizzazione esplicita.",
                  foreground="#888", padding=(12, 0, 12, 8)).pack(fill="x")

    # ------------------------------------------------------------- helpers
    def _populate_subnets(self):
        subnets = scanner.get_local_subnets()
        values = [str(s) for s in subnets]
        self.subnet_combo["values"] = values
        if values:
            self.subnet_var.set(values[0])
        else:
            self.subnet_var.set("192.168.1.0/24")

    def log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        def _append():
            self.log_text.configure(state="normal")
            self.log_text.insert("end", "[%s] %s\n" % (ts, msg))
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.after(0, _append)

    def set_status(self, text):
        self.after(0, lambda: self.status_var.set(text))

    def set_progress(self, value, maximum):
        def _upd():
            self.progress["maximum"] = maximum if maximum > 0 else 1
            self.progress["value"] = value
        self.after(0, _upd)

    # --------------------------------------------------------------- scan
    def start_scan(self):
        text = self.subnet_var.get().strip()
        try:
            subnet = ipaddress.ip_network(text, strict=False)
        except ValueError:
            messagebox.showerror(APP_TITLE,
                                 "Rete non valida.\nEsempio: 192.168.1.0/24")
            return
        if subnet.num_addresses > 4096:
            if not messagebox.askyesno(APP_TITLE,
                    "La rete selezionata ha %d indirizzi: la scansione potrebbe "
                    "essere molto lenta.\nContinuare?" % subnet.num_addresses):
                return

        # Reset UI
        self.tree.delete(*self.tree.get_children())
        self._row_to_finding.clear()
        self._row_to_recon.clear()
        self.results = []
        self.summary_var.set("")
        self._set_detail("Seleziona una riga per vedere il dettaglio e il rimedio consigliato.")
        self.stop_event.clear()

        self.scan_btn.configure(state="disabled")
        self.report_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.set_status("Scansione in corso...")

        self.scan_thread = threading.Thread(target=self._run_scan, args=(subnet,), daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        self.stop_event.set()
        self.set_status("Interruzione in corso...")
        self.log("Richiesta interruzione dall'utente.")

    def _progress_cb(self, done, total, phase="discovery"):
        self.set_progress(done, total)
        if phase == "discovery":
            self.set_status("Ricerca host: %d / %d" % (done, total))
        else:
            self.set_status("Analisi host: %d / %d" % (done, total))

    def _run_scan(self, subnet):
        start = datetime.datetime.now()
        try:
            results = scanner.full_scan(
                subnet,
                progress=self._progress_cb,
                log=self.log,
                stop_event=self.stop_event,
            )
            self.results = results
            self.after(0, lambda: self._render_results(results))
        except Exception as exc:  # pragma: no cover - robustezza UI
            self.log("ERRORE: %s" % exc)
            self.after(0, lambda: messagebox.showerror(APP_TITLE, "Errore: %s" % exc))
        finally:
            elapsed = (datetime.datetime.now() - start).total_seconds()
            self.log("Scansione terminata in %.1f s." % elapsed)
            self.after(0, self._scan_done)

    def _scan_done(self):
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        if self.results:
            self.report_btn.configure(state="normal")
        self.set_status("Completato.")

    # ------------------------------------------------------------ render
    def _render_results(self, results):
        self.tree.delete(*self.tree.get_children())
        self._row_to_finding.clear()
        self._row_to_recon.clear()

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        confirmed_count = 0

        for host in results:
            label = host.ip
            if host.hostname:
                label += "  (%s)" % host.hostname
            top_sev = host.max_severity or "INFO"
            n = len(host.findings)
            host_node = self.tree.insert(
                "", "end",
                text=label,
                values=(top_sev if n else "—",
                        "%d porte" % len(host.open_ports),
                        "",
                        "%d osservazioni" % n),
                tags=(top_sev,),
                open=(SEVERITY_WEIGHT.get(top_sev, 0) >= 4),
            )
            for f in host.findings:
                counts[f.severity] += 1
                # Distingue una debolezza CONFERMATA da una semplice esposizione,
                # cosi' i risultati davvero azionabili non si perdono nel rumore.
                if f.confirmed:
                    confirmed_count += 1
                    sev_label = "✔ " + f.severity
                    issue_label = f.issue
                else:
                    sev_label = f.severity
                    issue_label = "[esposizione] " + f.issue
                row = self.tree.insert(
                    host_node, "end",
                    text="",
                    values=(sev_label, f.service,
                            f.port if f.port else "—", issue_label),
                    tags=(f.severity,),
                )
                self._row_to_finding[row] = (host, f)

            # Righe "Cosa si puo' ottenere" (enumerazione)
            for item in host.recon:
                preview = item.lines[0] if item.lines else ""
                row = self.tree.insert(
                    host_node, "end",
                    text="",
                    values=("INFO", "🔎 " + item.source, "",
                            "Info ricavabili: " + preview),
                    tags=("INFO",),
                )
                self._row_to_recon[row] = (host, item)

        total_find = sum(counts.values())
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if counts[sev]:
                parts.append("%s: %d" % (sev, counts[sev]))
        summary = ("Host analizzati: %d   |   Osservazioni: %d   "
                   "(✔ confermate: %d · esposizioni: %d)"
                   % (len(results), total_find,
                      confirmed_count, total_find - confirmed_count))
        if parts:
            summary += "   |   " + "   ".join(parts)
        self.summary_var.set(summary)

        if not results:
            self.log("Nessun host attivo trovato (o scansione interrotta).")

    def _set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def on_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        row = sel[0]
        if row in self._row_to_recon:
            host, item = self._row_to_recon[row]
            lines = [
                "Host:    %s%s" % (host.ip, "  (%s)" % host.hostname if host.hostname else ""),
                "Fonte:   %s" % item.source,
                "",
                "🔎 Informazioni che si possono ottenere:",
            ]
            lines += ["    " + ln for ln in item.lines]
            if item.risk:
                sev, issue, remediation, _ev = item.risk
                lines += ["", "⚠️  Rischio (%s):" % sev, "    " + issue,
                          "", "Rimedio consigliato:", "    " + remediation]
            self._set_detail("\n".join(lines))
            return
        if row in self._row_to_finding:
            host, f = self._row_to_finding[row]
            port_txt = ("%d  (%s)" % (f.port, f.service)) if f.port else \
                       ("enumerazione (%s)" % f.service)
            if f.confirmed:
                tipo = "✔ CONFERMATO (verifica attiva del servizio)"
            else:
                tipo = "Esposizione — porta aperta, debolezza NON verificata"
            lines = [
                "Host:        %s%s" % (host.ip, "  (%s)" % host.hostname if host.hostname else ""),
                "MAC:         %s" % (host.mac or "n/d"),
                "Porta:       %s" % port_txt,
                "Gravità:     %s" % f.severity,
                "Tipo:        %s" % tipo,
                "",
                "Rischio:",
                "  %s" % f.issue,
                "",
                "Rimedio consigliato:",
                "  %s" % f.remediation,
            ]
            if f.evidence:
                lines += ["", "Evidenza:", "  %s" % f.evidence]
            self._set_detail("\n".join(lines))
        else:
            # Nodo host: mostra riepilogo
            for host in self.results:
                label_ip = self.tree.item(row, "text").split(" ")[0]
                if host.ip == label_ip:
                    ports = ", ".join(str(p) for p in host.open_ports) or "nessuna"
                    self._set_detail(
                        "Host: %s%s\nMAC: %s\nPorte aperte: %s\nOsservazioni: %d"
                        % (host.ip,
                           "  (%s)" % host.hostname if host.hostname else "",
                           host.mac or "n/d", ports, len(host.findings)))
                    break

    # ------------------------------------------------------------ report
    def export_report(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("Report HTML", "*.html")],
            initialfile="network_report_%s.html" %
                        datetime.datetime.now().strftime("%Y%m%d_%H%M"),
            title="Salva report",
        )
        if not path:
            return
        try:
            html_content = self._build_report_html()
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(html_content)
            self.log("Report salvato: %s" % path)
            if messagebox.askyesno(APP_TITLE, "Report salvato.\nVuoi aprirlo nel browser?"):
                webbrowser.open("file://" + os.path.abspath(path))
        except OSError as exc:
            messagebox.showerror(APP_TITLE, "Impossibile salvare: %s" % exc)

    def _build_report_html(self):
        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        confirmed_count = 0
        for h in self.results:
            for f in h.findings:
                counts[f.severity] += 1
                if f.confirmed:
                    confirmed_count += 1
        total_find = sum(counts.values())

        rows = []
        for host in self.results:
            hdr = html.escape(host.ip)
            if host.hostname:
                hdr += " (%s)" % html.escape(host.hostname)
            mac = html.escape(host.mac or "n/d")
            ports = ", ".join(str(p) for p in host.open_ports) or "nessuna"
            rows.append(
                '<tr class="host"><td colspan="5"><b>%s</b> &nbsp; '
                'MAC: %s &nbsp; Porte aperte: %s</td></tr>'
                % (hdr, mac, html.escape(ports)))
            if not host.findings:
                rows.append('<tr><td colspan="5"><i>Nessuna osservazione.</i></td></tr>')
            for f in host.findings:
                color = SEVERITY_COLOR.get(f.severity, "#000")
                port_txt = str(f.port) if f.port else "—"
                if f.confirmed:
                    tag = '<span class="tag tag-conf">✔ CONFERMATO</span>'
                else:
                    tag = '<span class="tag tag-exp">esposizione</span>'
                rows.append(
                    '<tr>'
                    '<td><span class="badge" style="background:%s">%s</span> %s</td>'
                    '<td>%s</td><td>%s</td><td>%s<br><small>%s</small></td>'
                    '<td>%s</td>'
                    '</tr>' % (
                        color, f.severity, tag, port_txt,
                        html.escape(f.service),
                        html.escape(f.issue),
                        html.escape(f.evidence) if f.evidence else "",
                        html.escape(f.remediation),
                    ))
            # Sezione "Cosa si puo' ottenere" (enumerazione)
            for item in host.recon:
                body = "<br>".join(html.escape(ln) for ln in item.lines)
                rows.append(
                    '<tr class="recon"><td>🔎 INFO</td>'
                    '<td>—</td><td>%s</td>'
                    '<td colspan="2"><b>Info ricavabili</b><br>%s</td></tr>'
                    % (html.escape(item.source), body))

        chips = " ".join(
            '<span class="chip" style="background:%s">%s: %d</span>'
            % (SEVERITY_COLOR[s], s, counts[s])
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts[s]
        )
        chips = ('<span class="chip" style="background:#2e7d32">'
                 '✔ Confermate: %d</span> '
                 '<span class="chip" style="background:#607d8b">'
                 'Esposizioni: %d</span> ' % (
                     confirmed_count, total_find - confirmed_count)) + chips

        return """<!DOCTYPE html>
<html lang="it"><head><meta charset="utf-8">
<title>Sentry — Network Report</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f8;color:#222}
 header{background:#1565c0;color:#fff;padding:24px 32px}
 header h1{margin:0;font-size:22px}
 header p{margin:4px 0 0;opacity:.9;font-size:13px}
 .wrap{padding:24px 32px}
 .chip,.badge{color:#fff;border-radius:12px;padding:3px 10px;font-size:12px;font-weight:600}
 .chips{margin:0 0 18px;line-height:2}
 .tag{font-size:10px;font-weight:700;border-radius:8px;padding:1px 6px;vertical-align:middle}
 .tag-conf{background:#2e7d32;color:#fff}
 .tag-exp{background:#eceff1;color:#607d8b;border:1px solid #cfd8dc}
 table{width:100%%;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1)}
 th,td{padding:9px 12px;text-align:left;border-bottom:1px solid #eee;font-size:13px;vertical-align:top}
 th{background:#fafafa;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#555}
 tr.host td{background:#eef3f8;font-size:13px}
 tr.recon td{background:#f3f9f3;font-size:12px;color:#33691e}
 small{color:#777}
 footer{padding:18px 32px;color:#999;font-size:12px}
</style></head>
<body>
<header>
 <h1>🛡️ Sentry — Network Report</h1>
 <p>La sentinella della tua rete &middot; Generato il %s &middot; Host analizzati: %d</p>
</header>
<div class="wrap">
 <div class="chips">%s</div>
 <p style="font-size:12px;color:#555;margin:0 0 16px">
  <b>✔ Confermato</b>: debolezza verificata attivamente sul servizio
  (es. accesso senza password, SMBv1, community SNMP di default).
  <b>Esposizione</b>: la porta è aperta ma non è stata provata alcuna
  debolezza concreta — da verificare, non necessariamente vulnerabile.
 </p>
 <table>
  <thead><tr><th>Gravità</th><th>Porta</th><th>Servizio</th>
  <th>Rischio / Evidenza</th><th>Rimedio consigliato</th></tr></thead>
  <tbody>
  %s
  </tbody>
 </table>
</div>
<footer>Strumento di autovalutazione. Le porte aperte non sono di per sé
 vulnerabilità: verifica configurazione e patch dei servizi segnalati.</footer>
</body></html>""" % (now, len(self.results), chips, "\n".join(rows))


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
