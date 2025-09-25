import json, re, time, queue, threading
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox

from .. import APP_NAME, VERSION
from ..utils import normalize_target
from ..config import set_proxy, set_anonymise, get_anonymise
from ..recon_core import run_recon
from .help_text import HELP_TEXT

class ReconApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")  # gentle green

        self.title(f"{APP_NAME} (OSINT)")
        try:
            self.iconphoto(False, tk.PhotoImage(file="recon.png"))
        except Exception:
            pass

        self.geometry("1120x780"); self.minsize(1020,680)

        self._recon_thread = None
        self._results = None
        self._log_queue = queue.Queue()

        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        self.sidebar = self._build_sidebar(self); self.sidebar.grid(row=0, column=0, sticky="nsw", padx=12, pady=12)
        self.main = self._build_main(self); self.main.grid(row=0, column=1, sticky="nsew", padx=(0,12), pady=12)

        self.after(120, self._drain_log_queue)

    # ---------- UI ----------
    def _build_sidebar(self, parent):
        frame = ctk.CTkFrame(parent, width=330, corner_radius=16)
        frame.grid_propagate(False); frame.columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Options", font=("Inter", 18, "bold")).grid(row=0, column=0, sticky="w", padx=12, pady=(12,6))

        self.entry_target = ctk.CTkEntry(frame, placeholder_text="Target (domain, IP or full URL)")
        self.entry_target.grid(row=1, column=0, padx=12, pady=6, sticky="ew")

        self.chk_bruteforce = ctk.CTkCheckBox(frame, text="Small subdomain brute (active)")
        self.chk_bruteforce.grid(row=2, column=0, padx=12, pady=4, sticky="w")

        self.chk_axfr = ctk.CTkCheckBox(frame, text="Try DNS AXFR (active)")
        self.chk_axfr.grid(row=3, column=0, padx=12, pady=4, sticky="w")

        self.chk_geo = ctk.CTkCheckBox(frame, text="IP geolocation")
        self.chk_geo.grid(row=4, column=0, padx=12, pady=4, sticky="w")

        self.chk_mx_banners = ctk.CTkCheckBox(frame, text="Active MX banners (25/tcp)")
        self.chk_mx_banners.grid(row=5, column=0, padx=12, pady=4, sticky="w")

        ctk.CTkLabel(frame, text="Banner ports (comma sep):", anchor="w").grid(row=6, column=0, padx=12, pady=(12,0), sticky="w")
        self.entry_ports = ctk.CTkEntry(frame, placeholder_text="e.g. 22,80,443")
        self.entry_ports.grid(row=7, column=0, padx=12, pady=6, sticky="ew")

        ctk.CTkLabel(frame, text="Shodan API key (optional):", anchor="w").grid(row=8, column=0, padx=12, pady=(8,0), sticky="w")
        self.entry_shodan = ctk.CTkEntry(frame, placeholder_text="sk-...")
        self.entry_shodan.grid(row=9, column=0, padx=12, pady=6, sticky="ew")

        ctk.CTkLabel(frame, text="Proxy (http/socks):", anchor="w").grid(row=10, column=0, padx=12, pady=(8,0), sticky="w")
        self.entry_proxy = ctk.CTkEntry(frame, placeholder_text="http://127.0.0.1:8080 or socks5://127.0.0.1:9050")
        self.entry_proxy.grid(row=11, column=0, padx=12, pady=6, sticky="ew")

        self.var_anonymise = tk.BooleanVar(value=False)
        self.chk_anonymise = ctk.CTkCheckBox(frame, text="Anonymise (skip external APIs)",
                                             variable=self.var_anonymise, command=self._on_anonymise_toggle)
        self.chk_anonymise.grid(row=12, column=0, padx=12, pady=6, sticky="w")

        self.btn_run = ctk.CTkButton(frame, text="Run Recon", command=self.start_recon, height=42)
        self.btn_run.grid(row=13, column=0, padx=12, pady=(16,6), sticky="ew")

        self.btn_save = ctk.CTkButton(frame, text="Save JSON", command=self.save_json, height=38, state="disabled")
        self.btn_save.grid(row=14, column=0, padx=12, pady=6, sticky="ew")

        self.btn_compare = ctk.CTkButton(frame, text="Compare JSON…", command=self.compare_json, height=38, state="disabled")
        self.btn_compare.grid(row=15, column=0, padx=12, pady=6, sticky="ew")

        self.btn_clear = ctk.CTkButton(frame, text="Clear Output", command=self.clear_output, height=36)
        self.btn_clear.grid(row=16, column=0, padx=12, pady=(6,12), sticky="ew")

        self.lbl_ethics = ctk.CTkLabel(
            frame,
            text=("Use only on assets you own or with explicit permission.\n"
                  "Active checks are opt-in and may be logged."),
            justify="left", anchor="w", font=("Inter", 11), wraplength=306
        )
        self.lbl_ethics.grid(row=17, column=0, padx=12, pady=(6,12), sticky="ew")
        return frame

    def _build_main(self, parent):
        frame = ctk.CTkFrame(parent, corner_radius=16)
        frame.rowconfigure(1, weight=1); frame.columnconfigure(0, weight=1); frame.columnconfigure(1, weight=1)

        ctk.CTkLabel(frame, text="Results", font=("Inter", 18, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(12,6))

        log_frame = ctk.CTkFrame(frame); log_frame.grid(row=1, column=0, sticky="nsew", padx=(12,6), pady=(0,12))
        log_frame.rowconfigure(1, weight=1); log_frame.columnconfigure(0, weight=1)

        ctk.CTkLabel(log_frame, text="Activity Log", font=("Inter", 14, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(10,0))
        self.txt_log = ctk.CTkTextbox(log_frame, wrap="word"); self.txt_log.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        right = ctk.CTkFrame(frame); right.grid(row=1, column=1, sticky="nsew", padx=(6,12), pady=(0,12))
        right.rowconfigure(1, weight=1); right.columnconfigure(0, weight=1)

        self.tabs = ctk.CTkTabview(right); self.tabs.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0,10))
        tab_summary = self.tabs.add("Summary"); tab_json = self.tabs.add("JSON")
        tab_endpoints = self.tabs.add("Endpoints"); tab_diff = self.tabs.add("Diff"); tab_help = self.tabs.add("Help")

        self.txt_summary = ctk.CTkTextbox(tab_summary, wrap="word"); self.txt_summary.pack(fill="both", expand=True, padx=6, pady=6)
        self.txt_json = ctk.CTkTextbox(tab_json, wrap="none"); self.txt_json.pack(fill="both", expand=True, padx=6, pady=6)
        self.txt_endpoints = ctk.CTkTextbox(tab_endpoints, wrap="word"); self.txt_endpoints.pack(fill="both", expand=True, padx=6, pady=6)
        self.txt_diff = ctk.CTkTextbox(tab_diff, wrap="word"); self.txt_diff.pack(fill="both", expand=True, padx=6, pady=6)

        self.txt_help = ctk.CTkTextbox(tab_help, wrap="word"); self.txt_help.pack(fill="both", expand=True, padx=6, pady=6)
        self.txt_help.insert("1.0", HELP_TEXT); self.txt_help.configure(state="disabled")

        # JSON search bar
        bar = ctk.CTkFrame(tab_json); bar.pack(fill="x", padx=6, pady=(6,0))
        self.entry_json_search = ctk.CTkEntry(bar, placeholder_text="Find in JSON…")
        self.entry_json_search.pack(side="left", padx=(6,6), pady=6, fill="x", expand=True)
        self.entry_json_search.bind("<Return>", lambda e: self.json_search_start())
        ctk.CTkButton(bar, text="Find", width=70, command=self.json_search_start).pack(side="left", padx=4, pady=6)
        ctk.CTkButton(bar, text="Prev", width=70, command=self.json_search_prev).pack(side="left", padx=4, pady=6)
        ctk.CTkButton(bar, text="Next", width=70, command=self.json_search_next).pack(side="left", padx=4, pady=6)
        ctk.CTkButton(bar, text="Clear", width=70, command=self.json_search_clear).pack(side="left", padx=(4,6), pady=6)
        return frame

    # ---------- helpers ----------
    def _drain_log_queue(self):
        try:
            while True:
                msg = self._log_queue.get_nowait()
                self.txt_log.insert("end", msg + "\n"); self.txt_log.see("end")
        except queue.Empty:
            pass
        finally:
            self.after(120, self._drain_log_queue)

    def log(self, msg: str):
        self._log_queue.put(str(msg))

    def set_summary(self, text): self.txt_summary.delete("1.0","end"); self.txt_summary.insert("1.0", text)
    def set_json(self, data):
        self.txt_json.delete("1.0", "end")
        self.txt_json.insert("1.0", json.dumps(data, indent=2, ensure_ascii=False))
        self._json_search_hits, self._json_search_idx = [], -1
        self._json_tag_setup()

    def _json_tag_setup(self):
        text = getattr(self.txt_json, "_textbox", self.txt_json)
        try:
            text.tag_config("json_search_hit", background="#444444")
            text.tag_config("json_search_current", background="#FFD54F")
        except Exception:
            pass

    def json_search_clear(self):
        text = getattr(self.txt_json, "_textbox", self.txt_json)
        text.tag_remove("json_search_hit", "1.0", "end")
        text.tag_remove("json_search_current", "1.0", "end")
        self._json_search_hits, self._json_search_idx = [], -1

    def json_search_start(self):
        term = (self.entry_json_search.get() or "").strip()
        self.json_search_perform(term, new_search=True)

    def json_search_next(self):
        if not getattr(self, "_json_search_hits", None): self.json_search_start(); return
        self._json_search_idx = (self._json_search_idx + 1) % len(self._json_search_hits)
        self._json_search_apply_cursor()

    def json_search_prev(self):
        if not getattr(self, "_json_search_hits", None): self.json_search_start(); return
        self._json_search_idx = (self._json_search_idx - 1) % len(self._json_search_hits)
        self._json_search_apply_cursor()

    def json_search_perform(self, term, new_search=False):
        text = getattr(self.txt_json, "_textbox", self.txt_json)
        self._json_tag_setup()
        if new_search: self.json_search_clear()
        if not term: return
        idx = "1.0"; ranges = []
        while True:
            pos = text.search(term, idx, nocase=1, stopindex="end")
            if not pos: break
            end = f"{pos}+{len(term)}c"; ranges.append((pos,end)); idx = end
        for start, end in ranges: text.tag_add("json_search_hit", start, end)
        self._json_search_hits = ranges
        if not ranges: self._json_search_idx = -1; return
        if new_search or self._json_search_idx < 0: self._json_search_idx = 0
        self._json_search_apply_cursor()

    def _json_search_apply_cursor(self):
        if not self._json_search_hits or self._json_search_idx < 0: return
        text = getattr(self.txt_json, "_textbox", self.txt_json)
        text.tag_remove("json_search_current", "1.0", "end")
        start, end = self._json_search_hits[self._json_search_idx]
        text.tag_add("json_search_current", start, end); text.see(start)

    def set_diff(self, text):
        self.txt_diff.delete("1.0","end"); self.txt_diff.insert("1.0", text)

    def clear_output(self):
        for w in (self.txt_log, self.txt_summary, self.txt_json, self.txt_endpoints):
            w.delete("1.0", "end")
        self._results = None
        self.btn_save.configure(state="disabled")
        self.btn_compare.configure(state="disabled")

    # ---------- actions ----------
    def _gather_flags(self):
        ports_raw = (self.entry_ports.get() or "").strip()
        ports = [int(p) for p in re.split(r"[,\s]+", ports_raw) if p.isdigit()]
        return {
            "bruteforce": bool(self.chk_bruteforce.get()),
            "brute_words": None,
            "axfr": bool(self.chk_axfr.get()),
            "geo": bool(self.chk_geo.get()),
            "ports": ports,
            "mx_banners": bool(self.chk_mx_banners.get()),
            "shodan_key": self.entry_shodan.get().strip() or None,
            "skip_whois": False,
        }

    def start_recon(self):
        if self._recon_thread and self._recon_thread.is_alive():
            messagebox.showinfo("Busy", "Recon is already running."); return

        raw_target = (self.entry_target.get() or "").strip()
        if not raw_target:
            messagebox.showwarning("Missing target", "Please enter a domain, IP, or URL."); return

        target = normalize_target(raw_target)
        self.entry_target.delete(0, "end"); self.entry_target.insert(0, target)

        flags = self._gather_flags()

        # apply proxy + anonymise to runtime config
        raw_proxy = (self.entry_proxy.get() or "").strip()
        set_proxy(raw_proxy if raw_proxy else None)
        set_anonymise(bool(self.var_anonymise.get()))

        self.clear_output()
        if get_anonymise():
            self.log("[*] Anonymise enabled: skipping external lookups (crt.sh, BufferOver, Wayback, precrawl_js).")
        else:
            self.log("[*] Anonymise disabled: full lookups enabled.")

        self.log(f"{APP_NAME} (GUI) — starting…")
        active_list = [n for n,e in [("brute",flags["bruteforce"]),("axfr",flags["axfr"]),
                                     ("ports",bool(flags["ports"])),("mx_banners",flags["mx_banners"])] if e]
        self.log("Active checks enabled: " + (", ".join(active_list) if active_list else "none"))

        self.btn_run.configure(state="disabled")

        def worker():
            try:
                results = run_recon(target, flags, log=self.log)
                self.after(0, self._on_recon_done, results, None)
            except Exception as e:
                self.after(0, self._on_recon_done, None, e)
        self._recon_thread = threading.Thread(target=worker, daemon=True); self._recon_thread.start()

    def _on_recon_done(self, results, error):
        if error:
            self.log(f"[!] Error: {error}")
            messagebox.showerror("Error", str(error))
            self.btn_run.configure(state="normal"); return
        self._results = results
        self.btn_save.configure(state="normal"); self.btn_compare.configure(state="normal")
        self.render_results(results); self.btn_run.configure(state="normal")

    def render_results(self, data):
        s = []
        if get_anonymise(): s.append("**ANON MODE**: external sources skipped; some fields may be empty.")
        s += [
            f"Target: {data.get('target')}",
            f"Timestamp (UTC): {data.get('timestamp')}",
        ]
        root_domain = data.get("root_domain")
        if root_domain: s.append(f"Root domain: {root_domain}")

        summary = data.get("summary", {})
        ips = summary.get("ips") or []
        if ips:
            ip_info = data.get("ip_info", {})
            pretty = []
            for ip in ips:
                inf = (ip_info.get(ip) or {})
                org = inf.get("org"); asn = (inf.get("asn") or {}).get("asn")
                pref = (inf.get("asn") or {}).get("prefix")
                tag = ip
                if org: tag += f" [{org}]"
                if asn: tag += f" AS{asn}"
                if pref: tag += f" {pref}"
                pretty.append(tag)
            s.append("IPs: " + ", ".join(pretty))
        else: s.append("IPs: —")

        s.append(f"Subdomains (passive): {data.get('summary',{}).get('subdomain_count',0)}")

        http = data.get("http", {}) or {}
        http_title = summary.get("http_title") or http.get("title")
        if http_title: s.append(f"HTTP title: {http_title}")
        sh = (http.get("security_headers") or {})
        if sh.get("grade"): s.append(f"Security headers grade: {sh['grade']} (score {sh.get('score')})")
        if sh.get("cors") and sh.get("cors") != "none": s.append(f"CORS: {sh['cors']}")

        whois_reg = summary.get("whois_registrar")
        if whois_reg: s.append(f"WHOIS registrar: {whois_reg}")

        mp = data.get("mail_policy", {})
        if mp.get("spf"):
            enf = mp.get("spf_details", {}).get("enforcement")
            s.append(f"SPF: present ({enf or 'enforcement unknown'})")
        spfx = (mp.get("spf_expanded") or {})
        if spfx.get("includes") or spfx.get("ip4") or spfx.get("ip6"):
            s.append(f"SPF includes: {', '.join(spfx.get('includes', [])[:6])}{'…' if len(spfx.get('includes', []))>6 else ''}")
        dmarc = (mp.get("dmarc_record") or {})
        if dmarc.get("p"):
            extra = [f"{k}={dmarc.get(k)}" for k in ("sp","pct","adkim","aspf") if dmarc.get(k)]
            rua = dmarc.get("rua")
            s.append(f"DMARC: p={dmarc.get('p')}{(' | ' + ', '.join(extra)) if extra else ''}{(' | rua=' + rua) if rua else ''}")

        dnsrec = data.get("dns", {})
        if dnsrec.get("CAA"): s.append("CAA present (restricted CA issuance)")
        if dnsrec.get("DS"): s.append("DNSSEC: DS present")
        if data.get("dns_ttls"): s.append("DNS TTLs captured")

        tlsweak = data.get("tls_weak_protocols") or {}
        if any(tlsweak.values()):
            s.append("Weak TLS accepted: " + ", ".join([k for k,v in tlsweak.items() if v]))

        if data.get("axfr"):
            any_axfr = any(v for v in data["axfr"].values())
            s.append(f"AXFR: {'possible (records returned)' if any_axfr else 'not allowed or failed'}")

        mxb = data.get("mx_banners") or {}
        if mxb:
            hits = sum(1 for _,v in mxb.items() if v)
            s.append(f"MX banners with data: {hits}")

        wb = data.get("wayback") or {}
        if wb: s.append(f"Wayback pages: root={wb.get('root_pages',0)}, wildcard={wb.get('wildcard_pages',0)}")

        # Endpoints
        prec = data.get("precrawl", {}) or {}
        endpoints = prec.get("endpoints") or []
        if endpoints:
            groups = {"rest": [], "api": [], "wallet": [], "address": [], "misc": []}
            for ep in endpoints:
                e = ep.lower()
                if e.startswith("/rest/"): groups["rest"].append(ep)
                elif e.startswith("/api/"): groups["api"].append(ep)
                elif e.startswith("/wallet"): groups["wallet"].append(ep)
                elif e.startswith("/address"): groups["address"].append(ep)
                else: groups["misc"].append(ep)

            s.append("Pre-crawl endpoints (grouped):")
            for cat in ["rest","api","wallet","address","misc"]:
                items = groups[cat]
                if not items: continue
                s.append(f"  {cat.upper()} ({len(items)}):")
                for ep in items[:5]: s.append(f"    • {ep}")
                if len(items) > 5: s.append(f"    ... {len(items)-5} more")

            self.txt_endpoints.delete("1.0","end"); self.txt_endpoints.insert("1.0","\n".join(endpoints))
        else:
            self.txt_endpoints.delete("1.0","end"); self.txt_endpoints.insert("1.0","No endpoints discovered.")

        banners = data.get("banners") or {}
        if banners:
            count = sum(1 for ip, mp in banners.items() for _, b in (mp or {}).items() if b)
            s.append(f"Banner grabs with data: {count}")

        self.set_summary("\n".join(s)); self.set_json(data)

    def _on_anonymise_toggle(self):
        if self.var_anonymise.get():
            messagebox.showinfo(
                "Anonymise mode — ethics & caution",
                "Anonymise mode reduces external lookups and uses a minimal User-Agent.\n\n"
                "Use only on assets you own or have permission to test."
            )
        # (actual state is applied in start_recon)

    def save_json(self):
        if not self._results:
            messagebox.showinfo("No results", "Nothing to save yet."); return
        default_name = f"recon_{int(time.time())}.json"
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=default_name,
                    filetypes=[("JSON files","*.json"),("All files","*.*")])
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(self._results, fh, indent=2, ensure_ascii=False)
            messagebox.showinfo("Saved", f"Saved results to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def compare_json(self):
        if not self._results:
            messagebox.showinfo("No results", "Run recon first."); return
        path = filedialog.askopenfilename(filetypes=[("JSON files","*.json"),("All files","*.*")])
        if not path: return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                old = json.load(fh)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read JSON: {e}"); return
        cur = self._results; lines = []
        old_ips = set(old.get("summary",{}).get("ips") or []); new_ips = set(cur.get("summary",{}).get("ips") or [])
        if old_ips or new_ips:
            add_ips = new_ips - old_ips; rem_ips = old_ips - new_ips
            if add_ips: lines.append("New IPs: " + ", ".join(sorted(add_ips)))
            if rem_ips: lines.append("Removed IPs: " + ", ".join(sorted(rem_ips)))
        old_subs = set(old.get("subdomains_all") or []); new_subs = set(cur.get("subdomains_all") or [])
        add_subs = new_subs - old_subs; rem_subs = old_subs - new_subs
        if add_subs: lines.append(f"New subdomains ({len(add_subs)}): " + ", ".join(sorted(list(add_subs))[:20]) + ("…" if len(add_subs)>20 else ""))
        if rem_subs: lines.append(f"Disappeared subdomains ({len(rem_subs)}): " + ", ".join(sorted(list(rem_subs))[:20]) + ("…" if len(rem_subs)>20 else ""))
        old_cert = (old.get("tls_cert") or {}).get("not_after"); new_cert = (cur.get("tls_cert") or {}).get("not_after")
        if old_cert != new_cert: lines.append(f"TLS not_after changed: {old_cert} -> {new_cert}")
        old_grade = ((old.get("http") or {}).get("security_headers") or {}).get("grade")
        new_grade = ((cur.get("http") or {}).get("security_headers") or {}).get("grade")
        if old_grade != new_grade: lines.append(f"Security headers grade changed: {old_grade} -> {new_grade}")
        if not lines: lines = ["No differences found in primary surfaces."]
        self.set_diff("\n".join(lines))
