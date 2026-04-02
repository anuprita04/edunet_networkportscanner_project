import socket
import threading
import time
import queue
import sys
import g4f
from fpdf import FPDF
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

# ---------------------------
# Service Map
# ---------------------------
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
}

# ---------------------------
# Scanner Worker
# ---------------------------
class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=0.5, max_workers=100):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()

        self.total_ports = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports = []
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()

    def stop(self):
        self._stop_event.set()

    def _scan_port(self, port):
        if self._stop_event.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                with self._lock:
                    self.open_ports.append((port, service))
                self.result_queue.put(('open', port, service))
            s.close()
        except Exception as e:
            self.result_queue.put(('error', port, str(e)))
        finally:
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))

    def resolve_target(self):
        return socket.gethostbyname(self.target)

    def run(self):
        sem = threading.Semaphore(self.max_workers)
        threads = []

        for port in range(self.start_port, self.end_port + 1):
            if self._stop_event.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._worker_wrapper, args=(sem, port), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.result_queue.put(('done', None, None))

    def _worker_wrapper(self, sem, port):
        try:
            self._scan_port(port)
        finally:
            sem.release()

# ---------------------------
# Tkinter GUI
# ---------------------------
class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Port Sniffer - Network Port Scanner")
        self.geometry("720x600")
        self.minsize(680, 480)
        self.configure(bg="black")

        self.scanner_thread = None
        self.scanner = None
        self.start_time = None
        self.poll_after_ms = 40

        self._build_ui()

    def _build_ui(self):
        frm_top = ttk.LabelFrame(self, text="Scan Settings")
        frm_top.pack(fill="x", padx=10, pady=10)

        ttk.Label(frm_top, text="Target (IP / Hostname):").grid(row=0, column=0, padx=8, pady=8, sticky="e")
        self.ent_target = ttk.Entry(frm_top, width=36)
        self.ent_target.grid(row=0, column=1, padx=8, pady=8, sticky="w")

        ttk.Label(frm_top, text="Start Port:").grid(row=0, column=2, padx=8, pady=8, sticky="e")
        self.ent_start = ttk.Entry(frm_top, width=10)
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=0, column=3, padx=8, pady=8, sticky="w")

        ttk.Label(frm_top, text="End Port:").grid(row=0, column=4, padx=8, pady=8, sticky="e")
        self.ent_end = ttk.Entry(frm_top, width=10)
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=0, column=5, padx=8, pady=8, sticky="w")

        self.btn_start = ttk.Button(frm_top, text="Start Scan", command=self.start_scan)
        self.btn_start.grid(row=1, column=4, padx=8, pady=8, sticky="e")

        self.btn_stop = ttk.Button(frm_top, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=1, column=5, padx=8, pady=8, sticky="w")

        # Progress / Status
        frm_status = ttk.LabelFrame(self, text="Status")
        frm_status.pack(fill="x", padx=10, pady=(0,10))

        self.var_status = tk.StringVar(value="Idle")
        self.lbl_status = ttk.Label(frm_status, textvariable=self.var_status)
        self.lbl_status.pack(side="left", padx=10, pady=8)

        self.var_elapsed = tk.StringVar(value="Elapsed: 0.00s")
        self.lbl_elapsed = ttk.Label(frm_status, textvariable=self.var_elapsed)
        self.lbl_elapsed.pack(side="right", padx=10, pady=8)

        self.progress = ttk.Progressbar(frm_status, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0,10))

        # Results
        frm_results = ttk.LabelFrame(self, text="Open Ports")
        frm_results.pack(fill="both", expand=True, padx=10, pady=(0,10))

        self.txt_results = tk.Text(frm_results, height=12, wrap="none")
        self.txt_results.pack(fill="both", expand=True, side="left", padx=(10,0), pady=10)

        yscroll = ttk.Scrollbar(frm_results, orient="vertical", command=self.txt_results.yview)
        yscroll.pack(side="right", fill="y", pady=10)
        self.txt_results.configure(yscrollcommand=yscroll.set)

        # Action Buttons
        frm_actions = ttk.Frame(self)
        frm_actions.pack(fill="x", padx=10, pady=(0,12))

        self.btn_report = ttk.Button(frm_actions, text="Generate AI Report", state="disabled", command=self.create_ai_report_thread)
        self.btn_report.pack(pady=10)

        self.btn_clear = ttk.Button(frm_actions, text="Clear", command=self.clear_results)
        self.btn_clear.pack(side="left")

        self.btn_save = ttk.Button(frm_actions, text="Save Results", command=self.save_results, state="disabled")
        self.btn_save.pack(side="right")

    def start_scan(self):
        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Target is required.")
            return

        try:
            start_p = int(self.ent_start.get())
            end_p = int(self.ent_end.get())
        except ValueError:
            messagebox.showerror("Error", "Ports must be numbers.")
            return

        self.scanner = PortScanner(target, start_p, end_p)
        try:
            resolved_ip = self.scanner.resolve_target()
            self.append_text(f"Target: {target} ({resolved_ip})\nRange: {start_p}-{end_p}\n\n")
        except:
            messagebox.showerror("Error", "Could not resolve host.")
            return

        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.btn_report.config(state="disabled")
        self.start_time = time.time()
        self.var_status.set("Scanning...")
        
        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()
        self.update_elapsed()
        self.after(self.poll_after_ms, self.poll_results)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()

    def clear_results(self):
        self.txt_results.delete("1.0", tk.END)
        self.progress.config(value=0)
        self.var_status.set("Idle")

    def save_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, "w") as f:
                f.write(self.txt_results.get("1.0", tk.END))

    def append_text(self, text):
        self.txt_results.insert(tk.END, text)
        self.txt_results.see(tk.END)

    def update_elapsed(self):
        if self.start_time and "Scanning" in self.var_status.get():
            elapsed = time.time() - self.start_time
            self.var_elapsed.set(f"Elapsed: {elapsed:.2f}s")
            self.after(200, self.update_elapsed)

    def poll_results(self):
        if not self.scanner: return
        try:
            while True:
                msg_type, a, b = self.scanner.result_queue.get_nowait()
                if msg_type == 'open':
                    self.append_text(f"[+] Port {a} ({b}) is open\n")
                elif msg_type == 'progress':
                    self.progress.configure(maximum=b, value=a)
                    self.var_status.set(f"Scanning... {a}/{b}")
                elif msg_type == 'done':
                    total_open = len(self.scanner.open_ports)
                    self.append_text("\nScan complete.\n")
                    self.append_text(f"Open ports found: {total_open}\n")
                    self.var_status.set("Completed")
                    self.btn_start.config(state="normal")
                    self.btn_stop.config(state="disabled")
                    if self.scanner.open_ports:
                        self.btn_save.config(state="normal")
                        self.btn_report.config(state="normal")
        except queue.Empty:
            pass
        if self.scanner_thread.is_alive():
            self.after(self.poll_after_ms, self.poll_results)

    def create_ai_report_thread(self):
        self.btn_report.config(state="disabled")
        self.var_status.set("Consulting AI...")
        threading.Thread(target=self.fetch_ai_data, daemon=True).start()

    def fetch_ai_data(self):
        target_ip = self.ent_target.get() 
        open_ports = self.scanner.open_ports
        port_list = ", ".join([f"{p}({s})" for p, s in open_ports])
        
        prompt = f"Analyze security for the following network scan. Open ports: {port_list}. Provide risks and fixes. Create a report."

        try:
            response = g4f.ChatCompletion.create(
                model=g4f.models.gpt_4,
                messages=[{"role": "user", "content": prompt}],
            )
            self.var_status.set("Report Generated...")
            self.after(0, self.open_report_window, target_ip, response)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"AI Failed: {e}"))
        finally:
            self.after(0, lambda: self.btn_report.config(state="normal"))

    def open_report_window(self, target_ip, ai_text):
        report_win = tk.Toplevel(self)
        report_win.title(f"AI Report: {target_ip}")
        report_win.geometry("600x500")

        clean_text = ai_text.replace("**", "").replace("#", "")
        
        text_area = scrolledtext.ScrolledText(report_win, wrap=tk.WORD)
        text_area.insert(tk.INSERT, clean_text)
        text_area.pack(expand=True, fill='both', padx=10, pady=10)

        btn_dl = ttk.Button(report_win, text="Save as PDF", command=lambda: self.save_pdf(target_ip, clean_text))
        btn_dl.pack(pady=5)

    def save_pdf(self, target_ip, content):
            path = filedialog.asksaveasfilename(defaultextension=".pdf", initialfile=f"Scan_{target_ip}.pdf")
            if path:
                try:
                    pdf = FPDF()
                    pdf.add_page()

                    pdf.set_font("helvetica", size=11)
                
                    safe_content = content.replace('’', "'").replace('‘', "'").replace('—', '-').replace('–', '-')
   
                    safe_content = safe_content.encode('latin-1', 'replace').decode('latin-1')
    
                    pdf.multi_cell(0, 10, text=safe_content)
                
                    pdf.output(path)
                    messagebox.showinfo("Saved", "Report saved successfully.")
                except Exception as e:
                    messagebox.showerror("PDF Error", f"Failed to generate PDF: {e}")

if __name__ == "__main__":
    app = ScannerGUI()
    app.mainloop()
