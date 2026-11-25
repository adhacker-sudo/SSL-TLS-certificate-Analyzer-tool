import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from certcheck import run_scan


class CertCheckGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("CertCheck - SSL/TLS Certificate & Configuration GUI")
        self.root.geometry("860x620")
        self.last_result: dict | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        top = ttk.LabelFrame(self.root, text="Target Configuration (Lab / Authorised Hosts Only)", padding=10)
        top.pack(fill="x", padx=12, pady=(10, 6))

        ttk.Label(top, text="Host:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.host_var = tk.StringVar(value="localhost")
        ttk.Entry(top, textvariable=self.host_var, width=28).grid(row=0, column=1, padx=(0, 12))

        ttk.Label(top, text="Port:").grid(row=0, column=2, sticky="w", padx=(0, 6))
        self.port_var = tk.StringVar(value="443")
        ttk.Entry(top, textvariable=self.port_var, width=8).grid(row=0, column=3, padx=(0, 12))

        ttk.Label(top, text="CA File (optional):").grid(row=1, column=0, sticky="w", pady=(8, 0), padx=(0, 6))
        self.cafile_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.cafile_var, width=42).grid(row=1, column=1, columnspan=2, sticky="we", pady=(8, 0))
        ttk.Button(top, text="Browse...", command=self._browse_cafile).grid(row=1, column=3, pady=(8, 0), padx=(6, 0))

        btn_row = ttk.Frame(self.root, padding=(12, 4))
        btn_row.pack(fill="x")

        self.scan_btn = ttk.Button(btn_row, text="Run Scan", command=self._on_scan)
        self.scan_btn.pack(side="left")

        ttk.Button(btn_row, text="Save Report (.txt)", command=self._save_txt).pack(side="left", padx=(8, 0))
        ttk.Button(btn_row, text="Save JSON (.json)", command=self._save_json).pack(side="left", padx=(8, 0))
        ttk.Button(btn_row, text="Clear", command=self._clear).pack(side="right")

        table_frame = ttk.LabelFrame(self.root, text="Graded Checks", padding=8)
        table_frame.pack(fill="x", padx=12, pady=6)

        columns = ("check", "verdict", "reason")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=6)
        self.tree.heading("check", text="Check")
        self.tree.heading("verdict", text="Verdict")
        self.tree.heading("reason", text="Details")
        self.tree.column("check", width=210, anchor="w")
        self.tree.column("verdict", width=90, anchor="center")
        self.tree.column("reason", width=510, anchor="w")
        self.tree.pack(fill="x")

        self.verdict_label = ttk.Label(self.root, text="Overall Verdict: -", font=("Segoe UI", 11, "bold"))
        self.verdict_label.pack(anchor="w", padx=14, pady=(2, 4))

        report_frame = ttk.LabelFrame(self.root, text="Full Report Output", padding=8)
        report_frame.pack(fill="both", expand=True, padx=12, pady=(2, 12))

        self.output_box = scrolledtext.ScrolledText(report_frame, wrap="word", font=("Consolas", 10))
        self.output_box.pack(fill="both", expand=True)

    def _browse_cafile(self) -> None:
        path = filedialog.askopenfilename(
            title="Select CA Certificate PEM File",
            filetypes=[("PEM / CRT files", "*.pem *.crt *.cer"), ("All files", "*.*")],
        )
        if path:
            self.cafile_var.set(path)

    def _on_scan(self) -> None:
        host = self.host_var.get().strip()
        if not host:
            messagebox.showwarning("Missing Host", "Please enter a target host.")
            return
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            messagebox.showwarning("Invalid Port", "Port must be a number (e.g., 443).")
            return

        cafile = self.cafile_var.get().strip() or None
        self.scan_btn.config(state="disabled")
        self.root.update_idletasks()

        try:
            result = run_scan(host, port, cafile=cafile)
            self.last_result = result
            self._render_result(result)
        except Exception as exc:
            messagebox.showerror("Scan Failed", str(exc))
        finally:
            self.scan_btn.config(state="normal")

    def _render_result(self, result: dict) -> None:
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)
        for item in result["checks"]:
            self.tree.insert("", "end", values=(item["check"], item["verdict"], item["reason"]))
        self.verdict_label.config(text=f"Overall Verdict: {result['overall_verdict']}")
        self.output_box.delete("1.0", "end")
        self.output_box.insert("1.0", result["report_text"])

    def _save_txt(self) -> None:
        if not self.last_result:
            messagebox.showinfo("No Report", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile="certcheck_report.txt",
            filetypes=[("Text files", "*.txt")],
        )
        if path:
            Path(path).write_text(self.last_result["report_text"] + "\n", encoding="utf-8")
            messagebox.showinfo("Saved", f"Report saved to {path}")

    def _save_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("No Report", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile="certcheck_report.json",
            filetypes=[("JSON files", "*.json")],
        )
        if path:
            serializable = {k: v for k, v in self.last_result.items() if k != "report_text"}
            Path(path).write_text(json.dumps(serializable, indent=2), encoding="utf-8")
            messagebox.showinfo("Saved", f"JSON saved to {path}")

    def _clear(self) -> None:
        self.last_result = None
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)
        self.verdict_label.config(text="Overall Verdict: -")
        self.output_box.delete("1.0", "end")


def main() -> None:
    root = tk.Tk()
    CertCheckGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
