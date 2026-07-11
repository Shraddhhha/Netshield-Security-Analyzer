import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from threading import Thread
from netshield_ml import run_netshield
import os
import matplotlib
matplotlib.use("Agg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# Colors
DARK_BG = "#0f172a"
CARD_BG = "#1e293b"
TEXT_LIGHT = "#e2e8f0"
ACCENT = "#38bdf8"
SUCCESS = "#4ade80"
ERROR = "#f87171"


# -------- CENTER WINDOW FUNCTION ---------
def center_window(win, width, height):
    win.update_idletasks()
    screen_w = win.winfo_screenwidth()
    screen_h = win.winfo_screenheight()
    x = (screen_w // 2) - (width // 2)
    y = (screen_h // 2) - (height // 2)
    win.geometry(f"{width}x{height}+{x}+{y}")


class NetShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("NETSHIELD - Security Analyzer")
        self.geometry("600x430")
        center_window(self, 600, 430)
        self.configure(bg=DARK_BG)
        self.resizable(False, False)

        self.selected_file = None

        self.build_ui()

    def build_ui(self):

        # Title
        title = tk.Label(self, text="NETSHIELD Security Analyzer",
                         font=("Segoe UI", 18, "bold"),
                         bg=DARK_BG, fg=ACCENT)
        title.pack(pady=(20, 5))

        subtitle = tk.Label(self, text="Upload your network logs to detect threats",
                            font=("Segoe UI", 11),
                            bg=DARK_BG, fg=TEXT_LIGHT)
        subtitle.pack()

        # Main Card
        card = tk.Frame(self, bg=CARD_BG, relief="ridge", bd=2)
        card.place(x=30, y=90, width=540, height=270)

        # File Label
        self.file_label = tk.Label(card, text="No file selected",
                                   bg=CARD_BG, fg=TEXT_LIGHT,
                                   font=("Segoe UI", 11))
        self.file_label.pack(pady=15)

        # Select Button
        select_btn = tk.Button(card, text="Select Log File",
                               command=self.select_file,
                               bg=ACCENT, fg="black",
                               activebackground="#0ea5e9",
                               font=("Segoe UI", 11, "bold"),
                               height=1, width=18)
        select_btn.pack(pady=5)

        # Scan Button
        scan_btn = tk.Button(card, text="Scan Now",
                             command=self.start_scan,
                             bg=SUCCESS, fg="black",
                             activebackground="#16a34a",
                             font=("Segoe UI", 11, "bold"),
                             height=1, width=18)
        scan_btn.pack(pady=5)

        # Progress Bar
        self.progress = ttk.Progressbar(card, length=420, mode="indeterminate")
        self.progress.pack(pady=15)

        # Status
        self.status_lbl = tk.Label(card, text="Status: Idle",
                                   bg=CARD_BG, fg=TEXT_LIGHT,
                                   font=("Segoe UI", 10))
        self.status_lbl.pack()

    # File selection
    def select_file(self):
        fp = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if fp:
            self.selected_file = fp
            self.file_label.config(text=os.path.basename(fp))
            self.status_lbl.config(text="Status: File selected")

    # Scan
    def start_scan(self):
        if not self.selected_file:
            messagebox.showwarning("No File", "Please select a CSV log file first.")
            return

        self.progress.start(10)
        self.status_lbl.config(text="Status: Scanning...")

        Thread(target=self.scan_worker, daemon=True).start()

    def scan_worker(self):
        try:
            df, anomalies = run_netshield(self.selected_file)

            # timeline
            try:
                timeline = df.groupby(df["timestamp"].dt.floor("h")).size()
            except:
                timeline = None

            self.after(100, lambda: self.scan_complete(df, anomalies, timeline))
        except Exception as e:
            self.after(100, lambda: self.scan_error(e))

    def scan_error(self, err):
        self.progress.stop()
        self.status_lbl.config(text="Status: Error")
        messagebox.showerror("Error", str(err))

    def scan_complete(self, df, anomalies, timeline):
        self.progress.stop()
        self.status_lbl.config(text="Status: Scan complete")
        self.open_summary(df, anomalies, timeline)

    # SUMMARY WINDOW
    def open_summary(self, df, anomalies, timeline):
        win = tk.Toplevel(self)
        center_window(win, 700, 520)
        win.title("Scan Summary")
        win.configure(bg=DARK_BG)

        card = tk.Frame(win, bg=CARD_BG)
        card.place(x=10, y=10, width=680, height=500)

        tk.Label(card, text="Scan Summary",
                 bg=CARD_BG, fg=ACCENT,
                 font=("Segoe UI", 16, "bold")).pack(pady=12)

        tk.Label(card, text=f"Total Log Events: {len(df)}",
                 bg=CARD_BG, fg=TEXT_LIGHT,
                 font=("Segoe UI", 12)).pack()

        tk.Label(card, text=f"Anomalies Detected: {len(anomalies)}",
                 bg=CARD_BG, fg=ERROR,
                 font=("Segoe UI", 12, "bold")).pack(pady=10)

        # Buttons
        btn_frame = tk.Frame(card, bg=CARD_BG)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="View Details",
                  bg=ACCENT, fg="black",
                  command=lambda: self.view_details(anomalies)).pack(side="left", padx=10)

        tk.Button(btn_frame, text="View Timeline",
                  bg=SUCCESS, fg="black",
                  command=lambda: self.view_timeline(timeline)).pack(side="left", padx=10)

        # Quick anomaly preview
        tk.Label(card, text="Suspicious IPs:",
                 bg=CARD_BG, fg=ACCENT,
                 font=("Segoe UI", 12)).pack(pady=10)

        listbox = tk.Listbox(card, height=8, bg=CARD_BG, fg=TEXT_LIGHT,
                             highlightthickness=0, relief="flat")
        listbox.pack(padx=30, fill="x")

        if len(anomalies) == 0:
            listbox.insert("end", "No anomalies detected.")
        else:
            top_ips = anomalies["source_ip"].value_counts().head(8)
            for ip, cnt in top_ips.items():
                listbox.insert("end", f"{ip} — {cnt} suspicious events")

    # Detailed table
    def view_details(self, anomalies):
        w = tk.Toplevel(self)
        center_window(w, 720, 400)
        w.title("Anomaly Details")

        text = tk.Text(w, wrap="none")
        text.pack(fill="both", expand=True)

        if len(anomalies) == 0:
            text.insert("end", "No anomaly details available.")
        else:
            text.insert("end", str(anomalies.head(200)))

    # Timeline graph
    def view_timeline(self, timeline):
        w = tk.Toplevel(self)
        center_window(w, 760, 430)
        w.title("Timeline Graph")

        if timeline is None or len(timeline) == 0:
            tk.Label(w, text="No timeline data available").pack(pady=20)
            return

        fig, ax = plt.subplots(figsize=(7,3))
        ax.plot(timeline.index, timeline.values, marker="o")
        ax.set_title("Event Frequency")
        ax.set_xlabel("Time")
        ax.set_ylabel("Count")
        fig.autofmt_xdate()

        canvas = FigureCanvasTkAgg(fig, master=w)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)


if __name__ == "__main__":
    app = NetShieldApp()
    app.mainloop()
