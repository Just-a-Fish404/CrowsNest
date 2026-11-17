import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import threading
import sys
import os

from CrowsNest import (run_full_assessment, format_report, resolve_sender, list_senders,
                       parse_batch_lines, run_batch, summarize, render_table, rows_to_csv)

NO_SENDER = "(none)"


def show_text(text):
    results.delete("1.0", tk.END)
    results.insert(tk.END, text)


batch_state = {"rows": []}      # summary rows from the most recent batch (for export)
progress_lock = threading.Lock()


def set_busy(busy):
    state = "disabled" if busy else "normal"
    run_button.config(state=state)
    load_button.config(state=state)
    export_button.config(state="disabled" if busy or not batch_state["rows"] else "normal")


def read_inputs():
    """Returns (selector, sender) from the form, or None after showing an error."""
    selector = select_dropdown.get().strip() or None
    sender = sender_dropdown.get().strip()
    if sender in ("", NO_SENDER):
        return selector, None
    try:
        resolve_sender(sender)
    except ValueError as exc:
        show_text(f"Error: {exc}")
        return None
    return selector, sender


def run_assessment():
    domain = domain_entry.get().strip()
    if not domain:
        show_text("Error: Please enter a valid domain:")
        return
    inputs = read_inputs()
    if inputs is None:
        return
    selector, sender = inputs

    set_busy(True)
    show_text("Running assessment...")

    def worker():
        try:
            text = format_report(run_full_assessment(domain, selector, sender))
        except Exception as exc:        # keep the GUI alive on any DNS surprise
            text = f"Error: {exc}"
        root.after(0, lambda: finish(text))

    threading.Thread(target=worker, daemon=True).start()


def finish(text):
    show_text(text)
    set_busy(False)


def load_domain_list():
    path = filedialog.askopenfilename(
        title="Select a domain list",
        filetypes=[("Text / CSV files", "*.txt *.csv"), ("All files", "*.*")])
    if not path:
        return
    try:
        with open(path, encoding="utf-8-sig") as handle:
            lines = handle.read().splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        messagebox.showerror("Could not read file", str(exc))
        return

    entries = parse_batch_lines(lines)
    if not entries:
        messagebox.showinfo("Empty list", "No domains were found in that file.")
        return
    inputs = read_inputs()
    if inputs is None:
        return
    selector, sender = inputs

    total = len(entries)
    counter = [0]
    box = {}
    finished = threading.Event()
    set_busy(True)
    show_text(f"Checking 0/{total} domains...")

    def progress(_result):
        with progress_lock:
            counter[0] += 1

    def worker():
        try:
            box["rows"] = [summarize(r) for r in run_batch(entries, selector, sender, 5, progress)]
        except Exception as exc:
            box["error"] = str(exc)
        finished.set()

    def poll():
        if finished.is_set():
            finish_batch(box, path)
        else:
            show_text(f"Checking {counter[0]}/{total} domains...")
            root.after(150, poll)

    threading.Thread(target=worker, daemon=True).start()
    poll()


def finish_batch(box, path):
    if "error" in box:
        show_text(f"Error: {box['error']}")
    else:
        batch_state["rows"] = box["rows"]
        show_text(render_table(box["rows"]) + f"\n\nSource: {os.path.basename(path)}")
    set_busy(False)


def export_csv():
    if not batch_state["rows"]:
        return
    path = filedialog.asksaveasfilename(
        title="Export results", defaultextension=".csv",
        filetypes=[("CSV file", "*.csv")], initialfile="crowsnest_results.csv")
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(rows_to_csv(batch_state["rows"]) + "\n")
    except OSError as exc:
        messagebox.showerror("Could not save file", str(exc))
        return
    messagebox.showinfo("Exported", f"Saved {len(batch_state['rows'])} results to:\n{path}")


#pretty colors
BG = "#111318"
PANEL = "#20242D"
PURPLE = "#563B70"
RED = "#A64B4B"
TEXT = "#D6CBAF"
MUTED = "#858595"


# makes the Window
root = tk.Tk()

root.title("CrowsNest - Email Record Assessment")
root.geometry("720x700")

if getattr(sys, 'frozen', False):
    application_path = sys._MEIPASS
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

icon_path = os.path.join(application_path, "crowsnest.png")

icon = tk.PhotoImage(file=icon_path)
root.iconphoto(True, icon)


banner = r"""                                                                             
   ______                           _   __          __ 
  / ____/________ _      _______   / | / /__  _____/ /_
 / /   / ___/ __ \ | /| / / ___/  /  |/ / _ \/ ___/ __/
/ /___/ /  / /_/ / |/ |/ (__  )  / /|  /  __(__  ) /_  
\____/_/   \____/|__/|__/____/  /_/ |_/\___/____/\__/  
                                                       
                                           """
banner_label = tk.Label(root, text=banner, font=("Courier", 10), justify="center")


banner_label.pack(pady=15)

#Domain input
domain_label= ttk.Label(root, text="Enter Domain:")
domain_label.pack()

domain_entry= ttk.Entry(root, width=25, justify="center")
domain_entry.pack(pady=5)

#DKIM selection
#Maybe add "?" button that explains what a DKIM selector is
select_label = tk.Label(root,text="DKIM Selector:",background=BG,foreground=TEXT)
select_label.pack()

def selector_help():
    messagebox.showinfo(
        "What is a DKIM Selector?",
        "A DKIM selector is a name used to locate "
        "a domain's DKIM public key in DNS.\n\n"
        "Your email provider assigns this selector.\n"
        "Common selectors include:\n"
        "google - Gmail\n"
        "selector1 - Outlook\n"
        "selector2 - Outlook\n"
        "k2 / k3 - Mailchimp\n\n"
        "If unsure, check your email provider's "
        "DKIM settings or contact your email administrator."
    )

selector_frame = ttk.Frame(root)
selector_frame.pack(pady=5)

select_dropdown = ttk.Combobox(selector_frame,values=["google", "selector1", "selector2", "sig1", "k1", "k2", "k3"],width=18)
select_dropdown.grid(row=0, column=0)

help_button = ttk.Button(
    selector_frame,text="?",width=5, padding=(6,8.2) , command=selector_help)
help_button.grid(row=0, column=1, padx=2)


#Sender validation (new)
sender_label = tk.Label(root, text="Email Sender (optional):", background=BG, foreground=TEXT)
sender_label.pack(pady=(8, 0))

sender_dropdown = ttk.Combobox(
    root, values=[NO_SENDER] + sorted(list_senders()), width=24, justify="center")
sender_dropdown.set(NO_SENDER)
sender_dropdown.pack(pady=5)


#Run button!!!!
button_frame = ttk.Frame(root)
button_frame.pack(pady=5)

run_button = ttk.Button(button_frame, text="Run Assessment", command=run_assessment)
run_button.grid(row=0, column=0, padx=4)

load_button = ttk.Button(button_frame, text="Load Domain List", command=load_domain_list)
load_button.grid(row=0, column=1, padx=4)

export_button = ttk.Button(button_frame, text="Export CSV", command=export_csv, state="disabled")
export_button.grid(row=0, column=2, padx=4)
root.bind("<Return>", lambda event: run_assessment())

#Result Display
results= tk.Text(root, height=14, width=85, state="normal", wrap="none")
results.pack(padx=10, pady=10)

root.configure(bg=BG)

# Initialize styling
style = ttk.Style()
style.theme_use("clam")


style.configure(
    "TFrame",
    background=BG
)

style.configure(
    "TLabel",
    background=BG,
    foreground=TEXT,
    font=("Segoe UI", 11)
)

# Input fields
style.configure(
    "TEntry",
    fieldbackground=PANEL,
    background=PURPLE,
    foreground=TEXT,
    arrowcolor=TEXT,
    padding=8,
    bordercolor=PURPLE,
    lightcolor=PURPLE,
    darkcolor=PURPLE
)

style.configure(
    "TCombobox",
    fieldbackground=PANEL,
    background=PURPLE,
    foreground=TEXT,
    arrowcolor=TEXT,
    padding=8,
    bordercolor=PURPLE,
    lightcolor=PURPLE,
    darkcolor=PURPLE
)


style.configure(
    "TButton",
    background=PURPLE,
    foreground=TEXT,
    font=("Segoe UI", 10, "bold"),
    padding=10,
    borderwidth=0
)

style.map(
    "TButton",
    background=[("active", MUTED)]
)

banner_label.configure(
    bg=BG,
    fg=TEXT,
    font=("Consolas", 11, "bold")
)

results.configure(
    bg=PANEL,
    fg=TEXT,
    insertbackground=TEXT,
    font=("Consolas", 10),
    relief="flat",
    padx=10,
    pady=10
)

root.mainloop()
