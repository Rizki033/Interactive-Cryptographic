# Caesar Cipher GUI 
import time 
import csv 
import tracemalloc
import psutil
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Caesar functions 
SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'
def caesar_encrypt (text: str, shift: int) -> str:
  result_chars = []
  for ch in text:
    if ch in SYMBOLS:
      symbolIndex = SYMBOLS.find(ch)
      translatedIndex = (symbolIndex + shift) % len(SYMBOLS)
      result_chars.append(SYMBOLS[translatedIndex])
    else:
      result_chars.append(ch)
  return ''.join(result_chars)

# decrypt function by applying negative shift
def caesar_decrypt(text: str, shift: int) -> str:
  return caesar_encrypt(text, (-shift)%len(SYMBOLS))

# measure resource 
process = psutil.Process()

def run_with_measurement(func, *args, **kwargs):
  # start tracemalloc to measure python allocations
  tracemalloc.start()
  # record start time
  t0_wall = time.perf_counter()
  t0_proc_times = process.cpu_times().user + process.cpu_times().system
  
  try:
    result = func(*args, **kwargs)
  finally:
    t1_wall = time.perf_counter()
    t1_proc_times = process.cpu_times().user + process.cpu_times().system
    
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
  wall_elapsed = t1_wall - t0_wall
  proc_time_delta = t1_proc_times - t0_proc_times
  cpu_percent_approx = (proc_time_delta / wall_elapsed * 100.0) if wall_elapsed > 0 else 0.0
  rss_bytes = process.memory_info().rss
  
  metrics = {
        'wall_seconds': wall_elapsed,
        'proc_seconds': proc_time_delta,
        'cpu_percent_approx': cpu_percent_approx,
        'py_alloc_current_bytes': current,
        'py_alloc_peak_bytes': peak,
        'process_rss_bytes': rss_bytes,
  }
  return result, metrics
  
# GUI
class CaesarGUI:
    def __init__(self, root):
      self.root = root
      root.title("Caesar Cipher GUI")
      
      # Top frame : inputs 
      frm_top = ttk.Frame(root, padding=8)
      frm_top.pack(fill='x')
      
      ttk.Label(frm_top, text="Message:").grid(row=0, column=0, sticky='w')
      self.entry_message = tk.Text(frm_top, height=4, width=70)
      self.entry_message.grid(row=1, column=0, columnspan=4, pady=(0,8))

      ttk.Label(frm_top, text="Key (0..{}):".format(len(SYMBOLS)-1)).grid(row=2, column=0, sticky='w')
      self.var_key = tk.IntVar(value=17)
      self.spin_key = ttk.Spinbox(frm_top, from_=0, to=len(SYMBOLS)-1, textvariable=self.var_key, width=6)
      self.spin_key.grid(row=2, column=1, sticky='w')

      self.var_mode = tk.StringVar(value='encrypt')
      ttk.Radiobutton(frm_top, text='Encrypt', variable=self.var_mode, value='encrypt').grid(row=2, column=2)
      ttk.Radiobutton(frm_top, text='Decrypt', variable=self.var_mode, value='decrypt').grid(row=2, column=3)

      self.btn_run = ttk.Button(frm_top, text="Run", command=self.on_run)
      self.btn_run.grid(row=3, column=0, pady=(6,0), sticky='w')

      self.btn_clear = ttk.Button(frm_top, text="Clear Table", command=self.clear_table)
      self.btn_clear.grid(row=3, column=1, pady=(6,0), sticky='w')

      self.btn_save = ttk.Button(frm_top, text="Save Table CSV", command=self.save_table_csv)
      self.btn_save.grid(row=3, column=2, pady=(6,0), sticky='w')

      # Result frame
      frm_result = ttk.Frame(root, padding=8)
      frm_result.pack(fill='x')

      ttk.Label(frm_result, text="Result:").grid(row=0, column=0, sticky='w')
      self.result_var = tk.StringVar(value="")
      self.entry_result = ttk.Entry(frm_result, textvariable=self.result_var, width=80)
      self.entry_result.grid(row=1, column=0, columnspan=4, pady=(2,8), sticky='w')

      # Table frame
      frm_table = ttk.Frame(root, padding=8)
      frm_table.pack(fill='both', expand=True)

      columns = ('timestamp', 'mode', 'key', 'cpu_percent')
      self.tree = ttk.Treeview(frm_table, columns=columns, show='headings', height=10)
      self.tree.heading('timestamp', text='Timestamp')
      self.tree.heading('mode', text='Mode')
      self.tree.heading('key', text='Key')
      self.tree.heading('cpu_percent', text='CPU % (approx)')

      self.tree.column('timestamp', width=140)
      self.tree.column('mode', width=80)
      self.tree.column('key', width=50, anchor='center')
      self.tree.column('cpu_percent', width=110)

      vsb = ttk.Scrollbar(frm_table, orient="vertical", command=self.tree.yview)
      self.tree.configure(yscrollcommand=vsb.set)
      vsb.pack(side='right', fill='y')
      self.tree.pack(fill='both', expand=True, side='left')

      # bottom status
      self.status_var = tk.StringVar(value="Ready")
      status_label = ttk.Label(root, textvariable=self.status_var, relief='sunken', anchor='w')
      status_label.pack(fill='x', padx=0, pady=0)

    def on_run(self):
        message = self.entry_message.get("1.0", tk.END).rstrip('\n')
        if not message:
            messagebox.showwarning("Input required", "Please enter a message.")
            return
        key = int(self.var_key.get()) % len(SYMBOLS)
        mode = self.var_mode.get()

        # Decide function
        if mode == 'encrypt':
            func = caesar_encrypt
        else:
            func = caesar_decrypt

        # run with measurement
        self.status_var.set("Running...")
        self.root.update_idletasks()
        try:
            result_text, metrics = run_with_measurement(func, message, key)
        except Exception as e:
            messagebox.showerror("Error", f"Exception during run: {e}")
            self.status_var.set("Error")
            return

        # display result
        self.result_var.set(result_text)

        # insert row in table
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cpu_pct = f"{metrics['cpu_percent_approx']:.2f}"
        self.tree.insert('', 'end', values=(ts, mode, str(key), cpu_pct))
        self.status_var.set(f"Last run: {mode} key={key}, cpu~{cpu_pct}%")

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_var.set("Table cleared")

    def save_table_csv(self):
        rows = []
        for iid in self.tree.get_children():
            rows.append(self.tree.item(iid)['values'])
        if not rows:
            messagebox.showinfo("No data", "Table is empty.")
            return
        fpath = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files','*.csv')])
        if not fpath:
            return
        with open(fpath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp','mode','key','cpu_percent_approx'])
            for r in rows:
                writer.writerow(r)
        self.status_var.set(f"Saved to {fpath}")
        messagebox.showinfo("Saved", f"Table saved to:\n{fpath}")

def main():
    root = tk.Tk()
    app = CaesarGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()

      
  
    

