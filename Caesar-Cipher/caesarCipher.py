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
def caesar_cipher (text: str, shift: int) -> str:
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
  return caesar_cipher(text, (-shift)%len(SYMBOLS))

# measure resource 
process = psutil.Process()

def run_with_measurements(func, *args, **kwargs):
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
      
  
    

