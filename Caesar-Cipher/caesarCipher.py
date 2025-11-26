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


