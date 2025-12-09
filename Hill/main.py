# hill_only_gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time, psutil
from math import isqrt
from typing import List, Tuple
import random
import string
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

MOD = 26
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# -------
# Matrix 
# -------
def _clean_letters(s: str) -> str:
    return "".join([c for c in s.upper() if c.isalpha()])

def _text_to_nums(text: str) -> List[int]:
    return [ord(c) - 65 for c in text]

def _nums_to_text(nums: List[int]) -> str:
    return "".join(ALPHA[n % MOD] for n in nums)

def _chunk(lst: List[int], size: int) -> List[List[int]]:
    return [lst[i:i+size] for i in range(0, len(lst), size)]

def _determinant(matrix: List[List[int]], mod: int = MOD) -> int:
    n = len(matrix)
    if n == 1:
        return matrix[0][0] % mod
    if n == 2:
        return (matrix[0][0]*matrix[1][1] - matrix[0][1]*matrix[1][0]) % mod
    det = 0
    for c in range(n):
        minor = [row[:c] + row[c+1:] for row in (matrix[1:])]
        cofactor = ((-1) ** c) * matrix[0][c] * _determinant(minor, mod)
        det += cofactor
    return det % mod

def _egcd(a: int, b: int) -> Tuple[int,int,int]:
    if a == 0:
        return (b, 0, 1)
    g, y, x = _egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def _modinv(a: int, mod: int) -> int:
    g, x, _ = _egcd(a % mod, mod)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {mod}")
    return x % mod

def _cofactor_matrix(matrix: List[List[int]]) -> List[List[int]]:
    n = len(matrix)
    cof = [[0]*n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            minor = [row[:c] + row[c+1:] for i,row in enumerate(matrix) if i != r]
            cof[r][c] = ((-1) ** (r + c)) * _determinant(minor, MOD)
    return cof

def _transpose(matrix: List[List[int]]) -> List[List[int]]:
    return [list(row) for row in zip(*matrix)]

def _matrix_mul(A: List[List[int]], v: List[int]) -> List[int]:
    n = len(A)
    out = []
    for i in range(n):
        s = 0
        for j in range(n):
            s += A[i][j] * v[j]
        out.append(s % MOD)
    return out

def matrix_inverse_mod26(matrix: List[List[int]]) -> List[List[int]]:
    n = len(matrix)
    det = _determinant(matrix, MOD) % MOD
    if det == 0:
        raise ValueError("Determinant is 0 mod 26 -> not invertible")
    try:
        det_inv = _modinv(det, MOD)
    except ValueError:
        raise ValueError("Determinant not invertible modulo 26 (gcd(det,26) != 1)")
    cof = _cofactor_matrix(matrix)
    adj = _transpose(cof)
    inv = [[(det_inv * (adj[i][j] % MOD)) % MOD for j in range(n)] for i in range(n)]
    return inv

def parse_key_matrix(key_text: str) -> Tuple[List[List[int]], int]:
    cleaned = _clean_letters(key_text)
    if len(cleaned) == 0:
        raise ValueError("Key must contain letters A-Z")
    L = len(cleaned)
    n = isqrt(L)
    if n * n != L:
        raise ValueError("Key length must be a perfect square (4,9,16...)")
    nums = _text_to_nums(cleaned)
    mat = _chunk(nums, n)
    return mat, n

# -------------------------
# Hill encrypt/decrypt (block-level)
# -------------------------
def hill_encrypt_blocks(key_matrix: List[List[int]], plaintext_letters: str) -> str:
    n = len(key_matrix)
    s = _clean_letters(plaintext_letters)
    # pad with 'X' if needed
    pad_len = (-len(s)) % n
    s = s + ('X' * pad_len)
    nums = _text_to_nums(s)
    blocks = _chunk(nums, n)
    out = []
    for blk in blocks:
        res = _matrix_mul(key_matrix, blk)
        out.append(_nums_to_text(res))
    return "".join(out)

def hill_decrypt_blocks(inv_key_matrix: List[List[int]], ciphertext_letters: str) -> str:
    n = len(inv_key_matrix)
    s = _clean_letters(ciphertext_letters)
    if len(s) % n != 0:
        raise ValueError("Ciphertext length must be multiple of block size")
    nums = _text_to_nums(s)
    blocks = _chunk(nums, n)
    out = []
    for blk in blocks:
        res = _matrix_mul(inv_key_matrix, blk)
        out.append(_nums_to_text(res))
    # remove trailing 'X' that may be padding (only remove actual padding)
    result = "".join(out)
    # it's safer to strip trailing X that were used for padding, but only if original likely had them
    # we'll just return result; user can interpret/remove X if needed
    return result

# -------------------------
# GUI Application (Hill only)
# -------------------------
class HillGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Hill Cipher — Encrypt / Decrypt")
        self.root.geometry("1200x800")
        self.root.configure(bg="#2c3e50")
        self.process = psutil.Process()
        self.stats_data = []
        self.create_widgets()

    def create_widgets(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#2c3e50")
        style.configure("TLabel", background="#2c3e50", foreground="#ecf0f1", font=("Arial", 10))

        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)

        # Input frame
        input_frame = ttk.LabelFrame(main, text="Input", padding=10)
        input_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)

        ttk.Label(input_frame, text="Key :").grid(row=0, column=0, sticky="w")
        self.key_entry = ttk.Entry(input_frame, width=60)
        self.key_entry.grid(row=0, column=1, pady=5)
        self.key_entry.insert(0, "GYBNQKURP")  # default 3x3

        ttk.Label(input_frame, text="Text :").grid(row=1, column=0, sticky="nw")
        self.text_input = scrolledtext.ScrolledText(input_frame, width=60, height=5, wrap="word")
        self.text_input.grid(row=1, column=1, pady=5)
        self.text_input.insert("1.0", "ACT")

        # Buttons
        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=1, column=0, columnspan=2, pady=8)
        self.enc_btn = tk.Button(btn_frame, text="CHIFFRER", bg="#27ae60", fg="white", width=16, command=self.encrypt_action)
        self.enc_btn.grid(row=0, column=0, padx=6)
        self.dec_btn = tk.Button(btn_frame, text="DÉCHIFFRER", bg="#e74c3c", fg="white", width=16, command=self.decrypt_action)
        self.dec_btn.grid(row=0, column=1, padx=6)
        self.clear_btn = tk.Button(btn_frame, text="EFFACER STATS", bg="#95a5a6", fg="white", width=16, command=self.clear_stats)
        self.clear_btn.grid(row=0, column=2, padx=6)

        # Result
        result_frame = ttk.LabelFrame(main, text="Result", padding=10)
        result_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)
        self.result_output = scrolledtext.ScrolledText(result_frame, width=80, height=5, wrap="word")
        self.result_output.pack(fill="x")

        # Bottom: charts left, stats right
        bottom = ttk.Frame(main)
        bottom.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=5)
        main.rowconfigure(3, weight=1)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)

        graph_frame = ttk.LabelFrame(bottom, text="Charts", padding=10)
        graph_frame.grid(row=0, column=0, sticky="nsew", padx=(0,5))
        bottom.columnconfigure(0, weight=2)

        self.fig = Figure(figsize=(6,4), facecolor="#34495e")
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        stats_frame = ttk.LabelFrame(bottom, text="Statistics", padding=10)
        stats_frame.grid(row=0, column=1, sticky="nsew", padx=(5,0))
        bottom.columnconfigure(1, weight=1)

        columns = ("Operation","Time(ms)","CPU(%)","Memory(MB)")
        self.stats_tree = ttk.Treeview(stats_frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.stats_tree.heading(col, text=col)
            self.stats_tree.column(col, width=120, anchor="center")
        self.stats_tree.pack(fill="both", expand=True)

    def measure(self, func, name):
        start = time.time()
        res = func()
        end = time.time()
        cpu = self.process.cpu_percent(interval=None)
        mem = self.process.memory_info().rss/1024/1024
        elapsed = (end-start)*1000
        self.stats_data.append({"operation":name,"time":elapsed,"cpu":cpu,"memory":mem})
        self.stats_tree.insert("", "end", values=(name,f"{elapsed:.2f}",f"{cpu:.2f}",f"{mem:.2f}"))
        self.update_graph()
        return res

    def encrypt_action(self):
        try:
            key_text = self.key_entry.get().strip()
            plain_raw = self.text_input.get("1.0","end").strip()
            if not key_text:
                raise ValueError("Enter a key .")
            clean_plain = _clean_letters(plain_raw)
            if len(clean_plain) == 0:
                raise ValueError("Plaintext must contain at least one letter A-Z.")
            mat, n = parse_key_matrix(key_text)
            # check invertibility to warn user (not strictly required for encrypt)
            try:
                inv = matrix_inverse_mod26(mat)
            except Exception as e:
                # still allow encryption but warn (decryption would fail)
                messagebox.showwarning("Warning", f"Key matrix not invertible decryption will fail: {e}")
                inv = None
            # perform encryption
            ciphertext = self.measure(lambda: hill_encrypt_blocks(mat, clean_plain), "Encrypt Hill")
            # show
            self.result_output.delete("1.0","end")
            self.result_output.insert("1.0", f"Ciphertext : {ciphertext}")
            # store last for optional use
            self._last_cipher = ciphertext
            self._last_inv = inv
            self._last_n = n
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_action(self):
        try:
            key_text = self.key_entry.get().strip()
            if not key_text:
                raise ValueError("Enter a key .")
            mat, n = parse_key_matrix(key_text)
            inv = matrix_inverse_mod26(mat)  
           
            current = self.result_output.get("1.0","end").strip()
            # if user previously encrypted, try to extract ciphertext letters, else ask error
            if current:

                if "Ciphertext :" in current:
                    cipher_letters = current.split("Ciphertext :",1)[1].splitlines()[0].strip()
                else:
                    
                    cipher_letters = _clean_letters(current)
            else:
                raise ValueError("No ciphertext found in result box; paste ciphertext letters or use the CHIFFRER button first.")
            if len(cipher_letters) == 0:
                raise ValueError("No letters found in ciphertext.")
            plaintext = self.measure(lambda: hill_decrypt_blocks(inv, cipher_letters), "Decrypt Hill")
            self.result_output.delete("1.0","end")
            self.result_output.insert("1.0", f"Ciphertext : {cipher_letters}\nDecrypted: {plaintext}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def update_graph(self):
        self.fig.clear()
        if not self.stats_data:
            self.canvas.draw()
            return
        ax1 = self.fig.add_subplot(211, facecolor="#2c3e50")
        ax2 = self.fig.add_subplot(212, facecolor="#2c3e50")

        ops = [d["operation"] for d in self.stats_data]
        times = [d["time"] for d in self.stats_data]
        cpus = [d["cpu"] for d in self.stats_data]

        colors1 = ["#3498db","#e74c3c","#27ae60","#f1c40f","#9b59b6"]
        colors2 = ["#e67e22","#1abc9c","#e74c3c","#3498db","#9b59b6"]

        ax1.bar(range(len(ops)), times, color=colors1[:len(ops)])
        ax1.set_xticks(range(len(ops)))
        ax1.set_xticklabels(ops, rotation=0, color="#ecf0f1")
        ax1.set_ylabel("Time (ms)", color="#ecf0f1")
        ax1.set_title("Execution time", color="#ecf0f1")
        ax1.tick_params(axis="y", colors="#ecf0f1")
        ax1.grid(True, alpha=0.3, color="#7f8c8d")

        ax2.bar(range(len(ops)), cpus, color=colors2[:len(ops)])
        ax2.set_xticks(range(len(ops)))
        ax2.set_xticklabels(ops, rotation=0, color="#ecf0f1")
        ax2.set_ylabel("CPU (%)", color="#ecf0f1")
        ax2.set_title("CPU usage", color="#ecf0f1")
        ax2.tick_params(axis="y", colors="#ecf0f1")
        ax2.grid(True, alpha=0.3, color="#7f8c8d")

        self.fig.tight_layout()
        self.canvas.draw()

    def clear_stats(self):
        self.stats_data = []
        for item in self.stats_tree.get_children():
            self.stats_tree.delete(item)
        self.fig.clear()
        self.canvas.draw()
        self.result_output.delete("1.0","end")
        messagebox.showinfo("Info", "Statistics cleared")

if __name__ == "__main__":
    root = tk.Tk()
    app = HillGUI(root)
    root.mainloop()
