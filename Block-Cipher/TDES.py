import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time
import psutil
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from block_cipher_modes import encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc, encrypt_cfb, decrypt_cfb
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

class TripleDESInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("Triple DES (3DES) - Modes ECB / CBC / CFB")
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

        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill="both", expand=True)

        # Input frame
        input_frame = ttk.LabelFrame(main_frame, text="Entrée", padding=10)
        input_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)

        ttk.Label(input_frame, text="Clé 1 (8 bytes):").grid(row=0, column=0, sticky="w")
        self.key1_entry = ttk.Entry(input_frame, width=50)
        self.key1_entry.grid(row=0, column=1, pady=5)
        self.key1_entry.insert(0, "12345678")

        ttk.Label(input_frame, text="Clé 2 (8 bytes):").grid(row=1, column=0, sticky="w")
        self.key2_entry = ttk.Entry(input_frame, width=50)
        self.key2_entry.grid(row=1, column=1, pady=5)
        self.key2_entry.insert(0, "87654321")

        ttk.Label(input_frame, text="Clé 3 (8 bytes) - optionnel pour 3-key 3DES:").grid(row=2, column=0, sticky="w")
        self.key3_entry = ttk.Entry(input_frame, width=50)
        self.key3_entry.grid(row=2, column=1, pady=5)
        self.key3_entry.insert(0, "11223344")  # If left empty → 2-key 3DES (K3 = K1)

        ttk.Label(input_frame, text="Texte clair:").grid(row=3, column=0, sticky="nw")
        self.text_input = scrolledtext.ScrolledText(input_frame, width=60, height=6, wrap="word")
        self.text_input.grid(row=3, column=1, pady=5)
        self.text_input.insert("1.0", "Bonjour ! Ceci est un message secret protégé par Triple DES.")

        # Mode buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=15)

        self.ecb_btn = tk.Button(button_frame, text="ECB", bg="#3498db", fg="white", width=12,
                                 command=lambda: self.run_mode("ECB"))
        self.ecb_btn.grid(row=0, column=0, padx=8)
        self.cbc_btn = tk.Button(button_frame, text="CBC", bg="#e74c3c", fg="white", width=12,
                                 command=lambda: self.run_mode("CBC"))
        self.cbc_btn.grid(row=0, column=1, padx=8)
        self.cfb_btn = tk.Button(button_frame, text="CFB", bg="#27ae60", fg="white", width=12,
                                 command=lambda: self.run_mode("CFB"))
        self.cfb_btn.grid(row=0, column=2, padx=8)

        # Result output
        result_frame = ttk.LabelFrame(main_frame, text="Résultat", padding=10)
        result_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)

        self.result_output = scrolledtext.ScrolledText(result_frame, width=80, height=6, wrap="word")
        self.result_output.pack(fill="both", expand=True)

        # Bottom: graphs + stats
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=5)
        main_frame.rowconfigure(3, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        # Graphs
        graph_frame = ttk.LabelFrame(bottom_frame, text="Graphiques de performance", padding=10)
        graph_frame.grid(row=0, column=0, sticky="nsew", padx=(0,5))
        bottom_frame.columnconfigure(0, weight=2)
        bottom_frame.rowconfigure(0, weight=1)

        self.fig = Figure(figsize=(7,5), facecolor="#34495e")
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # Statistics table
        stats_frame = ttk.LabelFrame(bottom_frame, text="Statistiques", padding=10)
        stats_frame.grid(row=0, column=1, sticky="nsew", padx=(5,0))
        bottom_frame.columnconfigure(1, weight=1)

        columns = ("Opération", "Temps (ms)", "CPU (%)", "Mémoire (MB)")
        self.stats_tree = ttk.Treeview(stats_frame, columns=columns, show="headings", height=18)
        for col in columns:
            self.stats_tree.heading(col, text=col)
            self.stats_tree.column(col, width=130, anchor="center")
        self.stats_tree.pack(fill="both", expand=True)

    def get_triple_des_keys(self):
        """Return three 8-byte keys (supports 2-key or 3-key 3DES)"""
        k1 = self.key1_entry.get().encode('utf-8')
        k2 = self.key2_entry.get().encode('utf-8')
        k3 = self.key3_entry.get().encode('utf-8')

        if len(k1) != 8 or len(k2) != 8:
            messagebox.showerror("Erreur", "Les clés 1 et 2 doivent faire exactement 8 bytes chacune !")
            raise ValueError("Invalid key length")

        # If key3 is empty or not 8 bytes → use 2-key 3DES (K3 = K1)
        if len(k3) != 8:
            k3 = k1
            mode_name = "2-key 3DES"
        else:
            mode_name = "3-key 3DES"

        return k1, k2, k3, mode_name

    def triple_des_encrypt_block(self, plaintext_block, key1, key2, key3):
        d1 = DES.new(key1, DES.MODE_ECB)
        d2 = DES.new(key2, DES.MODE_ECB)
        d3 = DES.new(key3, DES.MODE_ECB)
        # EDE: Encrypt with K1 → Decrypt with K2 → Encrypt with K3
        return d3.encrypt(d2.decrypt(d1.encrypt(plaintext_block)))

    def triple_des_decrypt_block(self, ciphertext_block, key1, key2, key3):
        d1 = DES.new(key1, DES.MODE_ECB)
        d2 = DES.new(key2, DES.MODE_ECB)
        d3 = DES.new(key3, DES.MODE_ECB)
        # Reverse EDE
        return d3.decrypt(d2.encrypt(d1.decrypt(ciphertext_block)))

    def measure(self, func, name):
        start = time.perf_counter()
        result = func()
        elapsed = (time.perf_counter() - start) * 1000

        cpu = self.process.cpu_percent(interval=0.01)
        mem = self.process.memory_info().rss / 1024 / 1024

        self.stats_data.append({"operation": name, "time": elapsed, "cpu": cpu, "memory": mem})
        self.stats_tree.insert("", "end", values=(name, f"{elapsed:.2f}", f"{cpu:.2f}", f"{mem:.2f}"))
        self.update_graph()
        return result

    def run_mode(self, mode):
        try:
            key1, key2, key3, key_mode = self.get_triple_des_keys()
            plaintext = self.text_input.get("1.0", "end").strip().encode('utf-8')
            iv = get_random_bytes(8)

            encrypt_block = lambda block: self.triple_des_encrypt_block(block, key1, key2, key3)
            decrypt_block = lambda block: self.triple_des_decrypt_block(block, key1, key2, key3)

            self.result_output.delete("1.0", "end")
            self.result_output.insert("1.0", f"Mode : {mode} | {key_mode}\nIV (hex) : {iv.hex()}\n\n")

            if mode == "ECB":
                ciphertext = self.measure(lambda: encrypt_ecb(encrypt_block, 8, plaintext), "Encrypt ECB")
                decrypted = self.measure(lambda: decrypt_ecb(decrypt_block, 8, ciphertext), "Decrypt ECB")
            elif mode == "CBC":
                ciphertext = self.measure(lambda: encrypt_cbc(encrypt_block, 8, plaintext, iv), "Encrypt CBC")
                decrypted = self.measure(lambda: decrypt_cbc(decrypt_block, 8, ciphertext, iv), "Decrypt CBC")
            elif mode == "CFB":
                ciphertext = self.measure(lambda: encrypt_cfb(encrypt_block, 8, plaintext, iv), "Encrypt CFB")
                decrypted = self.measure(lambda: decrypt_cfb(encrypt_block, 8, ciphertext, iv), "Decrypt CFB")

            self.result_output.insert("end", f"Ciphertext (hex):\n{ciphertext.hex()}\n\n")
            self.result_output.insert("end", f"Texte déchiffré:\n{decrypted.decode('utf-8', errors='replace')}")

        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def update_graph(self):
        self.fig.clear()
        if not self.stats_data:
            self.canvas.draw()
            return

        ops = [d["operation"] for d in self.stats_data]
        times = [d["time"] for d in self.stats_data]
        cpus = [d["cpu"] for d in self.stats_data]

        ax1 = self.fig.add_subplot(211, facecolor="#2c3e50")
        ax2 = self.fig.add_subplot(212, facecolor="#2c3e50")

        colors1 = ["#3498db", "#e74c3c", "#27ae60", "#f1c40f", "#9b59b6", "#1abc9c"]
        colors2 = ["#e67e22", "#9b59b6", "#e74c3c", "#3498db", "#27ae60", "#f1c40f"]

        ax1.bar(ops, times, color=colors1[:len(ops)])
        ax1.set_ylabel("Temps (ms)", color="#ecf0f1")
        ax1.set_title("Temps d'exécution", color="#ecf0f1")
        ax1.tick_params(colors="#ecf0f1")
        ax1.grid(True, alpha=0.3)

        ax2.bar(ops, cpus, color=colors2[:len(ops)])
        ax2.set_ylabel("CPU (%)", color="#ecf0f1")
        ax2.set_title("Utilisation CPU", color="#ecf0f1")
        ax2.tick_params(colors="#ecf0f1")
        ax2.grid(True, alpha=0.3)

        self.fig.tight_layout()
        self.canvas.draw()


if __name__ == "__main__":
    root = tk.Tk()
    app = TripleDESInterface(root)
    root.mainloop()