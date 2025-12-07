# des_gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time, psutil
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from block_cipher_modes import encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc, encrypt_cfb, decrypt_cfb
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

class DESInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("DES - Trois Modes ECB/CBC/CFB")
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

        # Entrée clé / texte
        input_frame = ttk.LabelFrame(main_frame, text="Entrée", padding=10)
        input_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)

        ttk.Label(input_frame, text="Clé (8 bytes):").grid(row=0, column=0, sticky="w")
        self.key_entry = ttk.Entry(input_frame, width=50)
        self.key_entry.grid(row=0, column=1, pady=5)
        self.key_entry.insert(0, "12345678")

        ttk.Label(input_frame, text="Texte:").grid(row=1, column=0, sticky="nw")
        self.text_input = scrolledtext.ScrolledText(input_frame, width=60, height=5, wrap="word")
        self.text_input.grid(row=1, column=1, pady=5)
        self.text_input.insert("1.0", "Hello! Ceci est un message secret.")

        # Boutons des modes
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)

        self.ecb_btn = tk.Button(button_frame, text="ECB", bg="#3498db", fg="white", width=12, command=lambda:self.run_mode("ECB"))
        self.ecb_btn.grid(row=0, column=0, padx=5)
        self.cbc_btn = tk.Button(button_frame, text="CBC", bg="#e74c3c", fg="white", width=12, command=lambda:self.run_mode("CBC"))
        self.cbc_btn.grid(row=0, column=1, padx=5)
        self.cfb_btn = tk.Button(button_frame, text="CFB", bg="#27ae60", fg="white", width=12, command=lambda:self.run_mode("CFB"))
        self.cfb_btn.grid(row=0, column=2, padx=5)

        # Résultat
        result_frame = ttk.LabelFrame(main_frame, text="Résultat", padding=10)
        result_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)

        self.result_output = scrolledtext.ScrolledText(result_frame, width=60, height=5, wrap="word")
        self.result_output.pack(fill="x")

        # Frame pour stats et graphiques (horizontal)
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=5)
        main_frame.rowconfigure(3, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        # Graphiques à gauche
        graph_frame = ttk.LabelFrame(bottom_frame, text="Graphiques", padding=10)
        graph_frame.grid(row=0, column=0, sticky="nsew", padx=(0,5))
        bottom_frame.columnconfigure(0, weight=2)
        bottom_frame.rowconfigure(0, weight=1)

        self.fig = Figure(figsize=(6,4), facecolor="#34495e")
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # Statistiques à droite
        stats_frame = ttk.LabelFrame(bottom_frame, text="Statistiques", padding=10)
        stats_frame.grid(row=0, column=1, sticky="nsew", padx=(5,0))
        bottom_frame.columnconfigure(1, weight=1)

        columns = ("Operation","Temps(ms)","CPU(%)","Mémoire(MB)")
        self.stats_tree = ttk.Treeview(stats_frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.stats_tree.heading(col, text=col)
            self.stats_tree.column(col, width=120, anchor="center")
        self.stats_tree.pack(fill="both", expand=True)

    # Mesure des performances
    def measure(self, func, name):
        start = time.time()
        res = func()
        end = time.time()
        cpu = self.process.cpu_percent()
        mem = self.process.memory_info().rss/1024/1024
        elapsed = (end-start)*1000

        self.stats_data.append({"operation":name,"time":elapsed,"cpu":cpu,"memory":mem})
        self.stats_tree.insert("", "end", values=(name,f"{elapsed:.2f}",f"{cpu:.2f}",f"{mem:.2f}"))
        self.update_graph()
        return res

    # Lancer le mode choisi
    def run_mode(self, mode):
        key = self.key_entry.get().encode()
        plaintext = self.text_input.get("1.0","end").strip().encode()
        if len(key) != 8:
            messagebox.showerror("Erreur","La clé doit être 8 bytes!")
            return
        iv = get_random_bytes(8)
        des = DES.new(key, DES.MODE_ECB)
        block_encrypt = des.encrypt
        block_decrypt = des.decrypt

        if mode=="ECB":
            ciphertext = self.measure(lambda: encrypt_ecb(block_encrypt,8,plaintext),"Encrypt ECB")
            decrypted = self.measure(lambda: decrypt_ecb(block_decrypt,8,ciphertext),"Decrypt ECB")
        elif mode=="CBC":
            ciphertext = self.measure(lambda: encrypt_cbc(block_encrypt,8,plaintext,iv),"Encrypt CBC")
            decrypted = self.measure(lambda: decrypt_cbc(block_decrypt,8,ciphertext,iv),"Decrypt CBC")
        else: #CFB
            ciphertext = self.measure(lambda: encrypt_cfb(block_encrypt,8,plaintext,iv),"Encrypt CFB")
            decrypted = self.measure(lambda: decrypt_cfb(block_encrypt,8,ciphertext,iv),"Decrypt CFB")

        self.result_output.delete("1.0","end")
        self.result_output.insert("1.0", f"Ciphertext (hex): {ciphertext.hex()}\nDecrypted: {decrypted.decode()}")

    # Mettre à jour graphique
    def update_graph(self):
        self.fig.clear()
        if not self.stats_data: return
        ax1 = self.fig.add_subplot(211, facecolor="#2c3e50")
        ax2 = self.fig.add_subplot(212, facecolor="#2c3e50")

        ops = [d["operation"] for d in self.stats_data]
        times = [d["time"] for d in self.stats_data]
        cpus = [d["cpu"] for d in self.stats_data]

        colors1 = ["#3498db","#e74c3c","#27ae60","#f1c40f","#9b59b6"]
        colors2 = ["#e67e22","#1abc9c","#e74c3c","#3498db","#9b59b6"]

        ax1.bar(ops,times,color=colors1[:len(ops)])
        ax1.set_ylabel("Temps (ms)",color="#ecf0f1")
        ax1.set_title("Temps d'exécution",color="#ecf0f1")
        ax1.tick_params(axis="x",colors="#ecf0f1")
        ax1.tick_params(axis="y",colors="#ecf0f1")
        ax1.grid(True,alpha=0.3,color="#7f8c8d")

        ax2.bar(ops,cpus,color=colors2[:len(ops)])
        ax2.set_ylabel("CPU (%)",color="#ecf0f1")
        ax2.set_title("Utilisation CPU",color="#ecf0f1")
        ax2.tick_params(axis="x",colors="#ecf0f1")
        ax2.tick_params(axis="y",colors="#ecf0f1")
        ax2.grid(True,alpha=0.3,color="#7f8c8d")

        self.fig.tight_layout()
        self.canvas.draw()

if __name__=="__main__":
    root = tk.Tk()
    app = DESInterface(root)
    root.mainloop()
