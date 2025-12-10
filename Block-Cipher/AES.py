from Crypto.Cipher import AES
from secrets import token_bytes
from Crypto.Util.Padding import pad, unpad

import time
import psutil

from tkinter import *
import tkinter
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter import END
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import threading


class AESClass:
    # Définit la variable vecteur d'initialisation globalement pour la class (str bytes)
    global vi
    vi = b''
    def __init__(self, key, mode):
        self.key = key
        self.mode = mode
        
    def encrypt(self, plaintext):
        global interface_instance # Use the global varable to access interface elements
        global vi # utilisé la variable global vi pour stockage

        # ============================================================================
        # 1. Le chiffrement avec ECB Mode (Electronic Codebook) - NOT RECOMMENDED for production
        # ============================================================================
        
        if (self.mode == "ECB"):
            # Déclarer Algorithme
            cipher = AES.new(self.key, AES.MODE_ECB)
            # padding message
            padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
            # chiffrer
            ciphertext = cipher.encrypt(padded_plaintext)
        

        # ============================================================================
        # 2. Le chiffrement avec CBC Mode (Cipher Block Chaining) - Common and secure
        # ============================================================================

        elif (self.mode == "CBC"):
            # Déclarer Algorithme
            cipher = AES.new(self.key, AES.MODE_CBC)

            # vecteur d'initialisation (Save IV for decryption)
            vi = cipher.iv

            # padding message
            padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size) 

            # Chiffrée
            ciphertext = cipher.encrypt(padded_plaintext)

            # Afficher le VI            
            interface_instance.vi_label.config(text="VI(hex): ")
            interface_instance.vi_label.grid(row=2, column=0, sticky=tk.W, pady=0)
            interface_instance.vi_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=0)

            # rendre la boit d'entrée capable de recoivoire un contenue
            interface_instance.vi_entry.config(state="normal")

            # supprimer le contenu existant
            interface_instance.vi_entry.delete(0, END)
            
            # Insérer la clé            
            interface_instance.vi_entry.insert(0, vi.hex())

            # rendre la boit d'entrée disable pour que l'utilisateur ne touche pas cette boite
            interface_instance.vi_entry.config(state="disabled")


        # ============================================================================
        # 3. Le chiffrement avec CFB Mode (Cipher Feedback) - Stream cipher, no padding needed
        # ============================================================================

        elif (self.mode == "CFB"):
            cipher = AES.new(self.key, AES.MODE_CFB)
            # vecteur d'initialisation (Save IV for decryption)
            vi = cipher.iv
            plaintext = plaintext.encode('utf-8')
            # chiffrer 
            ciphertext = cipher.encrypt(plaintext)

            # Afficher le VI
            
            interface_instance.vi_label.config(text="VI(hex): ")
            interface_instance.vi_label.grid(row=2, column=0, sticky=tk.W, pady=0)
            interface_instance.vi_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=0)

            # rendre la boit d'entrée capable de recoivoire un contenue
            interface_instance.vi_entry.config(state="normal")

            # supprimer le contenu existant
            interface_instance.vi_entry.delete(0, END)
            
            # Insérer la clé            
            interface_instance.vi_entry.insert(0, vi.hex())

            # rendre la boit d'entrée disable pour que l'utilisateur ne touche pas cette boite
            interface_instance.vi_entry.config(state="disabled")

        return ciphertext
    

    
    def decrypt(self, ciphertext):
        global vi # utilisé la variable global vi pour récupurer sa valeur

        # ============================================================================
        # 1. Le déchiffrement avec ECB Mode (Electronic Codebook)
        # ============================================================================
        
        if (self.mode == "ECB"):
            # Déclarer Algorithme
            cipher = AES.new(self.key, AES.MODE_ECB)
            
            # padding message
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

            # Convertir plaintext à str
            plaintext = plaintext.decode('utf-8')            
            

            # ============================================================================
            # 2. Le déchiffrement CBC Mode (Cipher Block Chaining)
            # ============================================================================

        elif (self.mode == "CBC"):
            # Déclarer Algorithme avec son VI
            cipher = AES.new(self.key, AES.MODE_CBC, iv=vi)

            # Déchiffrer
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

            # Convertir plqintext à str
            plaintext = plaintext.decode('utf-8') 
                       

            # ============================================================================
            # 3. Le déchiffrement CFB Mode (Cipher Feedback)
            # ============================================================================

        elif (self.mode == "CFB"):

            # Déclarer Algorithme avec son VI
            cipher = AES.new(self.key, AES.MODE_CFB, iv=vi)

            # Déchiffrer
            plaintext = cipher.decrypt(ciphertext)

            # Convertir plqintext à str
            plaintext = plaintext.decode('utf-8') 

        return plaintext                          



class AESInterface:
    key = b''
    mode = ''
    iv = b''
    def __init__(self, root):
        global interface_instance
        interface_instance = self  # Store in global to use it in AESClass
        
        self.root = root
        self.root.title("AES Algorithm - Analyse de Performance")
        self.root.geometry("1200x800")

        self.root.configure(bg='#2c3e50')
        
        self.stats_data = []
        self.process = psutil.Process()
        
        self.create_widgets()
        
    def create_widgets(self):

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#2c3e50', font=('Arial', 4))
        style.configure('TLabel', background='#2c3e50', foreground='#ecf0f1', font=('Arial', 7))
        style.configure('TButton', background='#3498db', foreground='white', font=('Arial', 7, 'bold'))
        
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        
        input_frame = ttk.LabelFrame(main_frame, text="Entrée", padding="2", width=800, height=140)
        input_frame.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=0, padx=(0, 0))
        input_frame.grid_propagate(False)
        
        

        self.key_label = ttk.Label(input_frame, text="Clé AES:", font=("Arial", 8))
        self.key_entry = ttk.Entry(input_frame, width=70, font=("Arial", 8))

        self.mode_label = ttk.Label(input_frame, text="Mode de:", font=("Arial", 8))
        self.mode_entry = ttk.Entry(input_frame, width=10, font=("Arial", 8))

        self.vi_label = ttk.Label(input_frame, text="Vecteur d'initialisation:", font=("Arial", 8))
        self.vi_entry = ttk.Entry(input_frame, width=10, font=("Arial", 8))

        
        
        ttk.Label(input_frame, text="Texte:").grid(row=3, column=0, sticky=tk.N,pady=0)
        self.text_input = scrolledtext.ScrolledText(input_frame, width=40, height=5, wrap=tk.WORD)
        self.text_input.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=0, padx=(8, 0))
        self.text_input.insert(1.0, "Bonjour! Ceci est un message secret à chiffrer.")
                

        mode_frame = ttk.LabelFrame(main_frame, text="Choisir Mode et type d'AES", padding="10", width=400, height=100)
        mode_frame.grid(row=0, column=2, sticky=tk.E, pady=5)
        mode_frame.grid_propagate(False)
        
        self.aes128_btn = tk.Button(mode_frame, text="AES128", command=self.aes128,
                                   bg='#95a5a6', fg='white', font=('Arial', 8, 'bold'),
                                   padx=2, pady=2)
        self.aes128_btn.grid(row=0, column=0, padx=5)
         
        self.aes192_btn = tk.Button(mode_frame, text="AES192", command=self.aes192,
                                   bg='#95a5a6', fg='white', font=('Arial', 8, 'bold'),
                                   padx=2, pady=2)
        self.aes192_btn.grid(row=0, column=1, padx=5)

        
        self.aes256_btn = tk.Button(mode_frame, text="AES256", command=self.aes256,
                                   bg='#95a5a6', fg='white', font=('Arial', 8, 'bold'),
                                   padx=2, pady=2)
        self.aes256_btn.grid(row=0, column=3, padx=5)
         
       
        
        
        self.modeecb_btn = tk.Button(mode_frame, text="Mode ECB", command=self.modeecb,
                                   bg='#95a5a6', fg='white', font=('Arial', 8, 'bold'),
                                   padx=2, pady=2)
        self.modeecb_btn.grid(row=1, column=3, padx=5)
         
       
        self.modecbc_btn = tk.Button(mode_frame, text="Mode CBC", command=self.modecbc,
                                   bg='#95a5a6', fg='white', font=('Arial', 8, 'bold'),
                                   padx=2, pady=2)
        self.modecbc_btn.grid(row=1, column=1, padx=5)

        self.modetcb_btn = tk.Button(mode_frame, text="Mode TCB", command=self.modecfb,
                                   bg='#95a5a6', fg='white', font=('Arial', 8, 'bold'),
                                   padx=2, pady=2)
        self.modetcb_btn.grid(row=1, column=0, padx=5)
        
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        self.encrypt_btn = tk.Button(button_frame, text="CHIFFRER", command=self.encrypt_text,
                                     bg='#27ae60', fg='white', font=('Arial', 12, 'bold'),
                                     padx=20, pady=10)
        self.encrypt_btn.grid(row=0, column=0, padx=5)
        
        self.decrypt_btn = tk.Button(button_frame, text="DÉCHIFFRER", command=self.decrypt_text,
                                     bg='#e74c3c', fg='white', font=('Arial', 12, 'bold'),
                                     padx=20, pady=10)
        self.decrypt_btn.grid(row=0, column=1, padx=5)
        
        self.clear_btn = tk.Button(button_frame, text="EFFACER", command=self.clear_stats,
                                   bg='#95a5a6', fg='white', font=('Arial', 12, 'bold'),
                                   padx=20, pady=10)
        self.clear_btn.grid(row=0, column=2, padx=5)
        
        

        result_frame = ttk.LabelFrame(main_frame, text="Résultat", padding="10")
        result_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.result_output = scrolledtext.ScrolledText(result_frame, width=60, height=5, wrap=tk.WORD)
        self.result_output.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        stats_frame = ttk.LabelFrame(main_frame, text="Statistiques de Performance", padding="10")
        stats_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5, padx=(0, 5))
        
        columns = ('Operation', 'Temps (ms)', 'CPU (%)', 'Mémoire (MB)')
        self.stats_tree = ttk.Treeview(stats_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.stats_tree.heading(col, text=col)
            self.stats_tree.column(col, width=120, anchor=tk.CENTER)
        
        self.stats_tree.grid(row=0, column=0,sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(stats_frame, orient=tk.VERTICAL, command=self.stats_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.stats_tree.configure(yscrollcommand=scrollbar.set)
        
        graph_frame = ttk.LabelFrame(main_frame, text="Graphique de Performance", padding="10")
        graph_frame.grid(row=3, column=1, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5, padx=(5, 0))
        
        self.fig = Figure(figsize=(6, 4), facecolor='#34495e')
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=2)
        self.root.rowconfigure(2, weight=1)
        self.root.rowconfigure(1, weight=2)
        
        main_frame.columnconfigure(1, weight=1)  # Column 2
        main_frame.columnconfigure(0, weight=1)  # Column 1
        main_frame.columnconfigure(2, weight=1)  # Column 3
        
        # main_frame.columnconfigure(0, weight=1)
        # main_frame.columnconfigure(1, weight=1)
        # main_frame.columnconfigure(2, weight=1)
        # # main_frame.columnconfigure(3, weight=3)
        # main_frame.rowconfigure(3, weight=2)
        # Configure main_frame for 4 columns and 4 rows
        # Columns configuration


        # main_frame.columnconfigure(0, weight=1)  # Column 0# main_frame.columnconfigure(2, weight=1)  # Column 2
        # main_frame.columnconfigure(3, weight=1)  # Column 3
        
        # # Rows configuration
        # main_frame.rowconfigure(0, weight=1)  # Row 0
        # main_frame.rowconfigure(1, weight=1)  # Row 1
        # main_frame.rowconfigure(2, weight=1)  # Row 2
        main_frame.rowconfigure(3, weight=1)  # Row 3
        
    def measure_performance(self, operation_func, operation_name):
        """Mesure les performances d'une opération"""
        cpu_before = self.process.cpu_percent()
        mem_before = self.process.memory_info().rss / 1024 / 1024  # MB
        
        start_time = time.time()
        result = operation_func()
        end_time = time.time()
        
        time.sleep(0.1)  
        cpu_after = self.process.cpu_percent()
        mem_after = self.process.memory_info().rss / 1024 / 1024  # MB
        
        elapsed_time = (end_time - start_time) * 1000  # ms
        cpu_usage = max(cpu_after, cpu_before)
        mem_usage = mem_after

        self.stats_data.append({
            'operation': operation_name,
            'time': elapsed_time,
            'cpu': cpu_usage,
            'memory': mem_usage
        })

        self.stats_tree.insert('', tk.END, values=(
            operation_name,
            f"{elapsed_time:.3f}",
            f"{cpu_usage:.2f}",
            f"{mem_usage:.2f}"
        ))

        self.update_graph()
        
        return result
    
    def aes128(self):
        try:  
            self.key = token_bytes(16)
            # Afficher les infos de clés
            self.key_label.config(text="Clé AES128 (hex): ")
            self.key_label.grid(row=0, column=0, sticky=tk.W, pady=0)
            self.key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=0)

            # rendre la boit d'entrée capable de recoivoire un contenue
            self.key_entry.config(state="normal")

            # supprimer le contenu existant
            self.key_entry.delete(0, END)

            # Insérer la clé            
            self.key_entry.insert(0, self.key.hex())

             # rendre la boit d'entrée disable pour que l'utilisateur ne touche pas cette boite
            self.key_entry.config(state="disabled")
            if not self.key:
                messagebox.showwarning("Attention", "Veuillez cliquer une autre fois sur AES128!")
                return 
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de création du clé à 16 octets: {str(e)}")

    def aes192(self):
        try:  
            self.key = token_bytes(24)            
            # Afficher les infos de clés
            self.key_label.config(text="Clé AES192 (hex): ")
            self.key_label.grid(row=0, column=0, sticky=tk.W, pady=0)
            self.key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=0)

            # rendre la boit d'entrée capable de recoivoire un contenue
            self.key_entry.config(state="normal")

            # supprimer le contenu existant
            self.key_entry.delete(0, END)
            
            # Insérer la clé            
            self.key_entry.insert(0, self.key.hex())

             # rendre la boit d'entrée disable pour que l'utilisateur ne touche pas cette boite
            self.key_entry.config(state="disabled")
            if not self.key:
                messagebox.showwarning("Attention", "Veuillez cliquer une autre fois sur AES192!")
                return 
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de création du clé à 24 octets: {str(e)}")
    
    def aes256(self):
        try:  
            self.key = token_bytes(32)
            # Afficher les infos de clés
            self.key_label.config(text="Clé AES256 (hex): ")

            self.key_label.grid(row=0, column=0, sticky=tk.W, pady=0)
            self.key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=0)

            # rendre la boit d'entrée capable de recoivoire un contenue
            self.key_entry.config(state="normal")

            # supprimer le contenu existant
            self.key_entry.delete(0, END)
            
            # Insérer la clé            
            self.key_entry.insert(0, self.key.hex())

             # rendre la boit d'entrée disable pour que l'utilisateur ne touche pas cette boite
            self.key_entry.config(state="disabled")
            if not self.key:
                messagebox.showwarning("Attention", "Veuillez cliquer une autre fois sur AES256!")
                return 
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de création du clé à 32 octets: {str(e)}")
    
    def modeecb(self):
        try:  
            self.mode = 'ECB'
            self.mode_label.grid(row=1, column=0, sticky=tk.W, pady=0)
            self.mode_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=0)

            # rendre la boit d'entrée capable de recoivoire un contenue
            self.mode_entry.config(state="normal")

            # supprimer le contenu existant
            self.mode_entry.delete(0, END)

            # Insérer la clé            
            self.mode_entry.insert(0, self.mode)

             # rendre la boit d'entrée disable pour que l'utilisateur ne touche pas cette boite
            self.mode_entry.config(state="disabled")
            if not self.mode:
                messagebox.showwarning("Attention", "Veuillez cliquer une autre fois sur 'Mode ECB'!")
                return 
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de sélection de mode ECB: {str(e)}")
    
    def modecbc(self):
        print('you are in CBC')
        try:  
            self.mode = 'CBC'
            self.mode_label.grid(row=1, column=0, sticky=tk.W, pady=5)
            self.mode_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)

            # rendre la boit d'entrée capable de recoivoire un contenue
            self.mode_entry.config(state="normal")

            # supprimer le contenu existant
            self.mode_entry.delete(0, END)

            # Insérer la clé            
            self.mode_entry.insert(0, self.mode)

             # rendre la boit d'entrée disable pour que l'utilisateur ne touche pas cette boite
            self.mode_entry.config(state="disabled")
            if not self.mode:
                messagebox.showwarning("Attention", "Veuillez cliquer une autre fois sur 'Mode CBC'!")
                return 
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de sélection de 'Mode CBC': {str(e)}")
    
    def modecfb(self):
        try:  
            self.mode = 'CFB'
            self.mode_label.grid(row=1, column=0, sticky=tk.W, pady=5)
            self.mode_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)

            # rendre la boit d'entrée capable de recoivoire un contenue
            self.mode_entry.config(state="normal")

            # supprimer le contenu existant
            self.mode_entry.delete(0, END)

            # Insérer la clé            
            self.mode_entry.insert(0, self.mode)

             # rendre la boit d'entrée disable pour que l'utilisateur ne touche pas cette boite
            self.mode_entry.config(state="disabled")
            if not self.mode:
                messagebox.showwarning("Attention", "Veuillez cliquer une autre fois sur 'Mode CFB'!")
                return 
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de sélection de 'Mode CFB': {str(e)}")
    
    def encrypt_text(self):
        try:
            plaintext = self.text_input.get(1.0, tk.END).strip()
            if not self.key or not plaintext:
                messagebox.showwarning("Attention", "Veuillez entrer une clé et un texte!")
                return
            
            aes = AESClass(self.key, self.mode)
            
            def encrypt_operation():               
                return aes.encrypt(plaintext)
            
            ciphertext = self.measure_performance(encrypt_operation, "Chiffrement")
            
            hex_result = ciphertext.hex()
            self.result_output.delete(1.0, tk.END)
            self.result_output.insert(1.0, f"Texte chiffré (hex):\n{aes.key.hex()}")
            
            self.last_ciphertext = ciphertext
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du chiffrement: {str(e)}")
    
    def decrypt_text(self):
        try:
            if not hasattr(self, 'last_ciphertext'):
                messagebox.showwarning("Attention", "Veuillez d'abord chiffrer un texte!")
                return
            
            key = self.key_entry.get()
            aes = AESClass(self.key, self.mode)
            
            def decrypt_operation():
                return aes.decrypt(self.last_ciphertext)
            
            plaintext = self.measure_performance(decrypt_operation, "Déchiffrement")
            
            self.result_output.delete(1.0, tk.END)
            self.result_output.insert(1.0, f"Texte déchiffré:\n{plaintext}")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du déchiffrement: {str(e)}")
    
    def update_graph(self):
        """Met à jour le graphique avec les nouvelles données"""
        self.fig.clear()
        
        if not self.stats_data:
            return
        

        ax1 = self.fig.add_subplot(211, facecolor='#2c3e50')
        ax2 = self.fig.add_subplot(212, facecolor='#2c3e50')
        
        operations = [d['operation'] for d in self.stats_data]
        times = [d['time'] for d in self.stats_data]
        cpus = [d['cpu'] for d in self.stats_data]
        
  
        colors1 = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6']
        bars1 = ax1.bar(range(len(operations)), times, color=colors1[:len(operations)])
        ax1.set_ylabel('Temps (ms)', color='#ecf0f1', fontweight='bold')
        ax1.set_title('Temps d\'exécution', color='#ecf0f1', fontweight='bold', pad=10)
        ax1.tick_params(axis='x', colors='#ecf0f1')
        ax1.tick_params(axis='y', colors='#ecf0f1')
        ax1.set_xticks(range(len(operations)))
        ax1.set_xticklabels([f"Op {i+1}" for i in range(len(operations))], rotation=0)
        ax1.grid(True, alpha=0.3, color='#7f8c8d')
        

        colors2 = ['#e67e22', '#1abc9c', '#e74c3c', '#3498db', '#9b59b6']
        bars2 = ax2.bar(range(len(operations)), cpus, color=colors2[:len(operations)])
        ax2.set_ylabel('CPU (%)', color='#ecf0f1', fontweight='bold')
        ax2.set_xlabel('Opérations', color='#ecf0f1', fontweight='bold')
        ax2.set_title('Utilisation CPU', color='#ecf0f1', fontweight='bold', pad=10)
        ax2.tick_params(axis='x', colors='#ecf0f1')
        ax2.tick_params(axis='y', colors='#ecf0f1')
        ax2.set_xticks(range(len(operations)))
        ax2.set_xticklabels([f"Op {i+1}" for i in range(len(operations))], rotation=0)
        ax2.grid(True, alpha=0.3, color='#7f8c8d')
        
        self.fig.tight_layout()
        self.canvas.draw()
    
    def clear_stats(self):
        """Efface toutes les statistiques"""
        self.stats_data = []
        for item in self.stats_tree.get_children():
            self.stats_tree.delete(item)
        self.fig.clear()
        self.canvas.draw()
        self.result_output.delete(1.0, tk.END)
        messagebox.showinfo("Info", "Statistiques effacées!")

if __name__ == "__main__":
    root = tk.Tk()
    app = AESInterface(root)
    root.mainloop()