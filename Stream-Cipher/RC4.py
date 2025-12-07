import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import threading

class RC4:
    def __init__(self, key):
        self.key = [ord(c) for c in key]
        
    def KSA(self):
        """Key Scheduling Algorithm"""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + self.key[i % len(self.key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S
    
    def PRGA(self, S, data):
        """Pseudo-Random Generation Algorithm"""
        i = j = 0
        result = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            result.append(byte ^ K)
        return bytes(result)
    
    def encrypt(self, plaintext):
        S = self.KSA()
        data = plaintext.encode('utf-8')
        return self.PRGA(S, data)
    
    def decrypt(self, ciphertext):
        S = self.KSA()
        data = self.PRGA(S, ciphertext)
        return data.decode('utf-8')

class RC4Interface:
    def __init__(self, root):
        self.root = root
        self.root.title("RC4 Cryptographie - Analyse de Performance")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        self.stats_data = []
        self.process = psutil.Process()
        
        self.create_widgets()
        
    def create_widgets(self):

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#2c3e50')
        style.configure('TLabel', background='#2c3e50', foreground='#ecf0f1', font=('Arial', 10))
        style.configure('TButton', background='#3498db', foreground='white', font=('Arial', 10, 'bold'))
        
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        input_frame = ttk.LabelFrame(main_frame, text="Entrée", padding="10")
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(input_frame, text="Clé RC4:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(input_frame, width=50)
        self.key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        self.key_entry.insert(0, "MaCleSecrete123")
        
        ttk.Label(input_frame, text="Texte:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.text_input = scrolledtext.ScrolledText(input_frame, width=60, height=5, wrap=tk.WORD)
        self.text_input.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        self.text_input.insert(1.0, "Bonjour! Ceci est un message secret à chiffrer.")

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
        
        self.stats_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(stats_frame, orient=tk.VERTICAL, command=self.stats_tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.stats_tree.configure(yscrollcommand=scrollbar.set)
        
        graph_frame = ttk.LabelFrame(main_frame, text="Graphique de Performance", padding="10")
        graph_frame.grid(row=3, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5, padx=(5, 0))
        
        self.fig = Figure(figsize=(6, 4), facecolor='#34495e')
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
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
    
    def encrypt_text(self):
        try:
            key = self.key_entry.get()
            plaintext = self.text_input.get(1.0, tk.END).strip()
            
            if not key or not plaintext:
                messagebox.showwarning("Attention", "Veuillez entrer une clé et un texte!")
                return
            
            rc4 = RC4(key)
            
            def encrypt_operation():
                return rc4.encrypt(plaintext)
            
            ciphertext = self.measure_performance(encrypt_operation, "Chiffrement")
            
            hex_result = ciphertext.hex()
            self.result_output.delete(1.0, tk.END)
            self.result_output.insert(1.0, f"Texte chiffré (hex):\n{hex_result}")
            
            self.last_ciphertext = ciphertext
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du chiffrement: {str(e)}")
    
    def decrypt_text(self):
        try:
            if not hasattr(self, 'last_ciphertext'):
                messagebox.showwarning("Attention", "Veuillez d'abord chiffrer un texte!")
                return
            
            key = self.key_entry.get()
            rc4 = RC4(key)
            
            def decrypt_operation():
                return rc4.decrypt(self.last_ciphertext)
            
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
    app = RC4Interface(root)
    root.mainloop()