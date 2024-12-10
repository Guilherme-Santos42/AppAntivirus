import os
import requests
import threading
import json
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import pyclamd

# Configurações do MalwareBazaar
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
SIGNATURES_FILE = "malware_signatures.json"
WHITELIST_FILE = "whitelist.json"
LOG_FILE = "antivirus_logs.txt"

# Função para baixar assinaturas do MalwareBazaar
def update_signatures():
    try:
        response = requests.post(MALWAREBAZAAR_API_URL, data={"query": "get_recent"})
        if response.status_code == 200:
            malware_data = response.json()
            with open(SIGNATURES_FILE, "w") as f:
                json.dump(malware_data, f)
            log_event("Assinaturas atualizadas com sucesso.")
        else:
            log_event(f"Erro ao atualizar assinaturas: {response.status_code}")
    except Exception as e:
        log_event(f"Erro ao conectar ao MalwareBazaar: {e}")

# Função para calcular o hash SHA256 de um arquivo
def calculate_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        log_event(f"Erro ao calcular hash: {e}")
        return None

# Função para verificar assinaturas
def check_signatures(filepath):
    file_hash = calculate_hash(filepath)
    if not file_hash:
        return False

    try:
        with open(SIGNATURES_FILE, "r") as f:
            signatures = json.load(f)
        for malware in signatures.get("data", []):
            if file_hash == malware["sha256_hash"]:
                return True
    except Exception as e:
        log_event(f"Erro ao verificar assinaturas: {e}")
    return False

# Função para logar eventos
def log_event(message):
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")
    print(message)

# Função de escaneamento (multithread)
def scan_file(filepath):
    if os.path.isdir(filepath):
        return
    if filepath in load_whitelist():
        log_event(f"{filepath} está na whitelist. Ignorado.")
        return

    if check_signatures(filepath):
        log_event(f"Malware detectado: {filepath}")
    else:
        log_event(f"{filepath} é seguro.")

def scan_directory(directory):
    threads = []
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            thread = threading.Thread(target=scan_file, args=(filepath,))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

# Função para carregar a whitelist
def load_whitelist():
    try:
        with open(WHITELIST_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

# Monitoramento em tempo real
class RealTimeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            scan_file(event.src_path)

def start_real_time_monitoring(directory):
    event_handler = RealTimeHandler()
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    log_event(f"Monitoramento iniciado no diretório: {directory}")
    return observer

# Monitoramento de processos
def monitor_processes():
    for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
        try:
            exe = proc.info["exe"]
            if exe and not os.path.islink(exe):
                scan_file(exe)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# Interface gráfica
class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivírus Avançado")
        self.root.geometry("600x400")

        # GUI Tabs
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(expand=True, fill="both")

        self.tab_scan = ttk.Frame(self.tabs)
        self.tab_realtime = ttk.Frame(self.tabs)
        self.tab_process = ttk.Frame(self.tabs)
        self.tab_update = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_scan, text="Escaneamento")
        self.tabs.add(self.tab_realtime, text="Monitoramento em Tempo Real")
        self.tabs.add(self.tab_process, text="Monitorar Processos")
        self.tabs.add(self.tab_update, text="Atualizar Assinaturas")

        self.create_scan_tab()
        self.create_realtime_tab()
        self.create_process_tab()
        self.create_update_tab()

    def create_scan_tab(self):
        ttk.Label(self.tab_scan, text="Selecione um diretório para escanear:").pack(pady=10)
        self.directory_entry = ttk.Entry(self.tab_scan, width=50)
        self.directory_entry.pack(pady=5)
        ttk.Button(self.tab_scan, text="Escolher Diretório", command=self.choose_directory).pack(pady=5)
        ttk.Button(self.tab_scan, text="Escanear", command=self.scan_selected_directory).pack(pady=10)

    def choose_directory(self):
        directory = filedialog.askdirectory()
        self.directory_entry.insert(0, directory)

    def scan_selected_directory(self):
        directory = self.directory_entry.get()
        if directory:
            scan_directory(directory)
        else:
            messagebox.showerror("Erro", "Por favor, escolha um diretório.")

    def create_realtime_tab(self):
        ttk.Label(self.tab_realtime, text="Escolha um diretório para monitorar em tempo real:").pack(pady=10)
        self.realtime_entry = ttk.Entry(self.tab_realtime, width=50)
        self.realtime_entry.pack(pady=5)
        ttk.Button(self.tab_realtime, text="Escolher Diretório", command=self.choose_realtime_directory).pack(pady=5)
        ttk.Button(self.tab_realtime, text="Iniciar Monitoramento", command=self.start_realtime).pack(pady=10)

    def choose_realtime_directory(self):
        directory = filedialog.askdirectory()
        self.realtime_entry.insert(0, directory)

    def start_realtime(self):
        directory = self.realtime_entry.get()
        if directory:
            start_real_time_monitoring(directory)
        else:
            messagebox.showerror("Erro", "Por favor, escolha um diretório.")

    def create_process_tab(self):
        ttk.Button(self.tab_process, text="Monitorar Processos", command=monitor_processes).pack(pady=20)

    def create_update_tab(self):
        ttk.Button(self.tab_update, text="Atualizar Assinaturas", command=update_signatures).pack(pady=20)

# Main
if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()
