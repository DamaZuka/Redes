import socket
import ssl
import tkinter as tk
from tkinter import scrolledtext

# Configuração da rede
HOST = '192.168.1.97' # IP do PC servidor
PORT = 8443

# 1. Configurar o contexto SSL
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE  # Para certificados self-signed

# 2. Criar socket e envolver no SSL
raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# O wrap_socket cria o "túnel" seguro
cliente_socket = context.wrap_socket(raw_socket, server_hostname='localhost')

try:
    cliente_socket.connect((HOST, PORT))
    print("Ligação segura estabelecida!")
except Exception as e:
    print(f"Erro ao conectar ao servidor: {e}")

def enviar_mensagem():
    msg = entry.get()
    if msg:
        # A mensagem é enviada através do túnel cifrado
        cliente_socket.sendall(msg.encode('utf-8'))
        chat_area.insert(tk.END, f"Tu: {msg}\n")
        entry.delete(0, tk.END)

# Setup da Janela
janela = tk.Tk()
janela.title("Chat Seguro - TLS/SSL")

chat_area = scrolledtext.ScrolledText(janela, width=40, height=10)
chat_area.pack(padx=10, pady=10)

entry = tk.Entry(janela, width=30)
entry.pack(padx=10, pady=5)

btn = tk.Button(janela, text="Enviar", command=enviar_mensagem)
btn.pack(pady=5)

janela.mainloop()