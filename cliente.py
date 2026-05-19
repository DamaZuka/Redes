import socket
import tkinter as tk
from tkinter import scrolledtext

# MUDAR AQUI: mete o IP do PC que está a correr o servidor
HOST = '192.168.163.1'
PORT = 8443

# Setup do Socket
cliente_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    cliente_socket.connect((HOST, PORT))
except Exception as e:
    print(f"Erro ao conectar ao servidor: {e}")

def enviar_mensagem():
    msg = entry.get()
    if msg:
        cliente_socket.sendall(msg.encode('utf-8'))
        chat_area.insert(tk.END, f"Tu: {msg}\n")
        entry.delete(0, tk.END)

# Setup da Janela
janela = tk.Tk()
janela.title("Chat Seguro - Projeto SRC")

chat_area = scrolledtext.ScrolledText(janela, width=40, height=10)
chat_area.pack(padx=10, pady=10)

entry = tk.Entry(janela, width=30)
entry.pack(padx=10, pady=5)

btn = tk.Button(janela, text="Enviar", command=enviar_mensagem)
btn.pack(pady=5)

janela.mainloop()