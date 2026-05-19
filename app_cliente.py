import tkinter as tk
from tkinter import scrolledtext
from rede_cliente import ClienteRedeSegura

# Instanciação da camada de rede
HOST = '192.168.1.97'
PORT = 8443
gestor_rede = ClienteRedeSegura(HOST, PORT)

# Estabelecimento da conexão prévio à execução da interface
if gestor_rede.estabelecer_conexao():
    print("Ligação segura estabelecida com sucesso pela camada de rede!")
else:
    print("Aviso: A iniciar terminal local sem conectividade ao servidor.")

def acao_enviar():
    msg = entry.get()
    if msg:
        # A interface delega o envio para a camada de rede
        gestor_rede.enviar_carga(msg)
        chat_area.insert(tk.END, f"Tu: {msg}\n")
        entry.delete(0, tk.END)

# Configuração estrita da Janela
janela = tk.Tk()
janela.title("Chat Seguro - Terminal Cliente")

chat_area = scrolledtext.ScrolledText(janela, width=40, height=10)
chat_area.pack(padx=10, pady=10)

entry = tk.Entry(janela, width=30)
entry.pack(padx=10, pady=5)

btn = tk.Button(janela, text="Transmitir", command=acao_enviar)
btn.pack(pady=5)

# Rotina de encerramento seguro do socket ao terminar a aplicação
janela.protocol("WM_DELETE_WINDOW", lambda: [gestor_rede.encerrar_conexao(), janela.destroy()])

janela.mainloop()