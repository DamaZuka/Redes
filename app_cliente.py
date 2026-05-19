import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from rede_cliente import ClienteRedeSegura

HOST = '192.168.1.97'
PORT = 8443

def lidar_com_queda_de_rede():
    btn.config(state=tk.DISABLED)
    entry.config(state=tk.DISABLED)
    chat_area.insert(tk.END, "[SISTEMA] Ligação perdida com o servidor.\n")
    messagebox.showerror("Erro de Conexão", "Foste desconectado do servidor seguro.")

def receber_mensagem_do_servidor(texto):
    """Escreve visualmente no chat as mensagens roteadas pelo servidor."""
    chat_area.insert(tk.END, f"{texto}\n")
    chat_area.yview(tk.END) # Faz scroll automático para a última mensagem

# Injetamos os dois callbacks na camada de rede
gestor_rede = ClienteRedeSegura(
    host=HOST,
    port=PORT,
    callback_erro=lidar_com_queda_de_rede,
    callback_mensagem=receber_mensagem_do_servidor
)

if gestor_rede.estabelecer_conexao():
    print("Ligação segura estabelecida com sucesso pela camada de rede!")
else:
    print("Aviso: A iniciar terminal local sem conectividade ao servidor.")

def acao_enviar():
    msg = entry.get()
    if msg:
        if gestor_rede.enviar_carga(msg):
            # Adiciona apenas a nossa própria mensagem localmente
            chat_area.insert(tk.END, f"[Tu]: {msg}\n")
            entry.delete(0, tk.END)
        else:
            chat_area.insert(tk.END, "[SISTEMA] Erro: Não foi possível transmitir o pacote.\n")

janela = tk.Tk()
janela.title("Chat Seguro - Terminal Cliente")

chat_area = scrolledtext.ScrolledText(janela, width=40, height=10)
chat_area.pack(padx=10, pady=10)

entry = tk.Entry(janela, width=30)
entry.pack(padx=10, pady=5)

btn = tk.Button(janela, text="Transmitir", command=acao_enviar)
btn.pack(pady=5)

janela.protocol("WM_DELETE_WINDOW", lambda: [gestor_rede.encerrar_conexao(), janela.destroy()])

janela.mainloop()