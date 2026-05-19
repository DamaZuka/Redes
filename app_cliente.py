import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from rede_cliente import ClienteRedeSegura

HOST = '192.168.1.97'
PORT = 8443

def lidar_com_queda_de_rede():
    """Esta função corre quando a thread de rede deteta que o servidor nos expulsou."""
    btn.config(state=tk.DISABLED) # Desativa o botão de enviar
    entry.config(state=tk.DISABLED) # Bloqueia a caixa de texto
    chat_area.insert(tk.END, "[SISTEMA] Ligação perdida com o servidor. Envio desativado.\n")
    messagebox.showerror("Erro de Conexão", "Foste desconectado do servidor seguro (Timeout/Inatividade).")

# Passamos a nossa função de tratamento como callback para a camada de rede
gestor_rede = ClienteRedeSegura(HOST, PORT, callback_erro=lidar_com_queda_de_rede)

if gestor_rede.estabelecer_conexao():
    print("Ligação segura estabelecida com sucesso pela camada de rede!")
else:
    print("Aviso: A iniciar terminal local sem conectividade ao servidor.")

def acao_enviar():
    msg = entry.get()
    if msg:
        # Tenta enviar. Se a rede já souber que caiu, nem avança
        if gestor_rede.enviar_carga(msg):
            chat_area.insert(tk.END, f"Tu: {msg}\n")
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