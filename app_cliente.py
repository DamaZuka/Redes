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
    chat_area.insert(tk.END, f"{texto}\n")
    chat_area.yview(tk.END)

def atualizar_identidade_ui(nome):
    janela.title(f"Chat Seguro - Logado como: {nome}")
    chat_area.insert(tk.END, f"[SISTEMA] Identidade confirmada: {nome}\n")

gestor_rede = ClienteRedeSegura(
    host=HOST,
    port=PORT,
    callback_erro=lidar_com_queda_de_rede,
    callback_mensagem=receber_mensagem_do_servidor,
    callback_nome=atualizar_identidade_ui
)

janela = tk.Tk()
janela.title("Chat Seguro - Terminal Cliente")

chat_area = scrolledtext.ScrolledText(janela, width=45, height=12)
chat_area.pack(padx=10, pady=10)

entry = tk.Entry(janela, width=35)
entry.pack(padx=10, pady=5)
entry.bind("<Return>", lambda event: acao_enviar())

def acao_enviar():
    msg = entry.get()
    if msg:
        if gestor_rede.enviar_carga(msg):
            # Não escreve localmente com "[Tu]", deixa o servidor responder para manter o alinhamento
            entry.delete(0, tk.END)
        else:
            chat_area.insert(tk.END, "[SISTEMA] Erro: Não foi possível transmitir o pacote.\n")

btn = tk.Button(janela, text="Transmitir", command=acao_enviar)
btn.pack(pady=5)

if gestor_rede.estabelecer_conexao():
    print("Ligação mTLS segura estabelecida.")
else:
    print("Erro crítico mTLS.")
    exit()

janela.protocol("WM_DELETE_WINDOW", lambda: [gestor_rede.encerrar_conexao(), janela.destroy()])
janela.mainloop()