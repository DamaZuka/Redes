import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import simpledialog  # Importado para criar o prompt de nome
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


gestor_rede = ClienteRedeSegura(
    host=HOST,
    port=PORT,
    callback_erro=lidar_com_queda_de_rede,
    callback_mensagem=receber_mensagem_do_servidor
)

# Inicialização da Janela Tkinter base antes do prompt
janela = tk.Tk()
janela.withdraw()  # Oculta a janela principal temporariamente

# Pede o Nickname ao utilizador através de um diálogo nativo
nickname = simpledialog.askstring("Username", "Introduz o teu nome para o chat:", parent=janela)

if not nickname:
    nickname = "User-Anonimo"

# Tenta estabelecer a conexão de rede mTLS
if gestor_rede.estabelecer_conexao():
    print("Ligação segura estabelecida com sucesso!")
    janela.deiconify()  # Mostra a janela principal do chat

    # Envia o comando de registo do Nickname para a Camada de Aplicação do Servidor
    gestor_rede.enviar_carga(f"/nick {nickname}")
else:
    print("Erro crítico: Falha na autenticação de transporte mTLS.")
    messagebox.showerror("Erro PKI", "Falha de autenticação TLS. Certificado rejeitado.")
    janela.destroy()
    exit()


def acao_enviar():
    msg = entry.get()
    if msg:
        if gestor_rede.enviar_carga(msg):
            chat_area.insert(tk.END, f"[Tu]: {msg}\n")
            entry.delete(0, tk.END)
        else:
            chat_area.insert(tk.END, "[SISTEMA] Erro: Não foi possível transmitir o pacote.\n")


janela.title(f"Chat Seguro - Logado como: {nickname}")

chat_area = scrolledtext.ScrolledText(janela, width=40, height=10)
chat_area.pack(padx=10, pady=10)

entry = tk.Entry(janela, width=30)
entry.pack(padx=10, pady=5)
entry.bind("<Return>", lambda event: acao_enviar())  # Atalho Enter para enviar

btn = tk.Button(janela, text="Transmitir", command=acao_enviar)
btn.pack(pady=5)

janela.protocol("WM_DELETE_WINDOW", lambda: [gestor_rede.encerrar_conexao(), janela.destroy()])

janela.mainloop()