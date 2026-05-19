import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import filedialog
import base64
import os
from rede_cliente import ClienteRedeSegura

HOST = '192.168.1.97'
PORT = 8443


def lidar_com_queda_de_rede():
    btn.config(state=tk.DISABLED)
    entry.config(state=tk.DISABLED)
    btn_file.config(state=tk.DISABLED)
    chat_area.insert(tk.END, "[SISTEMA] Ligação perdida com o servidor.\n")
    chat_area.yview(tk.END)
    messagebox.showerror("Erro de Conexão", "Foste desconectado do servidor seguro.")


import tempfile
import shutil


def receber_mensagem_do_servidor(texto):
    if texto.startswith("FILE_DATA:"):
        try:
            _, nome_ficheiro, conteudo_b64 = texto.split(":", 2)
            dados_binarios = base64.b64decode(conteudo_b64)

            # CRÍTICO: Gravar num ficheiro temporário SEM abrir janelas bloqueantes
            caminho_temp = os.path.join(tempfile.gettempdir(), nome_ficheiro)
            with open(caminho_temp, "wb") as f:
                f.write(dados_binarios)

            # Agora que já gravámos, perguntamos ao user para copiar do temp para onde ele quer
            chat_area.insert(tk.END, f"[SISTEMA] Ficheiro '{nome_ficheiro}' recebido!\n")

            if messagebox.askyesno("Download", f"Ficheiro '{nome_ficheiro}' recebido. Queres guardar?"):
                caminho_destino = filedialog.asksaveasfilename(initialfile=nome_ficheiro)
                if caminho_destino:
                    shutil.copy2(caminho_temp, caminho_destino)
                    chat_area.insert(tk.END, f"[SISTEMA] Guardado em: {caminho_destino}\n")

        except Exception as e:
            chat_area.insert(tk.END, f"[SISTEMA] Erro: {e}\n")

        chat_area.yview(tk.END)
        return

    # ... (o resto da tua função receber_mensagem_do_servidor continua igual)

    # 2. TRATA AS NOTIFICAÇÕES DE LINKS CLICÁVEIS
    if "[SISTEMA] Ficheiro recebido:" in texto:
        try:
            partes = texto.split("Ficheiro recebido: ")[1]
            nome_ficheiro = partes.split(" (Tamanho:")[0].strip()

            tag_name = f"link_{nome_ficheiro.replace('.', '_')}"
            idx_inicio = chat_area.index(tk.END + "-1c")
            chat_area.insert(tk.END, texto + "\n")
            idx_fim = chat_area.index(tk.END + "-1c")

            chat_area.tag_add(tag_name, idx_inicio, idx_fim)
            chat_area.tag_config(tag_name, foreground="blue", underline=True)
            chat_area.tag_bind(tag_name, "<Enter>", lambda e: chat_area.config(cursor="hand2"))
            chat_area.tag_bind(tag_name, "<Leave>", lambda e: chat_area.config(cursor=""))
            chat_area.tag_bind(tag_name, "<Button-1>", lambda e, n=nome_ficheiro: descarregar_ficheiro(n))
        except Exception:
            chat_area.insert(tk.END, f"{texto}\n")
    else:
        chat_area.insert(tk.END, f"{texto}\n")

    chat_area.yview(tk.END)


def descarregar_ficheiro(nome_ficheiro):
    """Pede diretamente o stream ao servidor."""
    chat_area.insert(tk.END, f"[SISTEMA] A solicitar download de '{nome_ficheiro}'...\n")
    chat_area.yview(tk.END)
    gestor_rede.enviar_carga(f"GET_FILE:{nome_ficheiro}")


def atualizar_identidade_ui(nome):
    janela.title(f"Chat Seguro - Logado como: {nome}")
    chat_area.insert(tk.END, f"[SISTEMA] Identidade confirmada: {nome}\n")
    chat_area.yview(tk.END)


def acao_enviar_ficheiro():
    ficheiro = filedialog.askopenfilename()
    if ficheiro:
        chat_area.insert(tk.END, f"[SISTEMA] A enviar ficheiro: {os.path.basename(ficheiro)}...\n")
        chat_area.yview(tk.END)
        if gestor_rede.enviar_ficheiro(ficheiro):
            chat_area.insert(tk.END, f"[SISTEMA] Envio concluído com sucesso!\n")
        else:
            chat_area.insert(tk.END, "[SISTEMA] Erro ao enviar ficheiro binário.\n")
        chat_area.yview(tk.END)


def acao_enviar():
    msg = entry.get().strip()
    if msg:
        if msg.startswith("CREATE:") or msg.startswith("JOIN:"):
            chat_area.insert(tk.END, f"[Comando]: {msg}\n")
        else:
            chat_area.insert(tk.END, f"[Tu]: {msg}\n")
        chat_area.yview(tk.END)

        if gestor_rede.enviar_carga(msg):
            entry.delete(0, tk.END)
        else:
            chat_area.insert(tk.END, "[SISTEMA] Erro crítico: Pacote não transmitido.\n")
            chat_area.yview(tk.END)


# --- Inicialização ---
gestor_rede = ClienteRedeSegura(
    host=HOST,
    port=PORT,
    callback_erro=lidar_com_queda_de_rede,
    callback_mensagem=receber_mensagem_do_servidor,
    callback_nome=atualizar_identidade_ui
)

janela = tk.Tk()
janela.title("Chat Seguro - Terminal Cliente")

chat_area = scrolledtext.ScrolledText(janela, width=60, height=18)
chat_area.pack(padx=10, pady=10)

entry = tk.Entry(janela, width=50)
entry.pack(padx=10, pady=5)
entry.bind("<Return>", lambda event: acao_enviar())

btn_file = tk.Button(janela, text="📎 Enviar Ficheiro", command=acao_enviar_ficheiro, bg="#e1e1e1")
btn_file.pack(pady=2)

btn = tk.Button(janela, text="Transmitir Mensagem", command=acao_enviar, bg="#4CAF50", fg="white")
btn.pack(pady=5)

if gestor_rede.estabelecer_conexao():
    print("Ligação mTLS estabelecida com sucesso.")
else:
    print("Erro mTLS.")
    exit()

janela.protocol("WM_DELETE_WINDOW", lambda: [gestor_rede.encerrar_conexao(), janela.destroy()])
janela.mainloop()