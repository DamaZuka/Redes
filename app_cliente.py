import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import filedialog
import base64
import os
from rede_cliente import ClienteRedeSegura

HOST = '192.168.1.97'
PORT = 8443
grupo_atual = None


def lidar_com_queda_de_rede():
    btn.config(state=tk.DISABLED)
    entry.config(state=tk.DISABLED)
    btn_file.config(state=tk.DISABLED)
    chat_area.insert(tk.END, "[SISTEMA] Ligação perdida com o servidor.\n")
    chat_area.yview(tk.END)
    messagebox.showerror("Erro de Conexão", "Foste desconectado do servidor seguro.")


def receber_mensagem_do_servidor(texto):
    global grupo_atual
    if "Foste removido do grupo" in texto or "Saíste do grupo" in texto:
        grupo_atual = None

    # INTERCETA O DOWNLOAD DIRETO PARA A RAM
    if texto.startswith("FILE_DATA:"):


        def _processar_e_guardar():
            try:
                _, nome_ficheiro, conteudo_b64 = texto.split(":", 2)
                dados_binarios = base64.b64decode(conteudo_b64)

                #Extrai a extensão corretamente
                extensao = os.path.splitext(nome_ficheiro)[1].lower()

                # Abre a janela já com a extensão forçada
                caminho_salvar = filedialog.asksaveasfilename(
                    initialfile=nome_ficheiro,
                    defaultextension=extensao,
                    filetypes=[(f"Ficheiro {extensao}", f"*{extensao}"), ("Todos os Ficheiros", "*.*")]
                )


                if caminho_salvar:
                    with open(caminho_salvar, "wb") as f:
                        f.write(dados_binarios)
                    chat_area.insert(tk.END, f"[SISTEMA] Guardado com sucesso em: {caminho_salvar}\n")

                chat_area.yview(tk.END)
            except Exception as e:
                chat_area.insert(tk.END, f"[SISTEMA] Erro ao gravar: {e}\n")
                chat_area.yview(tk.END)

        janela.after(0, _processar_e_guardar)
        return

    #TRATA DOS LINKS AZUIS CLICÁVEIS NO CHAT,
    if "FILE_LINK_" in texto:
        try:
            # Separa quem enviou ("prefixo") do ficheiro e tamanho ("resto")
            prefixo, resto = texto.split("FILE_LINK_", 1)
            nome_ficheiro = resto.split(" (Tamanho:")[0].strip()
            resto_tamanho = resto.split(" (Tamanho:")[1]

            # Imprime quem enviou ("[Grupo] AnonimoX:" ou "[Tu]:")
            chat_area.insert(tk.END, prefixo)

            # Cria o link só no nome do ficheiro
            tag_name = f"link_{nome_ficheiro.replace('.', '_')}"
            idx_inicio = chat_area.index(tk.END + "-1c")
            chat_area.insert(tk.END, nome_ficheiro)
            idx_fim = chat_area.index(tk.END + "-1c")

            # Imprime o tamanho a seguir ao link
            chat_area.insert(tk.END, f" (Tamanho:{resto_tamanho.rstrip()}\n")

            # Aplica o estilo p ficar azul e clicável
            chat_area.tag_add(tag_name, idx_inicio, idx_fim)
            chat_area.tag_config(tag_name, foreground="blue", underline=True)
            chat_area.tag_bind(tag_name, "<Enter>", lambda e: chat_area.config(cursor="hand2"))
            chat_area.tag_bind(tag_name, "<Leave>", lambda e: chat_area.config(cursor=""))
            chat_area.tag_bind(tag_name, "<Button-1>", lambda e, n=nome_ficheiro: descarregar_ficheiro(n))
        except Exception:
            # Fallback se houver algum erro a separar a string
            chat_area.insert(tk.END, f"{texto}\n")
    else:
        # Se for uma mensagem normal
        chat_area.insert(tk.END, f"{texto}\n")

    chat_area.yview(tk.END)


def descarregar_ficheiro(nome_ficheiro):
    """Pede diretamente o stream ao servidor."""
    chat_area.yview(tk.END)
    gestor_rede.enviar_carga(f"GET_FILE:{nome_ficheiro}")


def atualizar_identidade_ui(nome):
    janela.title(f"Chat Seguro - Logado como {nome}")
    chat_area.insert(tk.END, f"[SISTEMA] Bem-vindo {nome}!\n")
    chat_area.insert(tk.END, "--- GUIA DE COMANDOS ---\n")
    chat_area.insert(tk.END, "• CREATEJ:NomeSala:User1,User2  -> Criar e entrar num grupo\n")
    chat_area.insert(tk.END, "• JOIN:NomeSala                -> Entrar num grupo existente\n")
    chat_area.insert(tk.END, "• LEAVE                        -> Sair do grupo atual\n")
    chat_area.insert(tk.END, "------------------------\n")
    chat_area.yview(tk.END)


def acao_enviar_ficheiro():
    ficheiro = filedialog.askopenfilename()
    if ficheiro:
        chat_area.yview(tk.END)
        if gestor_rede.enviar_ficheiro(ficheiro):
            pass
        else:
            chat_area.insert(tk.END, "[SISTEMA] Erro ao enviar ficheiro binário.\n")
        chat_area.yview(tk.END)


def acao_enviar():
    global grupo_atual
    msg = entry.get().strip()

    if msg:
        if msg.startswith("CREATEJ:"):
            # Apanha o nome da sala
            partes = msg.split(":")
            if len(partes) >= 2:
                grupo_atual = partes[1].strip()
            chat_area.insert(tk.END, f"[Comando]: {msg}\n")

        elif msg.startswith("JOIN:"):
            grupo_atual = msg.split(":", 1)[1].strip()
            chat_area.insert(tk.END, f"[Comando]: {msg}\n")

        elif msg == "LEAVE":
            grupo_atual = None
            chat_area.insert(tk.END, f"[Comando]: LEAVE\n")

        else:

            if grupo_atual:
                chat_area.insert(tk.END, f"[{grupo_atual}] Tu: {msg}\n")
            else:
                chat_area.insert(tk.END, f"[Tu]: {msg}\n")

        chat_area.yview(tk.END)

        if gestor_rede.enviar_carga(msg):
            entry.delete(0, tk.END)
        else:
            chat_area.insert(tk.END, "[SISTEMA] Erro crítico: Pacote não transmitido.\n")
            chat_area.yview(tk.END)


#Inicialização
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