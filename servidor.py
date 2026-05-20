import socket
import ssl
import threading
import time
import datetime
import os

HOST = '0.0.0.0'
PORT = 8443

TIMEOUT_SOCKET_CONV = 5.0
INTERVALO_HEARTBEAT_LIMITE = 15.0

grupos_canais = {}
nomes_clientes = {}
acl_canais = {}

# RLock em vez de Lock para o servidor não congelar no JOIN
lock_canais = threading.RLock()
LOCK_LOG = threading.Lock()
FICHEIRO_LOG_REDE = "auditoria_infraestrutura.log"


def registar_evento_rede(categoria, message):
    agora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    linha_log = f"[{agora}] [{categoria}] {message}\n"
    with LOCK_LOG:
        with open(FICHEIRO_LOG_REDE, "a", encoding="utf-8") as f:
            f.write(linha_log)


class RateLimiterTokenBucket:
    def __init__(self, capacidade, taxa_reposicao):
        self.capacidade = capacidade
        self.taxa_reposicao = taxa_reposicao
        self.tokens = capacidade
        self.ultimo_ajuste = time.time()
        self.lock = threading.Lock()

    def consumir(self):
        with self.lock:
            agora = time.time()
            decorrido = agora - self.ultimo_ajuste
            self.ultimo_ajuste = agora
            self.tokens = min(self.capacidade, self.tokens + decorrido * self.taxa_reposicao)
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


limitadores_clientes = {}
lock_limitadores = threading.Lock()


def obter_limitador_cliente(identificador_socket):
    with lock_limitadores:
        if identificador_socket not in limitadores_clientes:
            limitadores_clientes[identificador_socket] = RateLimiterTokenBucket(capacidade=5, taxa_reposicao=2.0)
        return limitadores_clientes[identificador_socket]


def rotear_mensagem_grupo(canal, pacote_bytes, socket_origem):
    with lock_canais:
        if canal in grupos_canais:
            # Se o socket tentar mandar msg mas já levou auto-kick, bloqueia!
            if socket_origem is not None and socket_origem not in grupos_canais[canal]:
                return False
            destinatarios = list(grupos_canais[canal])
        else:
            return False

    for cliente_sock in destinatarios:
        if cliente_sock != socket_origem:
            try:
                cliente_sock.sendall(pacote_bytes)
            except Exception:
                pass
    return True

def desvincular_cliente_de_canais(cliente_sock):
    with lock_canais:
        for canal in list(grupos_canais.keys()):
            if cliente_sock in grupos_canais[canal]:
                grupos_canais[canal].remove(cliente_sock)


def tratar_cliente(conn, addr):
    ip_cliente = addr[0]
    porta_cliente = addr[1]
    id_sessao = (ip_cliente, porta_cliente)
    limiter = obter_limitador_cliente(id_sessao)

    nome_utilizador = f"Anonimo-{porta_cliente}"
    nomes_clientes[conn] = nome_utilizador

    try:
        conn.getpeercert()
        registar_evento_rede("AUTENTICAÇÃO_mTLS", f"Sucesso: Equipamento validado de {addr}")
    except Exception as e:
        registar_evento_rede("ALERTA_MFT", f"Falha mTLS de {addr}: {e}")
        conn.close()
        return

    conn.settimeout(TIMEOUT_SOCKET_CONV)
    ultimo_contacto = time.time()
    canal_atual = None

    # Envia o nome com uma quebra de linha para o recv do cliente não bloquear
    try:
        conn.sendall(f"SET_NAME:{nome_utilizador}\n".encode('utf-8'))
    except Exception:
        conn.close()
        return

    registar_evento_rede("CONEXÃO_ESTABELECIDA", f"Utilizador {nome_utilizador} ligado.")
    ultimos_envios_locais = []

    with conn:
        while True:
            if time.time() - ultimo_contacto > INTERVALO_HEARTBEAT_LIMITE:
                registar_evento_rede("TIMEOUT_REDE", f"Forçando encerramento: {nome_utilizador}")
                break

            try:
                dados = conn.recv(1024)
                if not dados:
                    break

                try:
                    msg = dados.decode('utf-8').strip()
                except UnicodeDecodeError:
                    continue

                if msg == "PING":
                    ultimo_contacto = time.time()
                    conn.sendall("PONG\n".encode('utf-8'))
                    continue

                # --- RATE LIMITING ---
                agora_envio = time.time()
                ultimos_envios_locais = [t for t in ultimos_envios_locais if agora_envio - t < 1.5]
                ultimos_envios_locais.append(agora_envio)

                if len(ultimos_envios_locais) > 5 or not limiter.consumir():
                    registar_evento_rede("DEFESA_RATE_LIMIT", f"Inundação de: {nome_utilizador}")
                    conn.sendall("[SISTEMA]: Limite de taxa excedido. Pacote descartado.\n".encode('utf-8'))
                    continue

                # --- COMANDO: CREATE ---
                if msg.startswith("CREATE:"):
                    try:
                        _, nome_sala, convidados = msg.split(":", 2)
                        lista_autorizados = [u.strip() for u in convidados.split(",")]
                        lista_autorizados.append(nome_utilizador)

                        with lock_canais:
                            if nome_sala not in acl_canais:
                                acl_canais[nome_sala] = lista_autorizados
                                grupos_canais[nome_sala] = []
                                conn.sendall(f"[SISTEMA]: Grupo privado '{nome_sala}' criado.\n".encode('utf-8'))
                                registar_evento_rede("CRIAR_CANAL", f"Grupo '{nome_sala}' por {nome_utilizador}")
                            else:
                                conn.sendall("[SISTEMA]: Erro: Esse grupo já existe.\n".encode('utf-8'))
                    except ValueError:
                        conn.sendall("[SISTEMA]: Erro. Usa: CREATE:NomeSala:User1,User2\n".encode('utf-8'))
                    continue

                # --- COMANDO: JOIN ---
                if msg.startswith("JOIN:"):
                    nome_sala = msg.split(":", 1)[1].strip()

                    with lock_canais:
                        if nome_sala in acl_canais:
                            if nome_utilizador in acl_canais[nome_sala]:
                                desvincular_cliente_de_canais(conn)
                                grupos_canais[nome_sala].append(conn)
                                canal_atual = nome_sala
                                conn.sendall(f"[SISTEMA]: Entraste no grupo privado '{nome_sala}'.\n".encode('utf-8'))
                                registar_evento_rede("MUDANÇA_CANAL", f"'{nome_utilizador}' em '{nome_sala}'")
                                msg_aviso = f"[SISTEMA]: {nome_utilizador} entrou no grupo.\n".encode('utf-8')
                                rotear_mensagem_grupo(canal_atual, msg_aviso, conn)
                            else:
                                conn.sendall("[SISTEMA]: ERRO: Sem permissão para este grupo.\n".encode('utf-8'))
                                registar_evento_rede("VIOLAÇÃO_ACESSO", f"Negado {nome_utilizador} em '{nome_sala}'")
                        else:
                            conn.sendall("[SISTEMA]: Erro: Esse grupo não existe.\n".encode('utf-8'))
                    continue

                # --- COMANDO: LEAVE ---
                if msg == "LEAVE":
                    if canal_atual:
                        nome_sala = canal_atual

                        with lock_canais:
                            if conn in grupos_canais.get(nome_sala, []):
                                grupos_canais[nome_sala].remove(conn)

                            sobrantes = grupos_canais.get(nome_sala, [])
                            integrantes_nomes = [nomes_clientes.get(c, "Desconhecido") for c in sobrantes]

                            # Vê se a sala era só para 2 (criador + 1 na ACL)
                            criado_para_dois = (len(acl_canais.get(nome_sala, [])) == 2)

                            if criado_para_dois and len(sobrantes) == 1:
                                # AUTO-KICK DO ÚLTIMO GAJO
                                ultimo_sock = sobrantes[0]
                                ultimo_sock.sendall(
                                    f"[SISTEMA]: {nome_utilizador} saiu. Foste removido do grupo por segurança.\n".encode(
                                        'utf-8'))
                                grupos_canais[nome_sala].remove(ultimo_sock)
                                registar_evento_rede("AUTO_KICK", f"Grupo {nome_sala} fechado (sem quorum).")
                            elif len(sobrantes) > 0:
                                # AVISA OS QUE SOBRAM
                                lista_str = ", ".join(integrantes_nomes)
                                aviso = f"[SISTEMA]: {nome_utilizador} saiu. Integrantes atuais: {lista_str}\n".encode(
                                    'utf-8')
                                rotear_mensagem_grupo(nome_sala, aviso, None)

                        conn.sendall(f"[SISTEMA]: Saíste do grupo '{nome_sala}'.\n".encode('utf-8'))
                        canal_atual = None
                    else:
                        conn.sendall("[SISTEMA]: Não estás em nenhum grupo para sair.\n".encode('utf-8'))
                    continue

                # --- COMANDO: FILE (RECEBER DO CLIENTE) ---
                if msg.startswith("FILE:"):
                    try:
                        _, nome_ficheiro, tamanho = msg.split(":")
                        tamanho = int(tamanho)

                        # Defesa Ativa: Sanitização contra Path Traversal
                        nome_seguro = os.path.basename(nome_ficheiro)
                        nome_final_disco = f"recibido_{nome_seguro}"

                        registar_evento_rede("RECEÇÃO_FICHEIRO", f"A receber '{nome_seguro}' de {nome_utilizador}")

                        with open(nome_final_disco, "wb") as f:
                            recebido = 0
                            while recebido < tamanho:
                                dados = conn.recv(min(tamanho - recebido, 4096))
                                if not dados:
                                    break
                                f.write(dados)
                                recebido += len(dados)

                        registar_evento_rede("FIM_RECEÇÃO", f"Guardado com sucesso: '{nome_seguro}'")

                        if canal_atual:
                            # Notifica a sala toda (MENOS quem enviou) c/ a formatação [Grupo] Nome:
                            mensagem_grupo = f"[{canal_atual}] {nome_utilizador}: FILE_LINK_{nome_seguro} (Tamanho: {tamanho} bytes)\n"
                            sucesso = rotear_mensagem_grupo(canal_atual, mensagem_grupo.encode('utf-8'), conn)
                            # Passamos 'conn' p/ o servidor NÃO mandar isto de volta ao gajo q enviou


                            # Responde SÓ ao gajo que enviou com a tag [Tu]:
                            mensagem_remetente = f"[Tu]: FILE_LINK_{nome_seguro} (Tamanho: {tamanho} bytes)\n"
                            conn.sendall(mensagem_remetente.encode('utf-8'))
                        else:
                            # Fallback caso alguém consiga mandar ficheiros fora de grupos
                            conn.sendall(f"[SISTEMA]: FILE_LINK_{nome_seguro} carregado com sucesso.\n".encode('utf-8'))
                    except Exception as e:
                        registar_evento_rede("ERRO_FICHEIRO", f"Falha ao receber: {e}")
                    continue

                    # --- COMANDO: GET_FILE (CORRIGIDO PARA NÃO CAIR A REDE) ---
                if msg.startswith("GET_FILE:"):
                    try:
                        import base64
                        nome_ficheiro = msg.split(":", 1)[1].strip()
                        nome_seguro = os.path.basename(nome_ficheiro)
                        caminho_ficheiro = f"recibido_{nome_seguro}"

                        if os.path.exists(caminho_ficheiro):
                            with open(caminho_ficheiro, "rb") as f:
                                conteudo_binario = f.read()

                            # Converte os bytes puros para uma string de texto Base64
                            conteudo_b64 = base64.b64encode(conteudo_binario).decode('utf-8')

                            # Envia tudo numa linha estruturada segura para a thread do cliente
                            conn.sendall(f"FILE_DATA:{nome_seguro}:{conteudo_b64}\n".encode('utf-8'))
                            registar_evento_rede("DOWNLOAD_CONCLUÍDO",
                                                 f"Enviado '{nome_seguro}' em B64 para {nome_utilizador}")
                        else:
                            conn.sendall("[SISTEMA]: Erro: Ficheiro não encontrado no servidor.\n".encode('utf-8'))
                        ultimo_contacto = time.time()  # <--- METE ISTO AQUI!
                    except Exception as e:
                        registar_evento_rede("ERRO_DOWNLOAD", f"Falha ao processar: {e}")
                    continue

                    # Envio normal de mensagens
                if canal_atual:
                    ultimo_contacto = time.time()
                    pacote_saida = f"[{canal_atual}] {nome_utilizador}: {msg}\n".encode('utf-8')

                    sucesso = rotear_mensagem_grupo(canal_atual, pacote_saida, conn)
                    if not sucesso:
                        conn.sendall(
                            "[SISTEMA]: Acesso negado. O grupo foi desfeito ou foste expulso.\n".encode('utf-8'))
                        canal_atual = None
                else:
                    conn.sendall("[SISTEMA]: Cria ou junta-te a um grupo primeiro.\n".encode('utf-8'))
            except socket.timeout:
                continue
            except Exception:
                break

    desvincular_cliente_de_canais(conn)
    with lock_limitadores:
        if id_sessao in limitadores_clientes:
            del limitadores_clientes[id_sessao]
    registar_evento_rede("LIMPEZA_RECURSOS", f"Recursos libertados para {nome_utilizador}")


def iniciar_servidor():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile="cert.pem", keyfile="chave.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile="cert.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bind_socket:
        bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_socket.bind(('0.0.0.0', 8443))
        bind_socket.listen(10)
        print("Servidor Hub ativo na porta 8443...")

        while True:
            try:
                raw_conn, addr = bind_socket.accept()
                secure_conn = context.wrap_socket(raw_conn, server_side=True)
                threading.Thread(target=tratar_cliente, args=(secure_conn, addr), daemon=True).start()
            except Exception:
                pass


if __name__ == "__main__":
    iniciar_servidor()