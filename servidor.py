import socket
import ssl
import threading
import time
import datetime

HOST = '0.0.0.0'
PORT = 8443

TIMEOUT_SOCKET_CONV = 5.0
INTERVALO_HEARTBEAT_LIMITE = 15.0

# Gestão de grupos e permissões em memória (Fase 1 e Requisitos)
grupos_canais = {}  # {"NomeSala": [socket1, socket2]}
acl_canais = {}  # {"NomeSala": ["Anonimo-12345", "Anonimo-67890"]}

lock_canais = threading.Lock()
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
            destinatarios = list(grupos_canais[canal])
        else:
            return
    for cliente_sock in destinatarios:
        if cliente_sock != socket_origem:
            try:
                cliente_sock.sendall(pacote_bytes)
            except Exception:
                pass


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

    # Envia o ID gerado dinamicamente para o cliente atualizar a UI dele
    try:
        conn.sendall(f"SET_NAME:{nome_utilizador}".encode('utf-8'))
    except Exception:
        conn.close()
        return

    registar_evento_rede("CONEXÃO_ESTABELECIDA", f"Utilizador {nome_utilizador} ligado.")
    ultimos_envios_locais = []

    with conn:
        while True:
            if time.time() - ultimo_contacto > INTERVALO_HEARTBEAT_LIMITE:
                registar_evento_rede("TIMEOUT_REDE", f"Forçando encerramento por inatividade: {nome_utilizador}")
                break

            try:
                dados = conn.recv(1024)
                if not dados:
                    registar_evento_rede("DESCONEXÃO_VOLUNTÁRIA", f"O utilizador {nome_utilizador} fechou a sessão.")
                    break

                try:
                    msg = dados.decode('utf-8').strip()
                except UnicodeDecodeError:
                    registar_evento_rede("ANOMALIA_PAYLOAD", f"Erro de decodificação de bytes de {addr}")
                    continue

                if msg == "PING":
                    ultimo_contacto = time.time()
                    conn.sendall("PONG".encode('utf-8'))
                    continue

                # --- RATE LIMITING ---
                agora_envio = time.time()
                ultimos_envios_locais = [t for t in ultimos_envios_locais if agora_envio - t < 1.5]
                ultimos_envios_locais.append(agora_envio)

                if len(ultimos_envios_locais) > 5 or not limiter.consumir():
                    registar_evento_rede("DEFESA_RATE_LIMIT", f"Inundação bloqueada para: {nome_utilizador}")
                    conn.sendall("ERRO: Limite de taxa excedido. Pacote descartado.\n".encode('utf-8'))
                    continue

                # --- COMANDO: CREATE:NomeSala:Amigo1,Amigo2 ---
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
                                registar_evento_rede("CRIAR_CANAL",
                                                     f"Grupo '{nome_sala}' criado por {nome_utilizador} com ACL: {lista_autorizados}")
                            else:
                                conn.sendall("[SISTEMA]: Erro: Esse grupo já existe.\n".encode('utf-8'))
                    except ValueError:
                        conn.sendall("[SISTEMA]: Erro. Usa: CREATE:NomeSala:Anonimo-X,Anonimo-Y\n".encode('utf-8'))
                    continue

                # --- COMANDO: JOIN:NomeSala ---
                if msg.startswith("JOIN:"):
                    try:
                        nome_sala = msg.split(":", 1)[1].strip()
                    except IndexError:
                        conn.sendall("[SISTEMA]: Erro. Usa: JOIN:NomeSala\n".encode('utf-8'))
                        continue

                    with lock_canais:
                        if nome_sala in acl_canais:
                            if nome_utilizador in acl_canais[nome_sala]:
                                desvincular_cliente_de_canais(conn)
                                grupos_canais[nome_sala].append(conn)
                                canal_atual = nome_sala
                                conn.sendall(f"[SISTEMA]: Entraste no grupo privado '{nome_sala}'.\n".encode('utf-8'))
                                registar_evento_rede("MUDANÇA_CANAL", f"'{nome_utilizador}' entrou em '{nome_sala}'")
                            else:
                                conn.sendall(
                                    "[SISTEMA]: ERRO: Não tens permissão para entrar neste grupo privado.\n".encode(
                                        'utf-8'))
                                registar_evento_rede("VIOLAÇÃO_ACESSO",
                                                     f"Acesso negado para {nome_utilizador} na sala '{nome_sala}'")
                        else:
                            conn.sendall("[SISTEMA]: Erro: Esse grupo não existe.\n".encode('utf-8'))
                    continue

                # Envio normal de mensagens
                if canal_atual:
                    ultimo_contacto = time.time()
                    print(f"[{canal_atual}][{nome_utilizador}]: {msg}")
                    pacote_saida = f"[{canal_atual}] {nome_utilizador}: {msg}\n".encode('utf-8')
                    rotear_mensagem_grupo(canal_atual, pacote_saida, conn)
                else:
                    conn.sendall(
                        "[SISTEMA]: Cria ou junta-te a um grupo primeiro usando CREATE: ou JOIN:\n".encode('utf-8'))

            except socket.timeout:
                continue
            except Exception as e:
                registar_evento_rede("ERRO_SESSÃO", f"Exceção na thread de {nome_utilizador}: {e}")
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

        registar_evento_rede("SISTEMA_START", "Servidor inicializado.")
        print("Servidor Hub Multiutilizador (mTLS) ativo na porta 8443...")

        while True:
            try:
                raw_conn, addr = bind_socket.accept()
                secure_conn = context.wrap_socket(raw_conn, server_side=True)
                threading.Thread(target=tratar_cliente, args=(secure_conn, addr), daemon=True).start()
            except Exception as e:
                registar_evento_rede("FALHA_HANDSHAKE", f"Tentativa de conexão abortada: {e}")


if __name__ == "__main__":
    iniciar_servidor()