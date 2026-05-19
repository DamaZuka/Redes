import socket
import ssl
import threading
import time
import datetime

HOST = '0.0.0.0'
PORT = 8443

TIMEOUT_SOCKET_CONV = 5.0
INTERVALO_HEARTBEAT_LIMITE = 15.0

grupos_canais = {
    "Geral": [],
    "Privado-SOC": []
}
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
    for cliente_sock in destinatarios:
        if cliente_sock != socket_origem:
            try:
                cliente_sock.sendall(pacote_bytes)
            except Exception:
                pass


def desvincular_cliente_de_canais(cliente_sock, identificador_socket):
    with lock_canais:
        for canal in grupos_canais:
            if cliente_sock in grupos_canais[canal]:
                grupos_canais[canal].remove(cliente_sock)
    with lock_limitadores:
        if identificador_socket in limitadores_clientes:
            del limitadores_clientes[identificador_socket]


def tratar_cliente(conn, addr):
    ip_cliente = addr[0]
    porta_cliente = addr[1]
    id_sessao = (ip_cliente, porta_cliente)
    limiter = obter_limitador_cliente(id_sessao)

    nome_utilizador = f"Anonimo-{porta_cliente}"

    try:
        conn.getpeercert()
        registar_evento_rede("AUTENTICAÇÃO_mTLS", f"Sucesso: Equipamento validado via X.509 de {addr}")
    except Exception as e:
        registar_evento_rede("ALERTA_MFT", f"Falha na leitura de {addr}: {e}")

    conn.settimeout(TIMEOUT_SOCKET_CONV)
    ultimo_contacto = time.time()

    with lock_canais:
        grupos_canais["Geral"].append(conn)
    canal_atual = "Geral"

    registar_evento_rede("ENTRADA_CANAL", f"Utilizador {nome_utilizador} entrou na sala 'Geral'")

    ultimos_envios_locais = []

    with conn:
        while True:
            tempo_decorrido = time.time() - ultimo_contacto
            if tempo_decorrido > INTERVALO_HEARTBEAT_LIMITE:
                registar_evento_rede("TIMEOUT_REDE",
                                     f"Forçando encerramento: {nome_utilizador} falhou o Heartbeat por inatividade.")
                break

            try:
                dados = conn.recv(1024)
                if not dados:
                    registar_evento_rede("DESCONEXÃO_VOLUNTÁRIA", f"O utilizador {nome_utilizador} fechou a sessão.")
                    break

                try:
                    msg = dados.decode('utf-8')
                except UnicodeDecodeError:
                    registar_evento_rede("ANOMALIA_PAYLOAD", f"Erro de decodificação de bytes de {addr}")
                    continue

                # --- TRATAMENTO CRÍTICO DE HEARTBEAT (SRC - Fase 3) ---
                # Se for tráfego de controlo (PING), atualiza o contacto e responde PONG imediatamente.
                # Não consome tokens do Rate Limiter para evitar falsos positivos por inatividade.
                if msg == "PING":
                    ultimo_contacto = time.time()
                    conn.sendall("PONG".encode('utf-8'))
                    continue

                # --- FILTRO DE INUNDAÇÃO (Apenas para mensagens de texto) ---
                agora_envio = time.time()
                ultimos_envios_locais = [t for t in ultimos_envios_locais if agora_envio - t < 1.5]
                ultimos_envios_locais.append(agora_envio)

                if len(ultimos_envios_locais) > 5 or not limiter.consumir():
                    registar_evento_rede("DEFESA_RATE_LIMIT",
                                         f"Inundação bloqueada para o utilizador: {nome_utilizador}")
                    conn.sendall("ERRO: Limite de taxa excedido. Pacote descartado.".encode('utf-8'))
                    continue

                if msg.startswith("/join "):
                    alvo = msg.split(" ")[1].strip()
                    with lock_canais:
                        if alvo in grupos_canais:
                            for c in grupos_canais:
                                if conn in grupos_canais[c]:
                                    grupos_canais[c].remove(conn)
                            grupos_canais[alvo].append(conn)
                            canal_atual = alvo
                            conn.sendall(f"[SISTEMA]: Entraste na sala {alvo}".encode('utf-8'))
                            registar_evento_rede("MUDANÇA_CANAL", f"Utilizador '{nome_utilizador}' mudou para '{alvo}'")
                        else:
                            conn.sendall("[SISTEMA]: Erro: Canal inexistente.".encode('utf-8'))
                    continue

                # Atualiza o timestamp de contacto para tráfego aplicacional lícito
                ultimo_contacto = time.time()

                print(f"[{canal_atual}][{nome_utilizador} ({ip_cliente})]: {msg}")
                pacote_saida = f"[{canal_atual}] {nome_utilizador}: {msg}".encode('utf-8')
                rotear_mensagem_grupo(canal_atual, pacote_saida, conn)

            except socket.timeout:
                continue
            except Exception as e:
                registar_evento_rede("ERRO_SESSÃO", f"Exceção na thread de {nome_utilizador}: {e}")
                break

    desvincular_cliente_de_canais(conn, id_sessao)
    registar_evento_rede("LIMPEZA_RECURSOS", f"Recursos libertados para o utilizador {nome_utilizador}")


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
        print("Servidor Hub Multiutilizador (SRC TLS 1.3) ativo na porta 8443...")

        while True:
            try:
                raw_conn, addr = bind_socket.accept()
                secure_conn = context.wrap_socket(raw_conn, server_side=True)

                cliente_thread = threading.Thread(target=tratar_cliente, args=(secure_conn, addr))
                cliente_thread.daemon = True
                cliente_thread.start()
            except Exception as e:
                registar_evento_rede("FALHA_HANDSHAKE", f"Tentativa de conexão abortada: {e}")


if __name__ == "__main__":
    iniciar_servidor()