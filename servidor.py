import socket
import ssl
import threading
import time
import datetime  # Importado para gerar timestamps de alta precisão

HOST = '0.0.0.0'
PORT = 8443

TIMEOUT_SOCKET_CONV = 5.0
INTERVALO_HEARTBEAT_LIMITE = 15.0

grupos_canais = {
    "Geral": [],
    "Privado-SOC": []
}
lock_canais = threading.Lock()

mapeamento_nomes = {}
lock_nomes = threading.Lock()

# --- SUBSISTEMA DE AUDITORIA DE INFRAESTRUTURA (SRC - CP5/CP9) ---
LOCK_LOG = threading.Lock()
FICHEIRO_LOG_REDE = "auditoria_infraestrutura.log"


def registar_evento_rede(categoria, mensagem):
    """
    Persiste eventos de rede com carimbo de data/hora de alta precisão.
    Garante a rastreabilidade e integridade dos registos de segurança.
    """
    agora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    linha_log = f"[{agora}] [{categoria}] {mensagem}\n"
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


limitadores_ip = {}
lock_limitadores = threading.Lock()


def obter_limitador(ip):
    with lock_limitadores:
        if ip not in limitadores_ip:
            limitadores_ip[ip] = RateLimiterTokenBucket(capacidade=5, taxa_reposicao=1.0)
        return limitadores_ip[ip]


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


def desvincular_cliente_de_canais(cliente_sock):
    with lock_canais:
        for canal in grupos_canais:
            if cliente_sock in grupos_canais[canal]:
                grupos_canais[canal].remove(cliente_sock)
    with lock_nomes:
        if cliente_sock in mapeamento_nomes:
            del mapeamento_nomes[cliente_sock]


def tratar_cliente(conn, addr):
    ip_cliente = addr[0]
    limiter = obter_limitador(ip_cliente)
    nome_utilizador = f"Anonimo-{addr[1]}"

    # Validação e auditoria do aperto de mão mTLS (CP4)
    try:
        conn.getpeercert()
        registar_evento_rede("AUTENTICAÇÃO_mTLS", f"Sucesso: Equipamento autenticado via X.509 de {addr}")
    except Exception as e:
        registar_evento_rede("ALERTA_MFT", f"Falha ao ler parâmetros criptográficos de {addr}: {e}")

    conn.settimeout(TIMEOUT_SOCKET_CONV)
    ultimo_contacto = time.time()

    with lock_canais:
        grupos_canais["Geral"].append(conn)
    canal_atual = "Geral"

    registar_evento_rede("ENTRADA_CANAL", f"Utilizador {nome_utilizador} ({ip_cliente}) entrou na sala 'Geral'")

    with conn:
        while True:
            tempo_decorrido = time.time() - ultimo_contacto
            if tempo_decorrido > INTERVALO_HEARTBEAT_LIMITE:
                registar_evento_rede("TIMEOUT_REDE",
                                     f"Forçando encerramento: {nome_utilizador} ({ip_cliente}) falhou o Heartbeat.")
                break

            try:
                dados = conn.recv(1024)
                if not dados:
                    registar_evento_rede("DESCONEXÃO_VOLUNTÁRIA",
                                         f"O utilizador {nome_utilizador} ({ip_cliente}) fechou a sessão.")
                    break

                ultimo_contacto = time.time()

                if not limiter.consumir():
                    registar_evento_rede("DEFESA_RATE_LIMIT", f"Bloqueio de inundação ativa para o IP: {ip_cliente}")
                    conn.sendall("ERRO: Limite de taxa excedido.".encode('utf-8'))
                    continue

                try:
                    msg = dados.decode('utf-8')

                    if msg == "PING":
                        conn.sendall("PONG".encode('utf-8'))
                        continue

                    if msg.startswith("/nick "):
                        novo_nome = msg.split(" ", 1)[1].strip()
                        nome_antigo = nome_utilizador
                        with lock_nomes:
                            mapeamento_nomes[conn] = novo_nome
                            nome_utilizador = novo_nome
                        registar_evento_rede("ALTERAÇÃO_IDENTIDADE",
                                             f"O socket {addr} alterou o nickname de '{nome_antigo}' para '{novo_nome}'")
                        continue

                    if msg.startswith("/join "):
                        alvo = msg.split(" ")[1].strip()
                        with lock_canais:
                            if alvo in grupos_canais:
                                for c in grupos_canais:
                                    if conn in grupos_canais[c]:
                                        grupos_canais[c].remove(conn)
                                grupos_canais[alvo].append(conn)
                                canal_anterior = canal_atual
                                canal_atual = alvo
                                conn.sendall(f"[SISTEMA]: Entraste na sala {alvo}".encode('utf-8'))
                                registar_evento_rede("MUDANÇA_CANAL",
                                                     f"Utilizador '{nome_utilizador}' transitou de '{canal_anterior}' para '{alvo}'")
                            else:
                                conn.sendall("[SISTEMA]: Erro: Canal inexistente.".encode('utf-8'))
                        continue

                    with lock_nomes:
                        exibir_nome = mapeamento_nomes.get(conn, nome_utilizador)

                    print(f"[{canal_atual}][{exibir_nome} ({ip_cliente})]: {msg}")

                    pacote_saida = f"[{canal_atual}] {exibir_nome}: {msg}".encode('utf-8')
                    rotear_mensagem_grupo(canal_atual, pacote_saida, conn)

                except UnicodeDecodeError:
                    registar_evento_rede("ANOMALIA_PAYLOAD", f"Erro de decodificação de bytes vindos de {addr}")

            except socket.timeout:
                continue
            except Exception as e:
                registar_evento_rede("ERRO_SESSÃO", f"Exceção crítica na thread de {nome_utilizador}: {e}")
                break

    desvincular_cliente_de_canais(conn)
    registar_evento_rede("LIMPEZA_RECURSOS", f"Sockets e buffers libertados com sucesso para o endpoint {addr}")


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

        registar_evento_rede("SISTEMA_START", "Servidor Hub de Alta Disponibilidade TLS 1.3 inicializado com sucesso.")
        print("Servidor Hub Multiutilizador (SRC TLS 1.3) ativo na porta 8443...")

        while True:
            try:
                raw_conn, addr = bind_socket.accept()
                secure_conn = context.wrap_socket(raw_conn, server_side=True)

                cliente_thread = threading.Thread(target=tratar_cliente, args=(secure_conn, addr))
                cliente_thread.daemon = True
                cliente_thread.start()
            except Exception as e:
                registar_evento_rede("FALHA_HANDSHAKE", f"Tentativa de conexão abortada durante negociação TLS: {e}")


if __name__ == "__main__":
    iniciar_servidor()