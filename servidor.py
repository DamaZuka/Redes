import socket
import ssl
import threading
import time

HOST = '0.0.0.0'
PORT = 8443

TIMEOUT_SOCKET_CONV = 5.0
INTERVALO_HEARTBEAT_LIMITE = 15.0

# --- GESTÃO DE REDE LÓGICA DE GRUPOS (SRC - REQUISITO TEMA 2) ---
# Tabela de estados em memória para indexar os sockets ativos por sala
grupos_canais = {
    "Geral": [],
    "Privado-SOC": []
}
lock_canais = threading.Lock()


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


# --- FUNÇÕES DE ENCAMINHAMENTO DE FLUXO DE REDE ---
def rotear_mensagem_grupo(canal, pacote_bytes, socket_origem):
    """SRC: Encaminha os bytes recebidos para todos os endpoints do grupo."""
    with lock_canais:
        if canal in grupos_canais:
            for cliente_sock in grupos_canais[canal]:
                if cliente_sock != socket_origem:
                    try:
                        cliente_sock.sendall(pacote_bytes)
                    except Exception:
                        pass


def desvincular_cliente_de_canais(cliente_sock):
    """Garante a limpeza de buffers mortos na tabela de rotas."""
    with lock_canais:
        for canal in grupos_canais:
            if cliente_sock in grupos_canais[canal]:
                grupos_canais[canal].remove(cliente_sock)


def tratar_cliente(conn, addr):
    ip_cliente = addr[0]
    limiter = obter_limitador(ip_cliente)

    # --- SRC (CP4): EXTRAÇÃO DE IDENTIDADE ATRAVÉS DE mTLS ---
    # Extrai o Common Name (CN) do certificado X.509 apresentado pelo cliente
    nome_utilizador = f"Anonimo-{addr[1]}"
    try:
        certificado = conn.getpeercert()
        if certificado and 'subject' in certificado:
            # O subject contém uma lista de tuplos com os dados do proprietário
            for sub_tuplo in certificado['subject']:
                for chave, valor in sub_tuplo:
                    if chave == 'commonName':
                        nome_utilizador = valor
    except Exception as e:
        print(f"[AVISO] Falha ao ler certificado de {addr}: {e}")

    print(f"[INFO] Conexão segura estabelecida. Utilizador Autenticado via mTLS: {nome_utilizador} {addr}")

    conn.settimeout(TIMEOUT_SOCKET_CONV)
    ultimo_contacto = time.time()

    with lock_canais:
        grupos_canais["Geral"].append(conn)
    canal_atual = "Geral"

    with conn:
        while True:
            tempo_decorrido = time.time() - ultimo_contacto
            if tempo_decorrido > INTERVALO_HEARTBEAT_LIMITE:
                print(f"[TIMEOUT] {nome_utilizador} excedeu o limite de Heartbeat. Desconexão forçada.")
                break

            try:
                dados = conn.recv(1024)
                if not dados:
                    print(f"[INFO] {nome_utilizador} encerrou a sessão de forma limpa.")
                    break

                ultimo_contacto = time.time()

                if not limiter.consumir():
                    print(
                        f"[DEFESA - RATE LIMIT] Tráfego abusivo bloqueado para o utilizador: {nome_utilizador} ({ip_cliente})")
                    conn.sendall("ERRO: Limite de taxa excedido. Pacote descartado.".encode('utf-8'))
                    continue

                try:
                    msg = dados.decode('utf-8')

                    if msg == "PING":
                        conn.sendall("PONG".encode('utf-8'))
                        continue

                    if msg.startswith("/join "):
                        alvo = msg.split(" ")[1]
                        with lock_canais:
                            if alvo in grupos_canais:
                                desvincular_cliente_de_canais(conn)
                                grupos_canais[alvo].append(conn)
                                canal_atual = alvo
                                conn.sendall(f"[SISTEMA]: Entraste na sala {alvo}".encode('utf-8'))
                            else:
                                conn.sendall("[SISTEMA]: Erro: Canal inexistente.".encode('utf-8'))
                        continue

                    # PRINT NO TERMINAL DO SERVIDOR (Agora mostra claramente de quem vem)
                    print(f"[{canal_atual}][{nome_utilizador} ({ip_cliente})]: {msg}")

                    # ROTEAMENTO ATIVO (SRC): Propaga a mensagem identificando o emissor autenticado
                    pacote_saida = f"[{canal_atual}] {nome_utilizador}: {msg}".encode('utf-8')
                    rotear_mensagem_grupo(canal_atual, pacote_saida, conn)

                except UnicodeDecodeError:
                    print(f"[AVISO] Erro na decodificação de payload inválido vindo de {nome_utilizador}")

            except socket.timeout:
                continue
            except Exception as e:
                print(f"[ERRO] Falha crítica na sessão de {nome_utilizador}: {e}")
                break

    desvincular_cliente_de_canais(conn)
    print(f"[INFO] Recursos libertados para a sessão de: {nome_utilizador}")

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
        print("Servidor de Alta Disponibilidade (mTLS / TLS 1.3) ativo na porta 8443...")

        while True:
            try:
                raw_conn, addr = bind_socket.accept()
                secure_conn = context.wrap_socket(raw_conn, server_side=True)

                cliente_thread = threading.Thread(target=tratar_cliente, args=(secure_conn, addr))
                cliente_thread.daemon = True
                cliente_thread.start()
            except Exception as e:
                print(f"[ERRO] Falha ao estabelecer o aperto de mão criptográfico: {e}")


if __name__ == "__main__":
    iniciar_servidor()