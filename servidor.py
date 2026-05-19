import socket
import ssl
import threading
import time

HOST = '0.0.0.0'
PORT = 8443

TIMEOUT_SOCKET_CONV = 5.0
INTERVALO_HEARTBEAT_LIMITE = 15.0

grupos_canais = {
    "Geral": [],
    "Privado-SOC": []
}
lock_canais = threading.Lock()

# Tabela para associar o socket do cliente ao nickname escolhido na app
mapeamento_nomes = {}
lock_nomes = threading.Lock()


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
    with lock_limitadores_ip:
        if ip not in limitadores_ip:
            limitadores_ip[ip] = RateLimiterTokenBucket(capacidade=5, taxa_reposicao=1.0)
        return limitadores_ip[ip]


def rotear_mensagem_grupo(canal, pacote_bytes, socket_origem):
    with lock_canais:
        if canal in grupos_canais:
            for cliente_sock in grupos_canais[canal]:
                if cliente_sock != socket_origem:
                    try:
                        cliente_sock.sendall(pacote_bytes)
                    except Exception:
                        pass


def desvincular_cliente(cliente_sock):
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

    # Identificação base por omissão usando a porta do socket remoto
    nome_utilizador = f"Anonimo-{addr[1]}"

    # Validação mTLS obrigatória do hardware (Apenas logs de auditoria de rede)
    try:
        cert = conn.getpeercert()
        print(f"[AUDITORIA mTLS] Máquina validada via certificado X.509 de: {addr}")
    except Exception:
        pass

    conn.settimeout(TIMEOUT_SOCKET_CONV)
    ultimo_contacto = time.time()

    with lock_canais:
        grupos_canais["Geral"].append(conn)
    canal_atual = "Geral"

    with conn:
        while True:
            tempo_decorrido = time.time() - ultimo_contacto
            if tempo_decorrido > INTERVALO_HEARTBEAT_LIMITE:
                print(f"[TIMEOUT] {nome_utilizador} excedeu o limite de Heartbeat. Forçando desconexão.")
                break

            try:
                dados = conn.recv(1024)
                if not dados:
                    break

                ultimo_contacto = time.time()

                if not limiter.consumir():
                    print(f"[DEFESA - RATE LIMIT] Saturação de tráfego para: {nome_utilizador}")
                    conn.sendall("ERRO: Limite de taxa excedido.".encode('utf-8'))
                    continue

                try:
                    msg = dados.decode('utf-8')

                    if msg == "PING":
                        conn.sendall("PONG".encode('utf-8'))
                        continue

                    # Comando interno para registar o nickname dinâmico da app
                    if msg.startswith("/nick "):
                        novo_nome = msg.split(" ", 1)[1].strip()
                        with lock_nomes:
                            mapeamento_nomes[conn] = novo_nome
                            nome_utilizador = novo_nome
                        print(f"[SISTEMA] {addr} registou o nickname: {nome_utilizador}")
                        continue

                    if msg.startswith("/join "):
                        alvo = msg.split(" ")[1]
                        with lock_canais:
                            if alvo in grupos_canais:
                                with lock_canais:
                                    for c in grupos_canais:
                                        if conn in grupos_canais[c]: grupos_canais[c].remove(conn)
                                    grupos_canais[alvo].append(conn)
                                canal_atual = alvo
                                conn.sendall(f"[SISTEMA]: Entraste na sala {alvo}".encode('utf-8'))
                            else:
                                conn.sendall("[SISTEMA]: Erro: Canal inexistente.".encode('utf-8'))
                        continue

                    # Recupera o nickname dinâmico para formatação do tráfego
                    with lock_nomes:
                        exibir_nome = mapeamento_nomes.get(conn, nome_utilizador)

                    print(f"[{canal_atual}][{exibir_nome} ({ip_cliente})]: {msg}")

                    # Roteamento ativo contendo a tag de identificação dinâmica
                    pacote_saida = f"[{canal_atual}] {exibir_nome}: {msg}".encode('utf-8')
                    rotear_mensagem_grupo(canal_atual, pacote_saida, conn)

                except UnicodeDecodeError:
                    print(f"[AVISO] Erro ao decodificar payload de {addr}")

            except socket.timeout:
                continue
            except Exception as e:
                print(f"[ERRO] Falha na sessão de {nome_utilizador}: {e}")
                break

    desvincular_cliente(conn)
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
        print("Servidor Hub Multiutilizador (SRC TLS 1.3) ativo na porta 8443...")

        while True:
            try:
                raw_conn, addr = bind_socket.accept()
                secure_conn = context.wrap_socket(raw_conn, server_side=True)

                cliente_thread = threading.Thread(target=tratar_cliente, args=(secure_conn, addr))
                cliente_thread.daemon = True
                cliente_thread.start()
            except Exception as e:
                print(f"[ERRO] Falha no handshake: {e}")


if __name__ == "__main__":
    iniciar_servidor()