import socket
import ssl
import threading
import time

HOST = '0.0.0.0'
PORT = 8443

# Configurações da Fase 3
TIMEOUT_CONEXAO = 10.0  # Máximo de segundos em inatividade
INTERVALO_HEARTBEAT_LIMITE = 15.0  # Tempo máximo sem receber Ping/dados do cliente


class RateLimiterTokenBucket:
    """Implementação do algoritmo Token Bucket para mitigar DoS por IP."""

    def __init__(self, capacidade, taxa_reposicao):
        self.capacidade = capacidade
        self.taxa_reposicao = taxa_reposicao  # Tokens por segundo
        self.tokens = capacidade
        self.ultimo_ajuste = time.time()
        self.lock = threading.Lock()

    def consumir(self):
        with self.lock:
            agora = time.time()
            passado = agora - self.ultimo_ajuste
            self.ultimo_ajuste = agora

            # Repor tokens com base no tempo decorrido
            self.tokens = min(self.capacidade, self.tokens + passado * self.taxa_reposicao)

            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


# Dicionário dinâmico para controlo de Rate Limiting por IP (Thread-Safe)
limitadores_ip = {}
lock_limitadores = threading.Lock()


def obter_limitador(ip):
    with lock_limitadores:
        if ip not in limitadores_ip:
            # Capacidade máxima de 5 pacotes, recupera 1 token por segundo
            limitadores_ip[ip] = RateLimiterTokenBucket(capacidade=5, taxa_reposicao=1.0)
        return limitadores_ip[ip]


def tratar_cliente(conn, addr):
    ip_cliente = addr[0]
    limiter = obter_limitador(ip_cliente)
    print(f"[INFO] Conexão segura sob monitorização de resiliência: {addr}")

    # Configurar timeout inicial do socket para operações de I/O
    conn.settimeout(TIMEOUT_CONEXAO)

    ultimo_contacto = time.time()

    with conn:
        while True:
            try:
                # Verificar se o cliente excedeu o tempo de Heartbeat tolerado
                if time.time() - ultimo_contacto > INTERVALO_HEARTBEAT_LIMITE:
                    print(f"[TIMEOUT] Cliente {addr} falhou o Heartbeat. Desconexão proativa.")
                    break

                dados = conn.recv(1024)
                if not dados:
                    break

                ultimo_contacto = time.time()

                # Aplicação do Rate Limiting
                if not limiter.consumir():
                    print(f"[DEFESA - RATE LIMIT] Tráfego abusivo bloqueado para o IP: {ip_cliente}")
                    conn.sendall("ERRO: Limite de taxa excedido. Pacote descartado.".encode('utf-8'))
                    continue

                try:
                    msg = dados.decode('utf-8')

                    # Interpelação do mecanismo de Heartbeat
                    if msg == "PING":
                        conn.sendall("PONG".encode('utf-8'))
                        continue

                    print(f"[Cliente {addr}]: {msg}")
                    conn.sendall("Recebido com integridade sob canal resiliente!".encode('utf-8'))

                except UnicodeDecodeError:
                    print(f"[AVISO] Payload corrompido ou inválido recebido de {addr}")

            except socket.timeout:
                # Validar se o timeout foi por inatividade completa
                if time.time() - ultimo_contacto > INTERVALO_HEARTBEAT_LIMITE:
                    print(f"[TIMEOUT] Canal inativo detetado para {addr}. Libertando recursos.")
                    break
                continue
            except Exception as e:
                print(f"[ERRO] Falha crítica na sessão {addr}: {e}")
                break

    print(f"[INFO] Sessão terminada de forma segura com: {addr}")


def iniciar_servidor():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    context.load_cert_chain(certfile="cert.pem", keyfile="chave.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile="cert.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bind_socket:
        bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_socket.bind((HOST, PORT))
        bind_socket.listen(10)
        print(f"Servidor de Alta Disponibilidade (Fase 3) ativo na porta {PORT}...")

        while True:
            try:
                # O wrap_socket foi movido para o accept individual para mitigar ataques de negação
                # de serviço durante o handshake inicial (Prevenção de bloqueio do loop principal)
                raw_conn, addr = bind_socket.accept()

                # Envolver a conexão em TLS individualmente de forma isolada
                secure_conn = context.wrap_socket(raw_conn, server_side=True)

                cliente_thread = threading.Thread(target=tratar_cliente, args=(secure_conn, addr))
                cliente_thread.daemon = True
                cliente_thread.start()
            except Exception as e:
                print(f"[ERRO] Falha no estabelecimento do aperto de mão criptográfico: {e}")


if __name__ == "__main__":
    iniciar_servidor()