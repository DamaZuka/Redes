import socket
import ssl
import threading
import time

HOST = '0.0.0.0'
PORT = 8443

# Configurações de Tolerância da Fase 3
TIMEOUT_SOCKET_CONV = 5.0  # Timeout curto para evitar bloqueio eterno no recv
INTERVALO_HEARTBEAT_LIMITE = 15.0  # Limite máximo de inatividade (segundos)


class RateLimiterTokenBucket:
    """
    Implementação do algoritmo Token Bucket para controlo de fluxo por IP.
    Garante a mitigação de ataques DoS/DDoS por inundação de pacotes.
    """

    def __init__(self, capacidade, taxa_reposicao):
        self.capacidade = capacidade
        self.taxa_reposicao = taxa_reposicao  # Tokens adicionados por segundo
        self.tokens = capacidade
        self.ultimo_ajuste = time.time()
        self.lock = threading.Lock()

    def consumir(self):
        with self.lock:
            agora = time.time()
            decorrido = agora - self.ultimo_ajuste
            self.ultimo_ajuste = agora

            # Recarrega o balde proporcionalmente ao tempo decorrido
            self.tokens = min(self.capacidade, self.tokens + decorrido * self.taxa_reposicao)

            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


# Estrutura de dados global para monitorização de IPs (Thread-Safe)
limitadores_ip = {}
lock_limitadores = threading.Lock()


def obter_limitador(ip):
    with lock_limitadores:
        if ip not in limitadores_ip:
            # Capacidade máxima de 5 pedidos, recupera 1 token por segundo
            limitadores_ip[ip] = RateLimiterTokenBucket(capacidade=5, taxa_reposicao=1.0)
        return limitadores_ip[ip]


def tratar_cliente(conn, addr):
    """
    Rotina assíncrona executada em thread dedicada para cada sessão ativa.
    Integra validação de relógio em tempo real contra falhas de Heartbeat.
    """
    ip_cliente = addr[0]
    limiter = obter_limitador(ip_cliente)
    print(f"[INFO] Conexão segura estabelecida sob monitorização de resiliência: {addr}")

    # Define o timeout interno do socket para operações I/O não bloqueantes
    conn.settimeout(TIMEOUT_SOCKET_CONV)
    ultimo_contacto = time.time()

    with conn:
        while True:
            # Validação cronológica antes do bloqueio de leitura (Mitigação de conexões mortas)
            tempo_decorrido = time.time() - ultimo_contacto
            if tempo_decorrido > INTERVALO_HEARTBEAT_LIMITE:
                print(
                    f"[TIMEOUT] Cliente {addr} excedeu o limite de Heartbeat ({tempo_decorrido:.1f}s). Desconexão forçada.")
                break

            try:
                dados = conn.recv(1024)
                if not dados:
                    print(f"[INFO] Cliente {addr} encerrou a sessão de forma limpa.")
                    break

                # Atualização imediata do indicador de vivacidade após receção de pacotes
                ultimo_contacto = time.time()

                # Aplicação estrita do algoritmo de Rate Limiting
                if not limiter.consumir():
                    print(f"[DEFESA - RATE LIMIT] Tráfego abusivo bloqueado para o IP: {ip_cliente}")
                    conn.sendall("ERRO: Limite de taxa excedido. Pacote descartado.".encode('utf-8'))
                    continue

                try:
                    msg = dados.decode('utf-8')

                    # Interpelação e resposta ao mecanismo Keep-Alive / Heartbeat
                    if msg == "PING":
                        conn.sendall("PONG".encode('utf-8'))
                        continue

                    print(f"[Cliente {addr}]: {msg}")
                    conn.sendall("Recebido com integridade sob canal resiliente!".encode('utf-8'))

                except UnicodeDecodeError:
                    print(f"[AVISO] Erro na decodificação de payload inválido vindo de {addr}")

            except socket.timeout:
                # O timeout do socket ocorreu. O loop recomeça e valida a inatividade no topo.
                continue
            except Exception as e:
                print(f"[ERRO] Falha crítica na sessão {addr}: {e}")
                break

    print(f"[INFO] Recursos libertados para a sessão: {addr}")


def iniciar_servidor():
    """Inicialização do contexto criptográfico TLS 1.3 mTLS e loop de escuta."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # Imposição restrita de TLS 1.3 (Perfect Forward Secrecy nativo)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    # Carregamento do material criptográfico do servidor
    context.load_cert_chain(certfile="cert.pem", keyfile="chave.pem")

    # Configuração de mTLS: Exigir obrigatoriamente a identidade do cliente
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

                # Encapsulamento TLS individualizado para proteger o loop principal contra DoS no handshake
                secure_conn = context.wrap_socket(raw_conn, server_side=True)

                # Delegação concorrente (Fase 1)
                cliente_thread = threading.Thread(target=tratar_cliente, args=(secure_conn, addr))
                cliente_thread.daemon = True
                cliente_thread.start()
            except Exception as e:
                print(f"[ERRO] Falha ao estabelecer o aperto de mão criptográfico: {e}")


if __name__ == "__main__":
    iniciar_servidor()