import socket
import ssl
import threading
import time


class ClienteRedeSegura:
    """
    Interface de rede segura responsável pelo encapsulamento TLS 1.3,
    autenticação mTLS e gestão autónoma do mecanismo Keep-Alive.
    """

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket_seguro = None
        self.ligado = False
        self.thread_heartbeat = None

    def estabelecer_conexao(self):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        # Ativação da validação obrigatória do certificado do servidor
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False  # Desativado temporariamente para testes locais por IP
        context.load_verify_locations(cafile="cert.pem")

        # Injeção de credenciais do cliente para cumprimento de mTLS
        try:
            context.load_cert_chain(certfile="cert.pem", keyfile="chave.pem")
        except Exception as e:
            print(f"[ERRO PKI] Falha crítica ao carregar credenciais do cliente: {e}")
            return False

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(5.0)  # Timeout limite para estabelecimento da ligação inicial

        try:
            self.socket_seguro = context.wrap_socket(raw_socket, server_hostname='localhost')
            self.socket_seguro.connect((self.host, self.port))

            # Remove o timeout para permitir escuta contínua e assíncrona
            self.socket_seguro.settimeout(None)
            self.ligado = True

            # Inicialização do mecanismo Keep-Alive em background
            self.thread_heartbeat = threading.Thread(target=self._executar_heartbeat)
            self.thread_heartbeat.daemon = True
            self.thread_heartbeat.start()

            print("[REDE] Canal de comunicação TLS 1.3 (mTLS) estabelecido.")
            return True
        except Exception as e:
            print(f"[ERRO] Falha ao erguer o canal seguro: {e}")
            self.ligado = False
            if self.socket_seguro:
                self.socket_seguro.close()
            return False

    def _executar_heartbeat(self):
        """Emissão periódica de pacotes de controlo invisíveis à Camada Aplicacional."""
        while self.ligado:
            try:
                time.sleep(5)  # Intervalo de Keep-Alive (5 segundos)
                if self.socket_seguro and self.ligado:
                    self.socket_seguro.sendall("PING".encode('utf-8'))
            except Exception:
                print("[REDE] Perda de conectividade identificada durante a rotina de Heartbeat.")
                self.ligado = False
                break

    def enviar_carga(self, mensagem):
        if self.socket_seguro and self.ligado:
            try:
                self.socket_seguro.sendall(mensagem.encode('utf-8'))
            except Exception as e:
                print(f"[ERRO] Quebra na transmissão de dados aplicacionais: {e}")
                self.ligado = False

    def encerrar_conexao(self):
        self.ligado = False
        if self.socket_seguro:
            try:
                self.socket_seguro.close()
                print("[REDE] Canal encerrado em conformidade.")
            except Exception as e:
                print(f"[ERRO] Falha no encerramento forçado da infraestrutura: {e}")