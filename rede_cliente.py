import socket
import ssl
import threading
import time


class ClienteRedeSegura:
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

        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        context.load_verify_locations(cafile="cert.pem")

        try:
            context.load_cert_chain(certfile="cert.pem", keyfile="chave.pem")
        except Exception as e:
            print(f"[ERRO PKI] Falha ao carregar credenciais do cliente: {e}")
            return False

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(5.0)  # Timeout de conexão inicial

        try:
            self.socket_seguro = context.wrap_socket(raw_socket, server_hostname='localhost')
            self.socket_seguro.connect((self.host, self.port))
            self.socket_seguro.settimeout(None)  # Remove timeout estático para leitura fluida
            self.ligado = True

            # Iniciar o ciclo de monitorização ativa de disponibilidade (Heartbeat)
            self.thread_heartbeat = threading.Thread(target=self._executar_heartbeat)
            self.thread_heartbeat.daemon = True
            self.thread_heartbeat.start()

            print("[REDE] Conexão com canal de resiliência ativo.")
            return True
        except Exception as e:
            print(f"[ERRO] Falha ao erguer o canal seguro: {e}")
            self.ligado = False
            if self.socket_seguro:
                self.socket_seguro.close()
            return False

    def _executar_heartbeat(self):
        """Rotina em background encarregue de manter o canal aberto (Keep-Alive)."""
        while self.ligado:
            try:
                time.sleep(5)  # Envia um PING a cada 5 segundos
                if self.socket_seguro and self.ligado:
                    # Utilização de um Lock aqui seria ideal se partilhasses o envio
                    # diretamente de múltiplas threads de escrita
                    self.socket_seguro.sendall("PING".encode('utf-8'))
            except Exception:
                print("[REDE] Perda de conectividade detetada no envio de Heartbeat.")
                self.ligado = False
                break

    def enviar_carga(self, mensagem):
        if self.socket_seguro and self.ligado:
            try:
                self.socket_seguro.sendall(mensagem.encode('utf-8'))
            except Exception as e:
                print(f"[ERRO DE TRANSMISSÃO] Falha no envio: {e}")
                self.ligado = False

    def encerrar_conexao(self):
        self.ligado = False
        if self.socket_seguro:
            try:
                self.socket_seguro.close()
                print("[REDE] Canal encerrado com sucesso.")
            except Exception as e:
                print(f"[ERRO] Falha no encerramento forçado do socket: {e}")