import socket
import ssl


class ClienteRedeSegura:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket_seguro = None

    def estabelecer_conexao(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.socket_seguro = context.wrap_socket(raw_socket, server_hostname='localhost')
            self.socket_seguro.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"[ERRO DE REDE] Falha ao estabelecer o túnel seguro: {e}")
            return False

    def enviar_carga(self, mensagem):
        if self.socket_seguro:
            try:
                self.socket_seguro.sendall(mensagem.encode('utf-8'))
            except Exception as e:
                print(f"[ERRO DE REDE] Falha na transmissão de dados: {e}")

    def encerrar_conexao(self):
        if self.socket_seguro:
            self.socket_seguro.close()