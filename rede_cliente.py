import socket
import ssl


class ClienteRedeSegura:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket_seguro = None

    def estabelecer_conexao(self):
        # 1. Configurar contexto para autenticação do Servidor
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        # Imposição estrita de TLS 1.3 e PFS
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        # Ativar verificação do certificado do servidor (Evita Man-in-the-Middle)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False  # Desativado temporariamente para testes com IPs locais (ex: 192.168.x.x)

        # Carregar a CA que o cliente confia para validar o servidor
        context.load_verify_locations(cafile="cert.pem")

        # Configuração do mTLS: Enviar o certificado do cliente para o servidor se autenticar
        try:
            context.load_cert_chain(certfile="cert.pem", keyfile="chave.pem")
        except Exception as e:
            print(f"[ERRO DE CONFIGURAÇÃO] Não foi possível carregar o certificado do cliente para mTLS: {e}")
            return False

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Envolver o socket e estabelecer o aperto de mão criptográfico (Handshake)
            self.socket_seguro = context.wrap_socket(raw_socket, server_hostname='localhost')
            self.socket_seguro.connect((self.host, self.port))
            print("[REDE] Túnel seguro TLS 1.3 (mTLS) estabelecido com sucesso.")
            return True
        except Exception as e:
            print(f"[ERRO DE REDE] Falha ao estabelecer o túnel seguro: {e}")
            if self.socket_seguro:
                self.socket_seguro.close()
            return False

    def enviar_carga(self, mensagem):
        if self.socket_seguro:
            try:
                self.socket_seguro.sendall(mensagem.encode('utf-8'))
                # Opcional: Ler a resposta síncrona do servidor
                resposta = self.socket_seguro.recv(1024)
                print(f"[REDE - Resposta Servidor]: {resposta.decode('utf-8')}")
            except Exception as e:
                print(f"[ERRO DE REDE] Falha na transmissão de dados: {e}")

    def encerrar_conexao(self):
        if self.socket_seguro:
            try:
                self.socket_seguro.close()
                print("[REDE] Conexão segura encerrada de forma limpa.")
            except Exception as e:
                print(f"[ERRO] Falha ao fechar socket: {e}")