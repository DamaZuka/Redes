import socket
import ssl
import threading
import time


class ClienteRedeSegura:
    def __init__(self, host, port, callback_erro=None, callback_mensagem=None, callback_nome=None):
        self.host = host
        self.port = port
        self.socket_seguro = None
        self.ligado = False
        self.callback_erro = callback_erro
        self.callback_mensagem = callback_mensagem
        self.callback_nome = callback_nome
        self.meu_nome = "A ligar..."

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
            print(f"[ERRO PKI] Falha crítica ao carregar credenciais: {e}")
            return False

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(5.0)

        try:
            self.socket_seguro = context.wrap_socket(raw_socket, server_hostname='localhost')
            self.socket_seguro.connect((self.host, self.port))
            self.socket_seguro.settimeout(None)
            self.ligado = True

            threading.Thread(target=self._executar_heartbeat, daemon=True).start()
            threading.Thread(target=self._escutar_servidor, daemon=True).start()

            print("[REDE] Canal de comunicação TLS 1.3 (mTLS) estabelecido.")
            return True
        except Exception as e:
            print(f"[ERRO] Falha ao erguer o canal seguro: {e}")
            self.ligado = False
            return False

    def _executar_heartbeat(self):
        while self.ligado:
            try:
                time.sleep(2)
                if self.socket_seguro and self.ligado:
                    self.socket_seguro.sendall("PING".encode('utf-8'))
            except Exception:
                self._notificar_queda()
                break

    def _escutar_servidor(self):
        while self.ligado:
            try:
                dados = self.socket_seguro.recv(1024)
                if not dados:
                    self._notificar_queda()
                    break

                msg = dados.decode('utf-8')

                # Intercetar identificação dinâmica vinda do servidor
                if msg.startswith("SET_NAME:"):
                    self.meu_nome = msg.split(":", 1)[1]
                    if self.callback_nome:
                        self.callback_nome(self.meu_nome)
                    continue

                if msg != "PONG":
                    if self.callback_mensagem:
                        self.callback_mensagem(msg)
            except Exception:
                self._notificar_queda()
                break

    def _notificar_queda(self):
        if self.ligado:
            self.ligado = False
            if self.socket_seguro:
                try:
                    self.socket_seguro.close()
                except:
                    pass
            if self.callback_erro:
                self.callback_erro()

    def enviar_carga(self, mensagem):
        if self.socket_seguro and self.ligado:
            try:
                self.socket_seguro.sendall(mensagem.encode('utf-8'))
                return True
            except Exception as e:
                self._notificar_queda()
                return False
        return False

    def encerrar_conexao(self):
        self.ligado = False
        if self.socket_seguro:
            try:
                self.socket_seguro.close()
            except:
                pass