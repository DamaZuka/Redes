import socket
import ssl
import threading
import time

#
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
                    self.socket_seguro.sendall("PING\n".encode('utf-8'))
            except Exception:
                self._notificar_queda()
                break

    def _escutar_servidor(self):
        buffer_dados = ""
        while self.ligado:
            try:
                #chunk de leitura
                dados = self.socket_seguro.recv(8192)
                if not dados:
                    self._notificar_queda()
                    break

                # Junta os bytes acabados de chegar ao buffer acumulado
                # O errors='ignore' previne crashes se o TCP cortar um acento a meio
                buffer_dados += dados.decode('utf-8', errors='ignore')

                # Só processa quando tiver a certeza que encontrou o fim da mensagem (\n)
                while '\n' in buffer_dados:
                    # Tira a primeira linha completa do buffer e deixa o resto lá para a próxima
                    linha, buffer_dados = buffer_dados.split('\n', 1)
                    linha = linha.strip()

                    if not linha:
                        continue

                    if linha.startswith("SET_NAME:"):
                        self.meu_nome = linha.split(":", 1)[1]
                        if self.callback_nome:
                            self.callback_nome(self.meu_nome)
                        continue

                    if linha != "PONG":
                        if self.callback_mensagem:
                            self.callback_mensagem(linha)
            except Exception as e:
                self._notificar_queda()
                break

    def _notificar_queda(self):
        if self.ligado:
            self.ligado = False
            if self.socket_seguro:
                try: self.socket_seguro.close()
                except: pass
            if self.callback_erro:
                self.callback_erro()

    def enviar_carga(self, mensagem):
        if self.socket_seguro and self.ligado:
            try:
                # Força o envio com quebra de linha clara
                self.socket_seguro.sendall(f"{mensagem}\n".encode('utf-8'))
                return True
            except Exception:
                self._notificar_queda()
                return False
        return False

    def encerrar_conexao(self):
        self.ligado = False
        if self.socket_seguro:
            try: self.socket_seguro.close()
            except: pass

    def enviar_ficheiro(self, caminho_ficheiro):
        import os
        if not os.path.exists(caminho_ficheiro):
            return False

        nome_ficheiro = os.path.basename(caminho_ficheiro)
        tamanho = os.path.getsize(caminho_ficheiro)

        # Avisa o servidor que vai chegar um ficheiro
        if self.socket_seguro and self.ligado:
            self.socket_seguro.sendall(f"FILE:{nome_ficheiro}:{tamanho}\n".encode('utf-8'))

            # Envia o conteúdo em blocos de 4KB
            with open(caminho_ficheiro, "rb") as f:
                while chunk := f.read(4096):
                    self.socket_seguro.sendall(chunk)
            return True
        return False