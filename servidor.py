import socket
import ssl

# Configuração
HOST = '0.0.0.0'
PORT = 8443


def iniciar_servidor():
    # 1. Configurar o contexto SSL (CP4)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="cert.pem", keyfile="chave.pem")

    # 2. Criar o socket base
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bind_socket:
        bind_socket.bind((HOST, PORT))
        bind_socket.listen(5)
        print(f"Servidor seguro a escutar na porta {PORT}...")

        # 3. Envolver o socket em SSL (Cria o túnel seguro)
        with context.wrap_socket(bind_socket, server_side=True) as secure_server:
            while True:
                try:
                    conn, addr = secure_server.accept()
                    print(f"Ligação segura aceite de: {addr}")

                    with conn:
                        while True:
                            dados = conn.recv(1024)
                            if not dados:
                                break

                            # Tratamento de erro de codificação (Robustez - CP8)
                            try:
                                msg = dados.decode('utf-8')
                                print(f"[Cliente {addr}]: {msg}")
                                conn.sendall("Recebido com seguranca!".encode('utf-8'))
                            except UnicodeDecodeError:
                                print(f"[Aviso] Erro ao decodificar pacote de {addr}")

                except Exception as e:
                    print(f"Erro na ligação: {e}")


if __name__ == "__main__":
    iniciar_servidor()