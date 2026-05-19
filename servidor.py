import socket
import ssl
import threading

HOST = '0.0.0.0'
PORT = 8443


def tratar_cliente(conn, addr):
    """Rotina concorrente para processamento de cada cliente ativo."""
    print(f"[INFO] Ligação segura estabelecida com: {addr}")
    with conn:
        while True:
            try:
                dados = conn.recv(1024)
                if not dados:
                    break

                try:
                    msg = dados.decode('utf-8')
                    print(f"[Cliente {addr}]: {msg}")
                    conn.sendall("Recebido com seguranca através de canal TLS 1.3 mTLS!".encode('utf-8'))
                except UnicodeDecodeError:
                    print(f"[AVISO] Erro ao decodificar pacote de {addr}")
            except Exception as e:
                print(f"[ERRO] Falha na comunicação com {addr}: {e}")
                break
    print(f"[INFO] Ligação encerrada com: {addr}")


def iniciar_servidor():
    # 1. Configurar o contexto SSL para TLS 1.3 e mTLS Estrito
    # Utiliza-se SERVER_AUTH mas configuramos para exigir obrigatoriamente o certificado do cliente
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # Imposição de TLS 1.3 (Bloqueia TLS 1.2 e inferiores - Prevenção de Downgrade)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    # Carregar os certificados do Servidor para cifrar o canal
    context.load_cert_chain(certfile="cert.pem", keyfile="chave.pem")

    # Configuração de mTLS (Autenticação Mútua): Exigir certificado ao cliente
    context.verify_mode = ssl.CERT_REQUIRED
    # O servidor deve confiar nos certificados assinados pela mesma CA (neste caso, aceita o próprio cert autoassinado)
    context.load_verify_locations(cafile="cert.pem")

    # 2. Criar o socket base TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bind_socket:
        # Permitir reutilizar o endereço imediatamente após reiniciar
        bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_socket.bind((HOST, PORT))
        bind_socket.listen(10)
        print(f"Servidor Seguro (mTLS / TLS 1.3) ativo na porta {PORT}...")

        # 3. Envolver o socket em SSL (Criação do túnel seguro ao nível de transporte)
        with context.wrap_socket(bind_socket, server_side=True) as secure_server:
            while True:
                try:
                    conn, addr = secure_server.accept()
                    # Processamento Assíncrono/Concorrente (Fase 1) para evitar bloqueios
                    cliente_thread = threading.Thread(target=tratar_cliente, args=(conn, addr))
                    cliente_thread.daemon = True
                    cliente_thread.start()
                except Exception as e:
                    print(f"[ERRO] Falha ao aceitar ligação: {e}")


if __name__ == "__main__":
    iniciar_servidor()