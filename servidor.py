import socket

# '0.0.0.0' garante que o servidor escuta em todos os interfaces da rede local
HOST = '0.0.0.0'
PORT = 8443


def iniciar_servidor():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor_socket:
        servidor_socket.bind((HOST, PORT))
        servidor_socket.listen()
        print(f"Servidor a escutar na porta {PORT}...")

        # Aceita a conexão do outro PC
        conexao, endereco = servidor_socket.accept()

        with conexao:
            print(f"Ligação estabelecida com sucesso com: {endereco}")
            while True:
                dados = conexao.recv(1024)
                if not dados:
                    break
                print(f"[Cliente {endereco}]: {dados.decode('utf-8')}")
                conexao.sendall("Recebi a tua mensagem!".encode('utf-8'))


if __name__ == "__main__":
    iniciar_servidor()