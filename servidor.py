import socket
import ssl

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="cert.pem", keyfile="chave.pem")

bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bind_socket.bind(('0.0.0.0', 8443))
bind_socket.listen(5)

# Envolvemos o socket normal no contexto SSL
secure_server = context.wrap_socket(bind_socket, server_side=True)

while True:
    conn, addr = secure_server.accept()
    print(f"Ligação segura de: {addr}")
    data = conn.recv(1024)
    print(f"Mensagem cifrada recebida: {data.decode('utf-8')}")
    conn.send(b"Mensagem recebida com seguranca!")
    conn.close()