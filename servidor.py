import socket
import ssl
import threading
import time
import datetime
import os

HOST = '0.0.0.0'
PORT = 8443

TIMEOUT_SOCKET_CONV = 5.0
INTERVALO_HEARTBEAT_LIMITE = 15.0

grupos_canais = {}
nomes_clientes = {}
acl_canais = {}
limitadores_clientes = {}
lock_limitadores = threading.Lock()

# RLock em vez de Lock para o servidor não congelar no JOIN
lock_canais = threading.RLock()
LOCK_LOG = threading.Lock()
FICHEIRO_LOG_REDE = "auditoria_infraestrutura.log"

# --- SISTEMA DE PROTEÇÃO FAIL2BAN ---
tentativas_falhadas = {}
contagem_bans = {}
ips_mutados = {}             # Guarda até quando o IP está silenciado (mute): { '192.168.1.5': timestamp }
ips_banidos_permanentes = set() # Guarda os IPs efetivamente banidos: { '192.168.1.5' }
MAX_FALHAS = 5               # Ajustado para 5 infrações para acionar uma penalização
lock_fail2ban = threading.Lock()

# Controlo de concorrência por IP
conexoes_por_ip = {}
lock_conexoes = threading.Lock()
MAX_CONEXOES_POR_IP = 3 # Limite de conexões simultâneas para o mesmo IP

def registar_evento_rede(categoria, message):
    agora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    linha_log = f"[{agora}] [{categoria}] {message}\n"
    with LOCK_LOG:
        with open(FICHEIRO_LOG_REDE, "a", encoding="utf-8") as f:
            f.write(linha_log)

# Limite máximo de tamanho de ficheiro (15 MB em bytes)
MAX_FILE_SIZE = 15 * 1024 * 1024

class RateLimiterTokenBucket:
    def __init__(self, capacidade, taxa_reposicao):
        self.capacidade = capacidade
        self.taxa_reposicao = taxa_reposicao
        self.tokens = capacidade
        self.ultimo_ajuste = time.time()
        self.lock = threading.Lock()

    def consumir(self):
        with self.lock:
            agora = time.time()
            decorrido = agora - self.ultimo_ajuste
            self.ultimo_ajuste = agora
            self.tokens = min(self.capacidade, self.tokens + decorrido * self.taxa_reposicao)
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False



def ip_esta_banido(ip):
    with lock_fail2ban:
        return ip in ips_banidos_permanentes

def obter_limitador_cliente(identificador_socket):
    with lock_limitadores:
        if identificador_socket not in limitadores_clientes:
            limitadores_clientes[identificador_socket] = RateLimiterTokenBucket(capacidade=5, taxa_reposicao=2.0)
        return limitadores_clientes[identificador_socket]


def rotear_mensagem_grupo(canal, pacote_bytes, socket_origem):
    with lock_canais:
        if canal in grupos_canais:
            # Se o socket tentar mandar msg mas já levou auto-kick, bloqueia!
            if socket_origem is not None and socket_origem not in grupos_canais[canal]:
                return False
            destinatarios = list(grupos_canais[canal])
        else:
            return False

    for cliente_sock in destinatarios:
        if cliente_sock != socket_origem:
            try:
                cliente_sock.sendall(pacote_bytes)
            except Exception:
                pass
    return True

def desvincular_cliente_de_canais(cliente_sock):
    with lock_canais:
        for canal in list(grupos_canais.keys()):
            if cliente_sock in grupos_canais[canal]:
                grupos_canais[canal].remove(cliente_sock)


def tratar_cliente(conn, addr):
    ip_cliente = addr[0]
    porta_cliente = addr[1]
    id_sessao = (ip_cliente, porta_cliente)
    limiter = obter_limitador_cliente(id_sessao)

    nome_utilizador = f"Anonimo-{porta_cliente}"
    nomes_clientes[conn] = nome_utilizador

    try:
        conn.getpeercert()
        registar_evento_rede("AUTENTICAÇÃO_mTLS", f"Sucesso: Equipamento validado de {addr}")
    except Exception as e:
        registar_evento_rede("ALERTA_MFT", f"Falha mTLS de {addr}: {e}")
        conn.close()
        return

    conn.settimeout(TIMEOUT_SOCKET_CONV)
    ultimo_contacto = time.time()
    canal_atual = None

    # Envia o nome com uma quebra de linha para o recv do cliente não bloquear
    try:
        conn.sendall(f"SET_NAME:{nome_utilizador}\n".encode('utf-8'))
    except Exception:
        conn.close()
        return

    registar_evento_rede("CONEXÃO_ESTABELECIDA", f"Utilizador {nome_utilizador} ligado.")
    ultimos_envios_locais = []

    try:
        with conn:
            while True:
                if ip_esta_banido(ip_cliente):
                    if canal_atual:
                        nome_sala = canal_atual
                        canal_atual = None
                        with lock_canais:
                            if conn in grupos_canais.get(nome_sala, []):
                                grupos_canais[nome_sala].remove(conn)

                        rotear_mensagem_grupo(nome_sala,
                                              f"[SISTEMA]: {nome_utilizador} foi removido pelo servidor.\n".encode(
                                                  'utf-8'),
                                              None)
                        processar_saida_e_kick(nome_sala, nome_utilizador)

                    try:
                        conn.sendall("[SISTEMA]: O teu IP está banido. Sessão terminada.\n".encode('utf-8'))
                        time.sleep(0.1)
                    except:
                        pass
                    break

                # Verificação redundante de inatividade antes de tentar ler do socket
                if time.time() - ultimo_contacto > INTERVALO_HEARTBEAT_LIMITE:
                    registar_evento_rede("TIMEOUT_REDE", f"Forçando encerramento (Pre-recv): {nome_utilizador}")
                    break

                try:
                    # Timeout curto para o recv não bloquear a thread indefinidamente se a janela fechar
                    conn.settimeout(1.0)
                    dados = conn.recv(1024)

                    # SE O CLIENTE FECHOU A JANELA BRUSCAMENTE, O SOCKET DEVOLVE VAZIO (b'')
                    if not dados:
                        registar_evento_rede("DESCONEXÃO_JANELA", f"Utilizador {nome_utilizador} fechou a aplicação.")
                        break

                    try:
                        msg = dados.decode('utf-8').strip()
                    except UnicodeDecodeError:
                        continue

                    if msg == "PING":
                        ultimo_contacto = time.time()
                        conn.sendall("PONG\n".encode('utf-8'))
                        continue

                    # --- VERIFICAÇÃO DE MUTE (Prioridade Máxima) ---
                    with lock_fail2ban:
                        is_muted = False
                        restante = 0
                        if ip_cliente in ips_mutados:
                            agora = time.time()
                            if agora < ips_mutados[ip_cliente]:
                                is_muted = True
                                restante = int(ips_mutados[ip_cliente] - agora)
                            else:
                                del ips_mutados[ip_cliente]

                    if is_muted:
                        try:
                            conn.sendall(
                                f"[SISTEMA]: Mensagem não enviada! Ainda estás banido temporariamente (faltam {restante} segundos).\n".encode(
                                    'utf-8'))
                        except:
                            pass
                        continue

                    # --- RATE LIMITING E FAIL2BAN ---
                    agora_envio = time.time()
                    ultimos_envios_locais = [t for t in ultimos_envios_locais if agora_envio - t < 1.5]
                    ultimos_envios_locais.append(agora_envio)

                    if len(ultimos_envios_locais) > 5 or not limiter.consumir():
                        registar_evento_rede("DEFESA_RATE_LIMIT", f"Inundação de: {nome_utilizador}")

                        foi_punido, tempo_castigo, tipo_punicao = registar_falha_ip(ip_cliente)

                        if foi_punido:
                            if tipo_punicao == "BAN":
                                if canal_atual:
                                    nome_sala = canal_atual
                                    canal_atual = None
                                    with lock_canais:
                                        if conn in grupos_canais.get(nome_sala, []):
                                            grupos_canais[nome_sala].remove(conn)

                                    rotear_mensagem_grupo(nome_sala,
                                                          f"[SISTEMA]: {nome_utilizador} foi banido permanentemente por abusos na rede.\n".encode(
                                                              'utf-8'), None)
                                    processar_saida_e_kick(nome_sala, nome_utilizador)

                                try:
                                    conn.sendall(
                                        "[SISTEMA]: Foste banido PERMANENTEMENTE por abusos na rede. Ligação terminada.\n".encode(
                                            'utf-8'))
                                    time.sleep(0.1)
                                except:
                                    pass
                                break

                            elif tipo_punicao == "MUTE":
                                try:
                                    conn.sendall(
                                        f"[SISTEMA]: Foste silenciado temporariamente por {tempo_castigo}s devido a flood!\n".encode(
                                            'utf-8'))
                                except:
                                    pass

                                if canal_atual:
                                    rotear_mensagem_grupo(canal_atual,
                                                          f"[SISTEMA]: O utilizador {nome_utilizador} foi silenciado por {tempo_castigo}s por spammar.\n".encode(
                                                              'utf-8'), conn)
                                continue

                        try:
                            conn.sendall("[SISTEMA]: Limite de taxa excedido. Pacote descartado.\n".encode('utf-8'))
                        except:
                            pass
                        continue

                    # --- COMANDO: CREATEJ (Criar e entrar automaticamente) ---
                    if msg.startswith("CREATEJ:"):
                        try:
                            _, nome_sala, convidados = msg.split(":", 2)
                            lista_autorizados = [u.strip() for u in convidados.split(",")]
                            lista_autorizados.append(nome_utilizador)

                            with lock_canais:
                                if nome_sala not in acl_canais:
                                    esta_em_grupo = any(conn in membros for membros in grupos_canais.values())
                                    if esta_em_grupo:
                                        conn.sendall(
                                            "[SISTEMA]: Erro: Já estás num grupo. Dá 'LEAVE' primeiro!\n".encode(
                                                'utf-8'))
                                    else:
                                        acl_canais[nome_sala] = lista_autorizados
                                        grupos_canais[nome_sala] = [conn]
                                        canal_atual = nome_sala

                                        conn.sendall(
                                            f"[SISTEMA]: Grupo '{nome_sala}' criado. Entraste automaticamente.\n".encode(
                                                'utf-8'))
                                        registar_evento_rede("CRIAR_E_ENTRAR",
                                                             f"'{nome_utilizador}' criou e entrou em '{nome_sala}'")
                                else:
                                    conn.sendall("[SISTEMA]: Erro: Esse grupo já existe.\n".encode('utf-8'))
                        except ValueError:
                            conn.sendall("[SISTEMA]: Erro. Usa: CREATEJ:NomeSala:User1,User2\n".encode('utf-8'))
                        continue

                    # --- COMANDO: JOIN ---
                    if msg.startswith("JOIN:"):
                        nome_sala = msg.split(":", 1)[1].strip()

                        with lock_canais:
                            # Verifica se já está num grupo
                            esta_em_grupo = any(conn in membros for membros in grupos_canais.values())
                            if esta_em_grupo:
                                conn.sendall(
                                    "[SISTEMA]: Erro: Já estás num grupo. Dá 'LEAVE' primeiro!\n".encode('utf-8'))
                                continue

                            if nome_sala in acl_canais:
                                if nome_utilizador in acl_canais[nome_sala]:
                                    desvincular_cliente_de_canais(conn)
                                    grupos_canais[nome_sala].append(conn)
                                    canal_atual = nome_sala

                                    # --- LISTAR QUEM ESTÁ LÁ (Segurança e Consciência de Contexto) ---
                                    membros = grupos_canais[nome_sala]
                                    outros = [nomes_clientes.get(m, "Desconhecido") for m in membros if m != conn]

                                    if outros:
                                        lista_str = ", ".join(outros)
                                        conn.sendall(
                                            f"[SISTEMA]: Entraste no grupo '{nome_sala}'. Integrantes: {lista_str}.\n".encode(
                                                'utf-8'))
                                    else:
                                        conn.sendall(
                                            f"[SISTEMA]: Entraste no grupo '{nome_sala}'.  Integrantes: {lista_str}: \n".encode(
                                                'utf-8'))

                                    registar_evento_rede("MUDANÇA_CANAL", f"'{nome_utilizador}' em '{nome_sala}'")

                                    # Avisa os outros que alguém entrou
                                    msg_aviso = f"[SISTEMA]: {nome_utilizador} entrou no grupo.\n".encode('utf-8')
                                    rotear_mensagem_grupo(canal_atual, msg_aviso, conn)
                                else:
                                    conn.sendall(
                                        "[SISTEMA]: ERRO: Sem permissão para este grupo.\n".encode('utf-8'))
                                    registar_evento_rede("VIOLAÇÃO_ACESSO",
                                                         f"Negado {nome_utilizador} em '{nome_sala}'")
                            else:
                                conn.sendall("[SISTEMA]: Erro: Esse grupo não existe.\n".encode('utf-8'))
                        continue

                    # --- COMANDO: LEAVE ---
                    if msg == "LEAVE":
                        if canal_atual:
                            nome_sala = canal_atual

                            with lock_canais:
                                if conn in grupos_canais.get(nome_sala, []):
                                    grupos_canais[nome_sala].remove(conn)

                                sobrantes = grupos_canais.get(nome_sala, [])

                                if len(sobrantes) < 2:
                                    processar_saida_e_kick(nome_sala, nome_utilizador)
                                else:
                                    integrantes_nomes = [nomes_clientes.get(c, "Desconhecido") for c in sobrantes]
                                    lista_str = ", ".join(integrantes_nomes)
                                    aviso = f"[SISTEMA]: {nome_utilizador} saiu. Integrantes atuais: {lista_str}\n".encode(
                                        'utf-8')
                                    rotear_mensagem_grupo(nome_sala, aviso, None)

                            conn.sendall(f"[SISTEMA]: Saíste do grupo '{nome_sala}'.\n".encode('utf-8'))
                            canal_atual = None
                        else:
                            conn.sendall("[SISTEMA]: Não estás em nenhum grupo para sair.\n".encode('utf-8'))
                        continue

                    # --- COMANDO: FILE ---
                    if msg.startswith("FILE:"):
                        try:
                            _, nome_ficheiro, tamanho = msg.split(":")
                            tamanho = int(tamanho)

                            # [Step 3] VALIDAÇÃO DE TAMANHO (Disk Filling)
                            if tamanho > MAX_FILE_SIZE:
                                registar_evento_rede("ALERTA_STORAGE",
                                                     f"Upload recusado: {nome_utilizador} tentou enviar {tamanho} bytes (Máximo: {MAX_FILE_SIZE})")
                                conn.sendall(
                                    "[SISTEMA]: Erro: O ficheiro excede o tamanho máximo permitido pelo servidor.\n".encode(
                                        'utf-8'))
                                continue  # Aborta o processamento deste comando e limpa o buffer

                            # [Step 2] Limpeza de Path Traversal (o que já tinhas)
                            nome_seguro = os.path.basename(nome_ficheiro)
                            nome_final_disco = f"recibido_{nome_seguro}"

                            registar_evento_rede("RECEÇÃO_FICHEIRO",
                                                 f"A receber '{nome_seguro}' de {nome_utilizador} ({tamanho} bytes)")

                            with open(nome_final_disco, "wb") as f:
                                recebido = 0
                                while recebido < tamanho:
                                    # O min() garante que não tentas ler mais do que o ficheiro realmente tem
                                    dados_file = conn.recv(min(tamanho - recebido, 4096))
                                    if not dados_file:
                                        break
                                    f.write(dados_file)
                                    recebido += len(dados_file)

                            registar_evento_rede("FIM_RECEÇÃO", f"Guardado com sucesso: '{nome_seguro}'")

                            if canal_atual:
                                mensagem_grupo = f"[{canal_atual}] {nome_utilizador}: FILE_LINK_{nome_seguro} (Tamanho: {tamanho} bytes)\n"
                                rotear_mensagem_grupo(canal_atual, mensagem_grupo.encode('utf-8'), conn)
                                mensagem_remetente = f"[Tu]: FILE_LINK_{nome_seguro} (Tamanho: {tamanho} bytes)\n"
                                conn.sendall(mensagem_remetente.encode('utf-8'))
                            else:
                                conn.sendall(
                                    f"[SISTEMA]: FILE_LINK_{nome_seguro} carregado com sucesso.\n".encode('utf-8'))
                        except Exception as e:
                            registar_evento_rede("ERRO_FICHEIRO", f"Falha ao receber: {e}")
                        continue

                    # --- COMANDO: GET_FILE ---
                    if msg.startswith("GET_FILE:"):
                        try:
                            import base64
                            nome_ficheiro = msg.split(":", 1)[1].strip()
                            nome_seguro = os.path.basename(nome_ficheiro)
                            caminho_ficheiro = f"recibido_{nome_seguro}"

                            if os.path.exists(caminho_ficheiro):
                                with open(caminho_ficheiro, "rb") as f:
                                    conteudo_binario = f.read()

                                conteudo_b64 = base64.b64encode(conteudo_binario).decode('utf-8')
                                conn.sendall(f"FILE_DATA:{nome_seguro}:{conteudo_b64}\n".encode('utf-8'))
                                registar_evento_rede("DOWNLOAD_CONCLUÍDO",
                                                     f"Enviado '{nome_seguro}' em B64 para {nome_utilizador}")
                            else:
                                conn.sendall("[SISTEMA]: Erro: Ficheiro não encontrado no servidor.\n".encode('utf-8'))
                            ultimo_contacto = time.time()
                        except Exception as e:
                            registar_evento_rede("ERRO_DOWNLOAD", f"Falha ao processar: {e}")
                        continue

                    # Envio normal de mensagens
                    if canal_atual:
                        ultimo_contacto = time.time()
                        pacote_saida = f"[{canal_atual}] {nome_utilizador}: {msg}\n".encode('utf-8')

                        sucesso = rotear_mensagem_grupo(canal_atual, pacote_saida, conn)
                        if not sucesso:
                            conn.sendall(
                                "[SISTEMA]: Acesso negado. O grupo foi desfeito ou foste expulso.\n".encode('utf-8'))
                            canal_atual = None
                    else:
                        conn.sendall("[SISTEMA]: Cria ou junta-te a um grupo primeiro.\n".encode('utf-8'))

                except socket.timeout:
                    # Captura o timeout de 1s e avalia se o tempo total sem PINGs violou o limite do heartbeat
                    if time.time() - ultimo_contacto > INTERVALO_HEARTBEAT_LIMITE:
                        registar_evento_rede("TIMEOUT_REDE",
                                             f"Forçando encerramento (Heartbeat expirado): {nome_utilizador}")
                        break
                    continue
                except Exception as e:
                    registar_evento_rede("ERRO_REDE_INTERNO", f"Erro na leitura de {nome_utilizador}: {e}")
                    break
    finally:
        # --- BLOCO OBRIGATÓRIO DE LIMPEZA ABSOLUTA AO SAIR DO LOOP ---
        if canal_atual:
            nome_sala_abortada = canal_atual
            with lock_conexoes:
                if ip_cliente in conexoes_por_ip:
                    conexoes_por_ip[ip_cliente] -= 1
                    if conexoes_por_ip[ip_cliente] <= 0:
                        del conexoes_por_ip[ip_cliente]

            registar_evento_rede("LIMPEZA_RECURSOS", f"Recursos totalmente libertados para {nome_utilizador}")

            # Avisa os restantes e valida se a sala deve fechar por falta de membros
            rotear_mensagem_grupo(nome_sala_abortada,
                                  f"[SISTEMA]: {nome_utilizador} fechou a conversa.\n".encode('utf-8'),
                                  None)
            processar_saida_e_kick(nome_sala_abortada, nome_utilizador)

        desvincular_cliente_de_canais(conn)

        with lock_limitadores:
            if id_sessao in limitadores_clientes:
                del limitadores_clientes[id_sessao]

        if conn in nomes_clientes:
            del nomes_clientes[conn]

        registar_evento_rede("LIMPEZA_RECURSOS", f"Recursos totalmente libertados para {nome_utilizador}")
def processar_saida_e_kick(nome_sala, nome_utilizador=None):
    with lock_canais:
        if nome_sala in grupos_canais:
            membros = grupos_canais[nome_sala]

            # SE A REGRA É: Se ficar menos que X pessoas, todos saem
            # (Exemplo: se ficarem menos de 2, fechamos tudo)
            if len(membros) < 2:
                for sock in list(membros):
                    try:
                        # Manda o aviso
                        sock.sendall(
                            f"[SISTEMA]: Grupo '{nome_sala}' fechado por falta de integrantes. Foste removido.\n".encode(
                                'utf-8'))

                        # Precisas de uma forma de avisar a thread que a variável canal_atual deve ser None
                        # Como estás dentro da thread do cliente, podes simplesmente remover da lista
                        grupos_canais[nome_sala].remove(sock)
                    except:
                        pass
                # Remove o canal todo
                del grupos_canais[nome_sala]
                del acl_canais[nome_sala]
                registar_evento_rede("AUTO_KICK", f"Grupo {nome_sala} dissolvido.")


def registar_falha_ip(ip):
    with lock_fail2ban:
        tentativas_falhadas[ip] = tentativas_falhadas.get(ip, 0) + 1

        if tentativas_falhadas[ip] >= MAX_FALHAS:
            contagem_bans[ip] = contagem_bans.get(ip, 0) + 1
            tentativas_falhadas[ip] = 0 # Reset para voltar a contar as próximas 5 falhas

            if contagem_bans[ip] >= 3:
                ips_banidos_permanentes.add(ip)
                registar_evento_rede("FAIL2BAN", f"IP {ip} banido PERMANENTEMENTE (3ª infração grave).")
                return True, 0, "BAN"
            else:
                tempo = 30 * contagem_bans[ip] # 1ª vez: 30s, 2ª vez: 60s
                ips_mutados[ip] = time.time() + tempo
                registar_evento_rede("FAIL2BAN", f"IP {ip} mutado por {tempo}s.")
                return True, tempo, "MUTE"

        return False, 0, "NADA"

def iniciar_servidor():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile="cert.pem", keyfile="chave.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile="cert.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bind_socket:
        bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bind_socket.bind(('0.0.0.0', 8443))
        bind_socket.listen(10)
        print("Servidor Hub ativo na porta 8443...") #todo meter porta dinamica

        while True:
            try:
                # ... dentro do while True no iniciar_servidor()
                raw_conn, addr = bind_socket.accept()
                ip_cliente = addr[0]

                # 1. VERIFICAR A LISTA NEGRA
                if ip_esta_banido(ip_cliente):
                    raw_conn.close()
                    continue

                # 2. VERIFICAR LIMITE DE CONEXÕES POR IP
                with lock_conexoes:
                    count = conexoes_por_ip.get(ip_cliente, 0)
                    if count >= MAX_CONEXOES_POR_IP:
                        registar_evento_rede("ALERTA_DOS", f"Bloqueio de excesso de conexões: {ip_cliente}")
                        raw_conn.close()
                        continue
                    conexoes_por_ip[ip_cliente] = count + 1

                # 3. SE PASSAR, PROSSEGUIR COM O mTLS
                try:
                    secure_conn = context.wrap_socket(raw_conn, server_side=True)
                    # Passamos o ip_cliente para podermos decrementar no finally da thread
                    threading.Thread(target=tratar_cliente, args=(secure_conn, addr), daemon=True).start()
                except Exception as e:
                    # Se falhar, decrementamos logo
                    with lock_conexoes:
                        conexoes_por_ip[ip_cliente] -= 1
                    registar_falha_ip(ip_cliente)
                    raw_conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    iniciar_servidor()