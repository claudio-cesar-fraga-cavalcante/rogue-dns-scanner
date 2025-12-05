# coding: utf-8
# Monitora Servidores DNS

from pathlib import Path
import dns.resolver
import dns.exception
import threading
import requests
import queue
import time
from datetime import date
from datetime import datetime
import glob
import argparse

# Variáveis Globais  - utilizadas para verificar o andamento do processo
# e abortar em caso de erro de conexão
registros_verificados = 0
andamento_verificacao = 0
total_ip_dns = 0
contador_status_conexao = 0

# Fila IP possui todos os ips de servidores DNS que serão consultados
# durante o processo de verificação
fila_ips_dns = queue.Queue()
lock = threading.Lock()

enviou_email = False

DIR_RESULTADOS = None
DIR_ENTRADA = None


def obter_dir_resultados():
    """
    Retorna o diretório de entrada onde estão a lista de ip relativa a servidores DNS.

    A função tenta identificar a raiz do projeto a partir da localização do
    arquivo atual (`__file__`). Caso o script esteja sendo executado de uma
    forma em que `__file__` não esteja disponível (por exemplo, ecd xecução direta
    em certos ambientes interativos), a raiz é inferida a partir do diretório
    de trabalho atual.

    Em seguida, cria (se ainda não existir) um diretório chamado
    ``input`` na raiz do projeto e retorna o caminho completo para ele.

    Returns:
        pathlib.Path: Caminho para o diretório ``input`` na raiz do projeto.
    """

    try:
        script_caminho = Path(__file__).resolve()
        raiz_projeto = script_caminho.parent.parent.parent
    except NameError:
        raiz_projeto = Path.cwd().parent.parent


    diretorio_entrada = raiz_projeto / "result_monitor" 
    diretorio_entrada.mkdir(exist_ok=True)

    diretorio_resultados_dia = diretorio_entrada / str(date.today()) 
    diretorio_resultados_dia.mkdir(exist_ok=True)

    return diretorio_resultados_dia


def obter_dir_entrada():
    """
    Retorna o diretório de entrada onde estão a lista de ip relativa a servidores DNS.

    A função tenta identificar a raiz do projeto a partir da localização do
    arquivo atual (`__file__`). Caso o script esteja sendo executado de uma
    forma em que `__file__` não esteja disponível (por exemplo, ecd xecução direta
    em certos ambientes interativos), a raiz é inferida a partir do diretório
    de trabalho atual.

    Em seguida, cria (se ainda não existir) um diretório chamado
    ``input`` na raiz do projeto e retorna o caminho completo para ele.

    Returns:
        pathlib.Path: Caminho para o diretório ``input`` na raiz do projeto.
    """

    try:
        script_caminho = Path(__file__).resolve()
        raiz_projeto = script_caminho.parent.parent.parent
    except NameError:
        raiz_projeto = Path.cwd().parent.parent


    diretorio_entrada = raiz_projeto / "input"
    diretorio_entrada.mkdir(exist_ok=True)

    return diretorio_entrada


def gerencia_verificacao(total_thread, dns_timeout, dns_lifetime):
    """
    Gerencia a criação e execução das threads responsáveis pelo processo de
    verificação DNS.

    Esta função inicializa o ambiente necessário para o scanner, determina o
    total de endereços que serão processados, inicia uma thread dedicada para
    verificação de acesso à internet e, em seguida, cria múltiplas threads para
    execução paralela das consultas DNS.

    Args:
        total_thread (int): Número de threads de trabalho que serão criadas para
            processar verificações DNS em paralelo.
        dns_timeout (int): Tempo máximo de espera (em segundos) para cada
            consulta DNS.
        dns_lifetime (int): Tempo total de vida permitido (em segundos) para
            uma consulta DNS antes de ser descartada.

    Globals:
        total_ip_dns (int): Variável global definida a partir do total de itens
            presentes na fila de endereços a serem verificados.

    Returns:
        int: Retorna sempre 0 ao final da inicialização das threads.
    """
    
    global total_ip_dns

    # Define o total de  threads de trabalho
    tamanho_fila = popula_fila()
    total_ip_dns = tamanho_fila
    contador_thread = 0

    t1 = threading.Thread(
        name='Thread_verifica_acesso', target=verifica_acesso_internet)
    t1.start()

    for i in range(total_thread):
        contador_thread += 1
        t2 = threading.Thread(name='Thread' + str(contador_thread),
                              target=verifica_servidores_dns, args=(dns_timeout, dns_lifetime))
        t2.start()

    return 0


def popula_fila():
    """
    Carrega uma lista de endereços IP de servidores DNS a partir de um arquivo
    e os insere em uma fila global utilizada por threads.

    A função:
        1. Inicializa a fila global ``fila_ips_dns``.
        2. Localiza o arquivo ``lista_ip_dns.txt`` no diretório de entrada
           (obtido via ``obter_dir_entrada()``).
        3. Lê cada linha do arquivo, removendo quebras de linha.
        4. Insere cada IP lido na fila.
        5. Retorna a quantidade total de IPs carregados.

    Returns:
        int: Quantidade de IPs inseridos na fila.
    """
    global fila_ips_dns
    fila_ips_dns = queue.Queue()
   
    nome_arquivo =  DIR_ENTRADA / "lista_ip_dns.txt"
    
    with open(nome_arquivo, 'r') as f:
        dns_ips = [ ip.rstrip('\n') for ip in f ]

    for ip in dns_ips:
        fila_ips_dns.put(ip)

    return fila_ips_dns.qsize()


def verifica_servidores_dns(dns_timeout, dns_lifetime):
    """
    Realiza consultas DNS em todos os servidores presentes na fila, verificando
    se algum deles retorna endereços IP divergentes dos IPs legítimos associados
    aos FQDNs monitorados.

    A função:
        - Carrega a relação de FQDNs e seus IPs legítimos a partir do arquivo
          ``listafqdn.txt``.
        - Configura um resolvedor DNS com os valores de timeout e lifetime
          informados.
        - Consome continuamente a fila de servidores DNS, processando cada IP por
          meio de threads.
        - Para cada servidor DNS, consulta todos os FQDNs definidos e compara
          os IPs retornados com os IPs legítimos.
        - Registra evidências e grava resultados caso sejam identificados IPs
          potencialmente forjados.
        - Trata erros comuns de resolução (NXDOMAIN, Timeout, NoNameservers,
          DNSException), registrando códigos específicos em arquivo.
        - Encerra quando a fila estiver vazia ou quando houver problemas
          persistentes de conectividade.

    Args:
        dns_timeout (int):
            Tempo máximo, em segundos, que cada consulta DNS pode aguardar antes
            de disparar timeout.
        dns_lifetime (int):
            Tempo máximo total permitido para a resolução DNS.

    Returns:
        int:
            - ``1`` quando todas as threads terminam e a fila de servidores DNS
              é esvaziada com sucesso.
            - ``-1`` quando o processo é interrompido devido a falhas recorrentes
              de conectividade com a Internet.

    Raises:
        None: todas as exceções relevantes são tratadas internamente.
    """
    # Esta função realiza o principal trabalho do script. Que consiste em realizar queries em todos os servidores
    # DNS. O objetivo é verificar se algum servidor DNS possui o endereço IP
    # forjado para um FQDN analisado

    global lock
    global registros_verificados
    global contador_status_conexao
    global enviou_email

    nome_arquivo =  DIR_ENTRADA / "listafqdn.txt"

    with open(nome_arquivo, 'r') as f:
        fqdn_ips = [ip.rstrip('\n') for ip in f]

    conf_dns = dns.resolver.Resolver()
    conf_dns.timeout = dns_timeout
    conf_dns.lifetime = dns_lifetime

    # Realiza a consulta DNS para cada servidor DNS informado (na fila) e guarda o resultado
    # Para posterior comparação com os ips legítimos dos FQDNs
    while True:
        try:
            # o parâmetro false é utilizado para a thread não bloquear
            ip_dns = (fila_ips_dns.get(False))
            fila_ips_dns.task_done()
        except queue.Empty:
            lock.acquire()
            print ("Aguarde 1 minuto para todas as threads serem encerradas adequadamente")
            # Envia e-mail informando o encerramento do processo de verificação
            if not enviou_email:
                envia_email()
                enviou_email = True
            lock.release()
            return 1

        # Utilizado para encerrar as threads caso a conexão com a Internet não
        # esteja satifastória
        if contador_status_conexao >= 5:
            return -1

        with lock:
            # Exibe o andamento do processo de validação
            registros_verificados += 1
            andamento_verificacao = int(
                registros_verificados / float(total_ip_dns) * 100)
            print ('Andamento: ' + str(registros_verificados) + ' de: ' + str(total_ip_dns)
                + '---' + str(andamento_verificacao) + '%')

        # Transforma ips dos FQDNs em um conjunto (set) que será utilizado para validar
        # se existem servidores DNS com ips forjados para os FQDNs consultados.
        # A variável fqdn_definido armazena o FQDN que será analisado e
        # a variável conjunto_ip_fqdn_definido armazena os ips verdadeiros
        # relacionados ao FQDN.
        for linha_fqdn in fqdn_ips:
            fqdn_definido = str(linha_fqdn).split(',')[0]
            conjunto_ip_fqdn_definido = set(str(linha_fqdn).split(',')[1:])

            try:
                conf_dns.nameservers = [ip_dns]
                resposta = conf_dns.resolve(fqdn_definido, 'A')
                # Transforma a resposta em uma lista e depois em um conjunto
                ips_resposta = ["".join(str(i).split(':')) for i in resposta]
                conjunto_ips_reposta = set(ips_resposta)
                # Verifica a diferença entre os conjuntos verdadeiro ips x os
                # ips retornados na consulta
                resultado_verificacao_consulta_dns = conjunto_ips_reposta.difference(
                    conjunto_ip_fqdn_definido)
                # Verifica se a reposta contém registros possivelmente maliciosos
                # Em caso positivo grava o resultado e obtém o artefato (site)
                if resultado_verificacao_consulta_dns:
                    baixa_evidencia_site(list(ips_resposta)[0], fqdn_definido)
                    grava_informacoes_dns(ip_dns, fqdn_definido, ips_resposta, lock)
            except dns.resolver.NXDOMAIN:
                grava_arquivo_resultado_consulta(ip_dns, '10', lock)
            except dns.resolver.Timeout:
                grava_arquivo_resultado_consulta(ip_dns, '20', lock)
                break
            except dns.resolver.NoNameservers:
                grava_arquivo_resultado_consulta(ip_dns, '30', lock)
            except dns.exception.DNSException:
                grava_arquivo_resultado_consulta(ip_dns, '40', lock)


def baixa_evidencia_site(ip, fqdn):
    """
    Realiza uma requisição HTTP ao endereço IP informado utilizando o FQDN como
    cabeçalho *Host*, com o objetivo de coletar uma evidência (conteúdo HTML)
    que possa indicar comportamento suspeito ou forjado em servidores DNS.

    A função:
        - Ignora o processamento caso o IP esteja em uma lista de exceções.
        - Envia uma requisição HTTP para o IP, simulando acesso ao FQDN.
        - Trata erros de conexão ou HTTP.
        - Caso a resposta seja bem-sucedida (status 200), salva o conteúdo HTML
          retornado no diretório de resultados.

    Args:
        ip (str):
            Endereço IP retornado pelo servidor DNS que será acessado via HTTP.
        fqdn (str):
            Nome de domínio totalmente qualificado (FQDN) utilizado como
            cabeçalho *Host* na requisição HTTP.

    Returns:
        None:
            A função não retorna valores. O conteúdo da página é salvo em arquivo
            somente quando a requisição obtém sucesso.

    Raises:
        None:
            Exceções comuns de conexão são tratadas internamente.
    """

    if verifica_excecao(str(ip)):
        return
    else:
        url = 'http://' + str(ip)
        headers = {'Host': str(fqdn)}

        try:
            resposta = requests.get(url, headers=headers)
        except requests.ConnectionError:
            return
        except requests.HTTPError:
            return

        if resposta.status_code == requests.codes.ok:            
            nome_arquivo =  DIR_RESULTADOS / f"{str(ip)} - {str(fqdn)}.html"
            with open(nome_arquivo, 'wb') as f:
                f.write(resposta.content)


def verifica_acesso_internet():
    """
    Monitora periodicamente a conectividade com a Internet durante a execução
    do processo, registrando falhas e controlando o estado geral de conexão.

    A função realiza:
        - Tentativas periódicas de acesso a uma URL de referência (Google).
        - Registro de falhas de conexão em arquivo.
        - Incremento/decremento de um contador global que indica estabilidade
          da conexão.
        - Encerramento automático quando a fila de servidores DNS for esvaziada.
        - Interrupção do processo caso sejam detectadas falhas consecutivas
          acima do limite permitido.

    Comportamento:
        - Se a fila de IPs a serem consultados estiver vazia, a thread encerra.
        - Cada falha de conexão incrementa o contador `contador_status_conexao`.
        - Cada conexão bem-sucedida decrementa o contador, até o mínimo de zero.
        - Se o contador atingir 5 falhas consecutivas, retorna `-1` indicando
          condição crítica de acesso à Internet.

    Args:
        None

    Returns:
        int:
            1  — quando a fila de servidores DNS esvaziou e a thread deve encerrar.
            -1 — quando o número de falhas consecutivas na conexão atingir o limite.

    Raises:
        None:
            Todas as exceções de rede são tratadas internamente.
    """

    global contador_status_conexao
    global fila_ips_dns
    url = 'http://www.google.com.br'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
    mensagem_erro = "erro na comunicação com a Internet"

    while True:
        if fila_ips_dns.empty():
            print (u"Fechando thread de verificação de acesso a Internet")
            return 1

        try:
            resposta = requests.get(url, headers=headers)
            time.sleep(60)

            if contador_status_conexao > 0:
                contador_status_conexao -= 1

        except requests.ConnectionError:
            grava_arquivo_status_internet(mensagem_erro)
            contador_status_conexao += 1
            time.sleep(60)
        except requests.HTTPError:
            grava_arquivo_status_internet(mensagem_erro)
            contador_status_conexao += 1
            time.sleep(60)

        if contador_status_conexao >= 5:
            return -1


def grava_arquivo_resultado_consulta(ip, texto, lock):

    data_hora = str(datetime.now())
    nome_arquivo =  DIR_RESULTADOS / f"{date.today()} - resultado_consulta_dns.txt"
    
    with lock:
        with open(nome_arquivo, 'a') as f:
            f.write(f"{data_hora},{ip},{texto}\n")    

# Utilizado para fazer log de erros de conexão
def grava_arquivo_status_internet(texto):
    data_hora = str(datetime.now())

    nome_arquivo =  DIR_RESULTADOS / f"{date.today()} - status_conexao.txt"

    with open(nome_arquivo, 'a') as f:
        f.write(f"{data_hora} - {texto}\n")

# Gera um arquivo para cada fqdn pesquisado, caso encontre DNS forjado
def grava_informacoes_dns(ip_definido, fqdn, resposta, lock):

    if verifica_excecao(str(resposta[0])):
        return
    else:
        with lock:
            nome_arquivo =  DIR_RESULTADOS / f"{date.today()} - {str(fqdn)}  - resultado_validacao_dns.txt"
            
            linha = f"{ip_definido},{fqdn},{','.join(resposta)}\n"
            with open(nome_arquivo, 'a') as f:
                f.write(linha)

def prepara_mensagem_email():
    mensagem = 'DNS_IP - FQDN_QUERY - RESPOSTA - OBS \n'

    # Prepara o conteúdo da mensagem a ser enviada
    lista_arquivos = glob.glob(DIR_RESULTADOS /  "'*resultado_validacao_dns.txt")
    
    for arquivo in lista_arquivos:
        with open(arquivo, "r") as f:
            linhas = f.readlines()
            for linha in linhas:
                #Passa ip retornado pela consulta para verificar se está em uma lista de exceção
                #e dessa forma não enviar este registro por e-mail
                if verifica_excecao(linha.rstrip('\n').split(',')[2]):
                    continue
                else:
                    mensagem = mensagem + linha
    return mensagem


def envia_email():
    import smtplib

    gmail_user = "alteraaqui@gmail.com"
    gmail_pwd = "alteraaqui@123" # Não comitar a senha em nenhum repositório
    FROM = 'alteraraqui@gmail.com'
    TO = ['alteraraqui@gmail.com']  # must be a list
    SUBJECT = "Resultado do processo de verificação DNS"
    TEXT = prepara_mensagem_email()

    # Prepare actual message
    message = """From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (FROM, ", ".join(TO), SUBJECT, TEXT)

    try:
        # server = smtplib.SMTP(SERVER)
        # or port 465 doesn't seem to work!
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.ehlo()
        server.starttls()
        server.login(gmail_user, gmail_pwd)
        server.sendmail(FROM, TO, message)
        # server.quit()
        server.close()
        print ('Mensagem enviada com sucesso')
    except:
        print ("Falha no envio do e-mail")


def verifica_excecao(ip_resposta_query):

    nome_arquivo =  DIR_ENTRADA / "ips_excepcionalizar.txt"

    with open(nome_arquivo, 'r') as f:
        ips_excepcionalizar = [ ip.rstrip('\n') for ip in f ]

    if ip_resposta_query in ips_excepcionalizar:
        return True
    else:
        return False

def inicializar_dirs():
    global DIR_RESULTADOS, DIR_ENTRADA
    if DIR_RESULTADOS is None:
        DIR_RESULTADOS = obter_dir_resultados()
    if DIR_ENTRADA is None:
        DIR_ENTRADA = obter_dir_entrada()


def main_monitor(qtd_threads: int, timeout: float, lifetime: float):
    inicializar_dirs()
    gerencia_verificacao(qtd_threads, timeout, lifetime)
