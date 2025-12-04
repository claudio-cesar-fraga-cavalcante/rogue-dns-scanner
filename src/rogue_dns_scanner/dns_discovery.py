#coding: utf-8
#Coleta de Servidores DNS
from pathlib import Path
import dns.resolver
import dns.exception
import threading
import argparse

QTD_BITS_IPV4 = 32

def obter_dir_saida():
    """
    Retorna o diretório de saída destinado aos arquivos de descoberta DNS.

    A função tenta identificar a raiz do projeto a partir da localização do
    arquivo atual (`__file__`). Caso o script esteja sendo executado de uma
    forma em que `__file__` não esteja disponível (por exemplo, execução direta
    em certos ambientes interativos), a raiz é inferida a partir do diretório
    de trabalho atual.

    Em seguida, cria (se ainda não existir) um diretório chamado
    ``discovery_dns`` na raiz do projeto e retorna o caminho completo para ele.

    Returns:
        pathlib.Path: Caminho para o diretório ``discovery_dns`` na raiz do projeto.
    """

    try:
        script_caminho = Path(__file__).resolve()
        raiz_projeto = script_caminho.parent.parent.parent
    except NameError:
        raiz_projeto = Path.cwd().parent.parent


    diretorio_saida = raiz_projeto / "discovery_dns"
    diretorio_saida.mkdir(exist_ok=True)

    return diretorio_saida


def coleta_servidores_dns(rede):
    """
    Gera threads para escanear sub-redes e identificar possíveis servidores DNS.

    Esta função recebe o primeiro octeto de uma rede (ex: 10, 172, 192),
    constrói ranges de IPs /16 no formato <rede>.<i>.0.0 para i de 0 a 255,
    e cria uma thread para processar cada uma dessas sub-redes usando a
    função `consulta_dns`.

    Args:
        rede (int): O primeiro octeto da rede que será analisada.
                        Exemplo: 10 → varrerá 10.0.0.0/16 até 10.255.0.0/16.

    Returns:
        None
    """   

    lock = threading.Lock()

    range_ip = list()

    for i in range(0, 256):
        ip = str(rede) + '.' + str(i) + '.' + '0' + '.' + '0'
        item_buscar = (str(rede), str(ip), 16,'www.google.com.br', 'A', lock)
        range_ip.append(item_buscar)

    # Cria uma thread para cada sub-rede listada em 'range_ip', iniciando a execução da função
    # de consulta DNS em paralelo para acelerar o processo de varredura.
    contador_thread = 0    
    for consulta in range_ip:
        contador_thread += 1
        t = threading.Thread(name='Thread' + str(contador_thread), target=consulta_dns, args = consulta)
        t.start()


       
def consulta_dns(rede, ip, mascara, fqdn, tipo_busca, lock):
    """
    Realiza uma varredura DNS em todos os IPs pertencentes à sub-rede fornecida.

    Cada thread executa esta função, que:
    - Divide o endereço de rede em octetos
    - Calcula todos os endereços possíveis usando o número de bits do host
    - Para cada IP gerado, tenta consultá-lo como se fosse um servidor DNS
    - Registra o resultado em arquivo usando `grava_informacoes_dns`

    Args:
        rede (str): O primeiro octeto da rede principal (ex: "10").
        ip (str): Endereço base da sub-rede (ex: "10.0.0.0").
        mascara (int): Máscara da sub-rede em bits (ex: 16).
        fqdn (str): Nome de domínio usado na consulta DNS.
        tipo_busca (str): Tipo de registro DNS (ex: "A").
        lock (threading.Lock): Lock usado para acesso concorrente seguro ao arquivo.

    Returns:
        None
    """

    # Divisão do endereços IP em octetos e definição de bits de rede e host
    bits_parte_rede = mascara
    bits_parte_host = QTD_BITS_IPV4 - bits_parte_rede

    octeto1, octeto2, octeto3, octeto4 = ip.split(".")
    
    # Remove o prefixo "0b" do binário e preenche com zeros à esquerda para garantir 8 bits por octeto.
    octeto1 = bin(int(octeto1))[2:].rjust(8,'0')
    octeto2 = bin(int(octeto2))[2:].rjust(8,'0')
    octeto3 = bin(int(octeto3))[2:].rjust(8,'0')
    octeto4 = bin(int(octeto4))[2:].rjust(8,'0')

    # Define a quantidade de endereços IP a serem varridos, calculada com base no número de bits destinados à parte de host.

    quantidade_ips = 2 ** bits_parte_host

    conf_dns = dns.resolver.Resolver()
    conf_dns.timeout = 1
    conf_dns.lifetime = 1

    # Realiza a consulta DNS para cada endereço IP calculado.
    # Cada rede IP é processada em uma thread separada.
    # Os endereços são gerados a partir do IP base recebido, incrementando seus octetos conforme necessário.

    for i in range(quantidade_ips):
        endereco_ip_bits = bin(i)[2:].rjust(32,'0') 
        octeto1t = int(octeto1, 2) + int(endereco_ip_bits[0:8], 2) 
        octeto2t = int(octeto2, 2) + int(endereco_ip_bits[8:16], 2)
        octeto3t = int(octeto3, 2) + int(endereco_ip_bits[16:24], 2)
        octeto4t = int(octeto4, 2) + int(endereco_ip_bits[24:32], 2)
        ip_definido = str(octeto1t) + '.' + str(octeto2t) + '.' + str(octeto3t) + '.' + str(octeto4t)
        
        with lock:
            print (f"{str(threading.currentThread())} - {ip_definido}")
        
        try:            
            conf_dns.nameservers=[ ip_definido ] 
            resposta = conf_dns.resolve(fqdn, tipo_busca) 
            grava_informacoes_dns(rede, ip_definido, "OK", lock) 
        except dns.resolver.NXDOMAIN:
            # Erro NXDOMAIN: o servidor DNS consultado não reconhece o domínio.           
            grava_informacoes_dns(rede, ip_definido, "NXDOMAIN", lock)            
        except dns.resolver.Timeout:
            # Timeout: o servidor não respondeu dentro do tempo limite.
            # Não vamos registrar servidores que não respondem
            continue
            #continue
        except dns.resolver.NoNameservers:          
            # Erro: não há servidores DNS válidos ou todos falharam ao responder.
            grava_informacoes_dns(rede, ip_definido, "NO_NAMESERVERS", lock)           
        except dns.exception.DNSException as erro:
            grava_informacoes_dns(rede, ip_definido, "GENERIC_ERROR", lock)
  

def grava_informacoes_dns(rede, ip_definido, resposta, lock):
    """
    Grava no arquivo o resultado da consulta DNS para um IP específico.

    Args:
        rede (int | str): Identificador da rede analisada, usado para compor o nome do arquivo.
        ip_definido (str): Endereço IP consultado.
        resposta (str): Código ou status da resposta da consulta DNS.
        lock (threading.Lock): Objeto de bloqueio utilizado para garantir exclusividade
            no acesso ao arquivo quando múltiplas threads estão em execução.

    Returns:
        None: A função apenas grava informações no arquivo e não retorna valor.
    """
    diretorio_saida = obter_dir_saida()
    nome_arquivo =  diretorio_saida / f"dns_discovery_network_{rede}.csv"

    with lock:
        print(f"{threading.currentThread()} - {ip_definido} - Gravando arquivo")
        
        with open(nome_arquivo, "a", encoding="utf-8") as f:
            f.write(f"{ip_definido},{resposta}\n")

def main():
    """
    Ponto de entrada do programa.

    Faz o parse dos argumentos de linha de comando, obtém o valor da rede
    informada pelo usuário e inicia o processo de varredura para identificação
    de servidores DNS.

    Args:
        None: Os parâmetros são recebidos diretamente da linha de comando.

    Returns:
        None: Executa o fluxo principal do programa sem retornar valores.
    """

    parser = argparse.ArgumentParser(description='Programa para identificar servidores DNS na Internet')
    parser.add_argument('-r', '--rede', type = int, action = 'store', dest = 'rede', default = 1,
                        required = True, help = 'Rede a ser pesquisada')

    arguments = parser.parse_args()
    coleta_servidores_dns(arguments.rede)

if __name__ == "__main__":
    main()
    