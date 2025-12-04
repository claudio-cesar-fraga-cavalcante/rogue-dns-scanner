# DNS Discovery

Este projeto realiza a descoberta de servidores DNS em sub-redes específicas, realizando consultas para verificar a disponibilidade e a resposta de cada IP como servidor DNS.

O script `dns_discovery.py` utiliza **threads** para acelerar a varredura e grava os resultados em arquivos CSV separados por rede.

---

## Pré-requisitos

- Python 3.8 ou superior
- Pacotes Python:
  - `dnspython`

Você pode instalar o pacote necessário com:

```bash
pip install dnspython
```

---

## Instalação

1. Clone ou baixe este repositório.
2. Navegue até a pasta do projeto:

```bash
cd caminho/do/projeto
```

3. Certifique-se de ter o Python e `pip` instalados.

---

## Execução

O script é executado a partir do terminal utilizando **argumentos de linha de comando**.

```bash
python dns_discovery.py --rede <primeiro_octeto>
```

### Argumentos

- `-r`, `--rede`  
  Primeiro octeto da rede que será escaneada.  
  Exemplo: `10` → varrerá de `10.0.0.0/16` até `10.255.0.0/16`.

### Exemplo de execução:

```bash
python dns_discovery.py --rede 10
```

Isso iniciará a varredura da rede 10.x.x.x, criando um arquivo CSV em:

```
<raiz_do_projeto>/discovery_dns/dns_discovery_network_10.csv
```

O CSV conterá os IPs varridos e o status da consulta DNS (`OK`, `NXDOMAIN`, `NO_NAMESERVERS`, `GENERIC_ERROR`).

---

## Estrutura de saída

- `discovery_dns/` → diretório criado automaticamente na raiz do projeto para armazenar os arquivos CSV.
- `dns_discovery_network_<rede>.csv` → arquivo com resultados da rede específica.

---

## Observações

- A varredura é feita utilizando threads para cada sub-rede /16.
- O script respeita timeouts de 1 segundo para consultas DNS.
- Servidores que não respondem não são registrados.

---

## Contato

Para dúvidas ou sugestões, abra uma issue no repositório ou entre em contato com o responsável pelo projeto.
