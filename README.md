## O Rogue DNS Scanner é uma ferramenta composta por dois módulos principais:

- Discovery – Varredura de redes IPv4 para identificar servidores DNS.

- Monitor – Validação e detecção de respostas DNS forjadas.

- Ambos são acessados por uma CLI unificada (cli.py)

### Clonando o projeto
$ git clone https://github.com/claudio-cesar-fraga-cavalcante/rogue-dns-scanner.git

$ cd rogue_dns_scanner

### Pré-requisitos

Este projeto utiliza o uv, um gerenciador de ambientes Python rápido e moderno.

**Linux / MACOS:**  

$ curl -LsSf https://astral.sh/uv/install.sh | sh

**Windows (Power Shell)**  

$ iwr https://astral.sh/uv/install.ps1 -useb | iex

### Executar o Discovery

$ uv run python cli.py discovery -r 200

### Executar o Monitor

$ uv run python cli.py monitor -p 200 -t 1.5 -l 1.5

### Se desejar também pode instalar o aplicativo seguindos os passos abaixo

$ uv tool install .  

**E utilizá-lo da seguinte maneira:**

$ rogue-dns discovery -r 200  
$ rogue-dns monitor -p 200 -t 1.5 -l 1.5  


*Para mais detalhes verifique a documentação completa na Wiki*:  
https://github.com/claudio-cesar-fraga-cavalcante/rogue-dns-scanner/wiki/Rogue-DNS-Scanner  

