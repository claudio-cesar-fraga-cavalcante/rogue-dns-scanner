# cli.py
import argparse
from rogue_dns_scanner.dns_discovery import main_discovery
from rogue_dns_scanner.dns_monitor import main_monitor


def main():
    parser = argparse.ArgumentParser(
        description="CLI unificada do Rogue DNS Scanner"
    )

    subparsers = parser.add_subparsers(dest="comando", required=True)

    parser_discovery = subparsers.add_parser(
        "discovery",
        help="Localiza servidores DNS"
    )
    parser_discovery.add_argument(
        "-r", "--rede",
        type=int, required=True,
        help="Rede a ser pesquisada"
    )

    parser_monitor = subparsers.add_parser(
        "monitor",
        help="Verifica DNS forjados"
    )
    parser_monitor.add_argument(
        "-p", "--thread",
        type=int, default=100,
        help="Quantidade de threads"
    )
    parser_monitor.add_argument(
        "-t", "--timeout",
        type=float, default=2,
        help="Timeout das consultas"
    )
    parser_monitor.add_argument(
        "-l", "--lifetime",
        type=float, default=2,
        help="Tempo de vida da transferência"
    )

    args = parser.parse_args()

    if args.comando == "discovery":
        main_discovery(args.rede)

    elif args.comando == "monitor":
        main_monitor(args.thread, args.timeout, args.lifetime)


if __name__ == "__main__":
    main()
