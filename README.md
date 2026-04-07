# Network / Service Enumerator (CTF Tool)

Ferramenta simples em Python para enumeração de conexões de rede e serviços locais em ambientes Linux que não tenham netstat ou não seja possivel instalar.

## Descrição

Este script analisa conexões ativas do sistema usando:

- `/proc/net/tcp`
- `/proc/net/udp`
- Mapeamento de processos via `/proc/[pid]/fd`
- Banner grabbing básico em portas abertas

Caso `netstat` esteja disponível, ele será usado automaticamente. Caso contrário, a ferramenta faz parsing manual do `/proc`.

## Funcionalidades

- Listagem de conexões TCP e UDP
- Mapeamento de PID e processo (quando permitido)
- Identificação de serviços comuns (SSH, HTTP, MySQL, MongoDB, etc.)
- Banner grabbing em portas abertas (LISTEN)
- Detecção simples de serviço baseado em porta + banner
- Multi-threading para acelerar scans
- Fallback automático para `/proc` quando `netstat` não existe

## Serviços detectados

- SSH (22)
- HTTP (80, 8080, 8000)
- HTTPS (443)
- FTP (21)
- SMTP (25)
- MySQL (3306)
- MongoDB (27017)

## Requisitos

- Python 3.x
- Linux (requer acesso ao `/proc`)
- Permissões adequadas para leitura de processos (algumas infos podem aparecer como `-` sem root)

## Uso

```bash
chmod +x  static.py
python3 static.py
