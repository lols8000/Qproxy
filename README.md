# Qproxy V2.2

Proxy local HTTP/HTTPS em Python para bloquear anúncios e rastreadores por **domínio**, com painel local, estatísticas, whitelist e atualização automática de listas.

## Uso simples no Windows

A forma recomendada é:

```powershell
python main.py
```

O `main.py` recupera proxy travado, inicia o servidor, espera a porta `127.0.0.1:8899` responder, ativa o proxy do Windows e restaura a configuração anterior ao encerrar.

Painel:

```text
http://127.0.0.1:8900
```

## Compatibilidade com YouTube

A V2.2 adiciona uma allowlist de compatibilidade para infraestrutura essencial do YouTube. Ela tem prioridade sobre EasyList/EasyPrivacy e evita que regras remotas impeçam a reprodução dos vídeos.

Domínios protegidos por padrão:

- `youtube.com`
- `youtu.be`
- `ytimg.com`
- `googlevideo.com`
- `youtubei.googleapis.com`
- `youtube.googleapis.com`
- `youtube-nocookie.com`

Essa lista pode ser alterada em `compatibility_allowlist` no JSON de configuração.

Como o Qproxy não faz MITM, ele não consegue distinguir com segurança um vídeo normal de um anúncio quando ambos usam a mesma infraestrutura do YouTube. A prioridade nessa lista é preservar a reprodução.

## Se a internet ficar presa

```powershell
python main.py --restore-proxy
```

## Instalação

Requer Python 3.10+. Para uso direto:

```powershell
python main.py
```

Instalação opcional:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

## Execução avançada

```powershell
python -m qproxy --config config.example.json
```

## Recursos

- bloqueio HTTP e HTTPS por host sem descriptografar TLS;
- EasyList e EasyPrivacy;
- atualização automática/manual;
- allowlist de compatibilidade;
- whitelist editável;
- dashboard local;
- métricas e histórico;
- sem dependências externas de runtime.

## Limite técnico

Qproxy **não faz MITM**. Em HTTPS ele decide pelo host do túnel `CONNECT`, não pelo caminho interno da URL. Por isso o bloqueio por domínio não consegue separar todo anúncio first-party do conteúdo principal.

## Atualizar listas

```powershell
python -m qproxy --config config.example.json --update-lists
```

## Testes

```powershell
python -m unittest discover -s tests -v
```

## Licença

Código do Qproxy: MIT. Listas de terceiros possuem suas próprias licenças.
