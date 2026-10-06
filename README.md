# Qproxy

Qproxy é um proxy local HTTP/HTTPS em Python para bloquear anúncios e rastreadores por domínio, sem descriptografar o tráfego HTTPS.

## O que ele faz

- aceita conexões de proxy HTTP em `127.0.0.1:8899`;
- intercepta `CONNECT` de HTTPS e bloqueia hosts conhecidos antes de criar o túnel;
- bloqueia domínios e subdomínios por lista local;
- suporta whitelist;
- entende listas em formato simples, `hosts` e regras básicas `||dominio^`;
- registra bloqueios no console;
- inclui scripts PowerShell para ativar/desativar o proxy do Windows.

> Limitação importante: como não há MITM, Qproxy não enxerga o caminho interno de uma URL HTTPS. Portanto ele bloqueia por domínio. Anúncios servidos pelo mesmo domínio do conteúdo (ex.: alguns anúncios embutidos em feeds/vídeos) exigem extensão de navegador ou filtragem adicional.

## Instalação

Requer Python 3.10+.

```powershell
git clone https://github.com/lols8000/Qproxy.git
cd Qproxy
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

## Executar

```powershell
qproxy --config config.example.json
```

Ou sem instalar o comando:

```powershell
python -m qproxy --config config.example.json
```

Depois configure o navegador/sistema para usar:

```text
HTTP proxy: 127.0.0.1
Porta:      8899
HTTPS:      usar o mesmo proxy
```

No Windows você pode usar:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\enable_windows_proxy.ps1
```

Para desfazer:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\disable_windows_proxy.ps1
```

## Configuração

Copie `config.example.json` se quiser alterar porta/listas:

```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 8899,
  "blocklists": ["data/blocklist.txt"],
  "whitelists": ["data/whitelist.txt"],
  "connect_timeout_seconds": 10,
  "log_allowed": false
}
```

## Formatos de lista aceitos

```text
doubleclick.net
0.0.0.0 googlesyndication.com
127.0.0.1 ads.example.com
||tracker.example.org^
```

Whitelist:

```text
example.com
@@||allowed.example.org^
```

## Testes

```powershell
python -m unittest discover -s tests -v
```

## Próximos passos

A evolução natural é adicionar atualizador de blocklists, painel local, estatísticas persistidas e uma extensão de navegador para filtragem cosmética.
