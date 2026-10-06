# Qproxy V2

Proxy local HTTP/HTTPS em Python para bloquear anúncios e rastreadores por **domínio**, com painel local, estatísticas, whitelist e atualização automática de listas.

## O que mudou na V2

- bloqueio HTTP e HTTPS por host sem descriptografar TLS;
- EasyList e EasyPrivacy baixadas e armazenadas em cache local;
- atualização automática (24 h por padrão) e atualização manual pelo painel;
- recarga atômica das regras sem reiniciar o proxy;
- classificação de bloqueios em `ad` e `tracker`;
- painel local em `http://127.0.0.1:8900`;
- métricas, top domínios bloqueados e atividade recente;
- whitelist editável no painel;
- estatísticas persistidas em `data/stats.json`;
- endpoint administrativo protegido por token efêmero e dashboard restrito a localhost por padrão;
- sem dependências externas de runtime.

## Limite técnico importante

Qproxy **não faz MITM** e não instala certificado raiz. Em HTTPS ele enxerga o host do túnel `CONNECT`, mas não o caminho interno da URL. Portanto, ele bloqueia muito bem publicidade e tracking servidos por domínios separados, mas não remove de forma confiável anúncios first-party embutidos no mesmo domínio do conteúdo (por exemplo, certos anúncios dentro de serviços de vídeo).

Uma futura V3 pode adicionar uma extensão de navegador para filtragem cosmética e regras por URL/DOM, mantendo o proxy sem interceptação TLS.

## Instalação

Requer Python 3.10+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

## Rodar

```powershell
qproxy --config config.example.json
```

Proxy:

```text
127.0.0.1:8899
```

Painel:

```text
http://127.0.0.1:8900
```

## Atualizar listas sem iniciar o proxy

```powershell
qproxy --config config.example.json --update-lists
```

As listas remotas padrão são EasyList e EasyPrivacy. O Qproxy extrai apenas regras que podem ser convertidas com segurança em domínio/host. Regras cosméticas e regras que dependem do conteúdo HTTPS são ignoradas.

## Configuração do Windows

Use os scripts em `scripts/` para ativar/desativar o proxy do Windows ou configure manualmente o endereço `127.0.0.1` porta `8899`.

## Testes

```powershell
python -m unittest discover -s tests -v
```

## Segurança

- O proxy e o dashboard escutam apenas em `127.0.0.1` por padrão.
- Não exponha o proxy em `0.0.0.0` sem entender que isso pode permitir uso por outras máquinas da rede.
- O dashboard não descriptografa nem armazena conteúdo HTTPS.
- A atividade recente registra hostname, ação e protocolo, não o conteúdo das páginas HTTPS.
- Operações de alteração no painel exigem um token administrativo efêmero inserido apenas na página local.

## Licença

Código do Qproxy: MIT. Listas de terceiros possuem suas próprias licenças e são baixadas diretamente de seus mantenedores; não são incorporadas ao repositório.
