# Qproxy V2.1

Proxy local HTTP/HTTPS em Python para bloquear anúncios e rastreadores por **domínio**, com painel local, estatísticas, whitelist e atualização automática de listas.

## Uso simples no Windows

A forma recomendada agora é apenas:

```powershell
python main.py
```

O `main.py` faz sozinho:

1. recupera um proxy antigo do Qproxy que tenha ficado preso;
2. inicia o servidor local;
3. espera a porta `127.0.0.1:8899` realmente responder;
4. só então ativa o proxy do Windows;
5. abre o painel local;
6. ao fechar ou pressionar `Ctrl+C`, restaura a configuração de proxy anterior;
7. mantém um watchdog separado para tentar restaurar o proxy mesmo se o processo principal morrer abruptamente.

Não é necessário executar os arquivos `.ps1` para o uso normal.

Painel:

```text
http://127.0.0.1:8900
```

Proxy:

```text
127.0.0.1:8899
```

### Se a internet tiver ficado sem acesso por uma execução antiga

Com a versão nova:

```powershell
python main.py --restore-proxy
```

Ou desative manualmente em:

**Configurações → Rede e Internet → Proxy → Usar um servidor proxy → Desativado**

## Instalação

Requer Python 3.10+.

A execução direta não exige instalar o pacote:

```powershell
python main.py
```

Opcionalmente, para instalar o comando `qproxy`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

## Execução avançada

Sem alterar automaticamente o proxy do Windows:

```powershell
python -m qproxy --config config.example.json
```

Ou, se o pacote foi instalado:

```powershell
qproxy --config config.example.json
```

## Recursos

- bloqueio HTTP e HTTPS por host sem descriptografar TLS;
- EasyList e EasyPrivacy baixadas e armazenadas em cache local;
- atualização automática e manual das listas;
- recarga das regras sem reiniciar;
- classificação de bloqueios em `ad` e `tracker`;
- painel local;
- métricas, top domínios bloqueados e atividade recente;
- whitelist editável;
- estatísticas persistentes;
- sem dependências externas de runtime.

## Limite técnico

Qproxy **não faz MITM** e não instala certificado raiz. Em HTTPS ele enxerga o host do túnel `CONNECT`, mas não o caminho interno da URL. Por isso bloqueia bem publicidade e tracking servidos por domínios separados, mas não remove de forma confiável anúncios first-party no mesmo domínio do conteúdo.

## Atualizar listas

```powershell
python -m qproxy --config config.example.json --update-lists
```

## Testes

```powershell
python -m unittest discover -s tests -v
```

## Segurança

- proxy e dashboard usam `127.0.0.1` por padrão;
- o Qproxy não descriptografa conteúdo HTTPS;
- o `main.py` salva temporariamente as configurações anteriores de proxy para restaurá-las na saída;
- não exponha o proxy em `0.0.0.0` sem entender as implicações.

## Licença

Código do Qproxy: MIT. Listas de terceiros possuem suas próprias licenças e são baixadas diretamente dos mantenedores.
