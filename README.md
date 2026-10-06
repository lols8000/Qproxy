# Qproxy V3

Qproxy combina duas camadas de bloqueio:

1. **proxy local Python** para anúncios e trackers servidos por domínios separados;
2. **Qproxy YouTube Companion** para anúncios e elementos patrocinados que aparecem dentro da própria página do YouTube.

## Uso do proxy no Windows

```powershell
python main.py
```

O `main.py` recupera proxy travado, inicia o servidor, espera `127.0.0.1:8899` responder, ativa o proxy do Windows e restaura a configuração anterior ao encerrar.

Painel:

```text
http://127.0.0.1:8900
```

## YouTube: instalar o complemento

O proxy sozinho não consegue separar com segurança vídeo e publicidade quando os dois usam a mesma infraestrutura do YouTube. Por isso a V3 inclui a pasta:

```text
browser_extension
```

### Firefox

1. Abra `about:debugging#/runtime/this-firefox`.
2. Clique em **Carregar extensão temporária...**.
3. Selecione `browser_extension/manifest.json`.
4. Recarregue o YouTube.

### Chrome / Edge

1. Abra `chrome://extensions` ou `edge://extensions`.
2. Ative o **Modo do desenvolvedor**.
3. Clique em **Carregar sem compactação / Load unpacked**.
4. Selecione a pasta `browser_extension`.

## O que o complemento do YouTube faz

- observa o estado real de anúncio do player;
- tenta clicar em diferentes variantes do botão **Pular anúncio**;
- fecha overlays publicitários;
- em anúncio ativo sem botão de pular, muta/acelera e tenta avançar o anúncio;
- restaura mute, volume e velocidade do vídeo normal;
- esconde cards, slots e elementos patrocinados identificáveis na interface.

A detecção de anúncio não depende apenas da existência de contêineres genéricos no DOM, para não acelerar vídeos normais.

## Compatibilidade de reprodução

A allowlist interna continua protegendo:

- `youtube.com`
- `youtu.be`
- `ytimg.com`
- `googlevideo.com`
- `youtubei.googleapis.com`
- `youtube.googleapis.com`
- `youtube-nocookie.com`

Ela tem prioridade sobre EasyList/EasyPrivacy para impedir que regras remotas quebrem a reprodução.

## Limite técnico

Nenhum bloqueador baseado apenas em domínio consegue eliminar todos os anúncios first-party do YouTube sem risco de bloquear o vídeo principal. A extensão reduz essa lacuna atuando no DOM/player, mas o YouTube pode alterar seletores e fluxo de anúncios ao longo do tempo.

## Se a internet ficar presa

```powershell
python main.py --restore-proxy
```

## Instalação opcional do pacote Python

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

## Execução avançada

```powershell
python -m qproxy --config config.example.json
```

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
