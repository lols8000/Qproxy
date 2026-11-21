# Qproxy V4.0 — Bloqueio de Anúncios nos Pacotes do Windows

O **Qproxy V4.0** foi redesenhado para filtrar propagandas, rastreadores e telemetria **diretamente na pilha de pacotes do Windows (kernel WFP via WinDivert)** antes de chegarem aos aplicativos, sem arrastar seu tráfego de navegação/vídeo por um proxy lento.

## O que mudou na V4.0 (bloqueio efetivo + internet mais rápida)

1. **Bloqueio direto nos pacotes do Windows (`WinDivert / WFP`) — sem proxy lento no caminho:**
   - **Filtro seletivo no kernel:** apenas pacotes de controle mínimos entram no motor do Qproxy (DNS, `TLS ClientHello`, `QUIC Initial` e cabeçalhos `HTTP`). Todo o restante do tráfego permitido (vídeos 4K, downloads, jogos, chamadas) trafega **100% no kernel do Windows em velocidade nativa**, eliminando o gargalo do proxy HTTP/HTTPS tradicional.
   - **DNS em pacotes (UDP 53 IPv4/IPv6) + Cache DNS em RAM (<1 ms):** domínios de anúncios são bloqueados antes mesmo de sair da placa de rede (resposta instantânea `0.0.0.0` / `::` / `NODATA` para registros `HTTPS`, sem travamentos), enquanto domínios permitidos repetidos são respondidos da memória em menos de 1 ms em vez de esperar 20–100 ms pelo DNS da operadora.
   - **Proteção contra CNAME Cloaking:** analisa respostas DNS de entrada e bloqueia rastreadores disfarçados em subdomínios *first-party* (ex.: `metrics.site.com -> CNAME tracker.criteo.com`) antes de chegarem ao Windows.
   - **TLS SNI (TCP 443/8443):** bloqueia conexões HTTPS publicitárias mesmo quando o navegador usa DoH ou quando o app ignora o proxy do Windows (Spotify, apps Electron, jogos, UWP, telemetria), injetando `TCP RST+ACK` instantâneo (<1 ms) e suportando pacotes ClientHello pós-quânticos truncados.
   - **QUIC / HTTP/3 Initial SNI (UDP 443 — RFC 9000 v1 e RFC 9369 v2):** descriptografa o pacote Initial para extrair o SNI e descartar conexões QUIC de servidores de anúncios sem desabilitar o HTTP/3 em sites legítimos como o YouTube.
   - **HTTP Host + Caminho (TCP 80/8080):** bloqueia hosts e caminhos publicitários (`/pagead/`, `/gampad/`, `/ads/ads.js`, etc.) devolvendo `HTTP 204 No Content` imediato.
   - **Canário DoH (`use-application-dns.net`):** sinaliza gentilmente ao Firefox para usar o DNS local filtrado/cacheado.
2. **Listas muito mais eficazes (e atualização paralela com `gzip` + `ETag`):**
   - Além da lista base offline ampliada (~180 redes globais, brasileiras, popunders, apps e telemetria Windows), a V4.0 traz por padrão: **HaGeZi Multi PRO**, **AdGuard DNS Filter** (inclui filtro Português/BR), **OISD Big**, **HaGeZi Windows/Office Telemetry**, **StevenBlack hosts**, **EasyList** e **EasyPrivacy**.
   - Motor de regras com cache O(1), suporte a wildcards (`*.dominio`), `$important`/`$all` e invalidação instantânea ao editar bloqueios/whitelist.
3. **Fallback automático inteligente (`auto`):**
   - **Modo Pacotes (`packet`)**: Windows + Administrador + WinDivert (máximo bloqueio em todos os apps + velocidade nativa).
   - **Modo DNS Local (`dns`)**: Administrador sem WinDivert — sobe servidor DNS local assíncrono (`127.0.0.1:53` e `::1:53`) com corrida paralela entre `1.1.1.1`, `8.8.8.8` e `9.9.9.9`, cache LRU e bloqueio de CNAME cloaking, com backup/restauração automática via watchdog.
   - **Modo Proxy Otimizado (`proxy`)**: sem Administrador ou fora do Windows — proxy HTTP/HTTPS agora com `TCP_NODELAY`, cache de IP/DNS, buffers de 128 KB e bloqueio por caminho HTTP.
4. **Extensão de navegador expandida (YouTube + Web global):**
   - Mantém o bloqueio seguro de anúncios no YouTube (sem mexer na velocidade ou posição do vídeo) e agora também sincroniza regras `declarativeNetRequest` globais de terceiros para outros sites.

## Como usar no Windows (Modo Pacotes — Recomendado)

### Opção 1 — 1 clique (mais fácil)
Dê duplo clique em:

```text
scripts\iniciar_qproxy_admin.bat
```

Ele pede permissão de Administrador (UAC), baixa e verifica o **SHA-256** do driver oficial **WinDivert 2.2.2** automaticamente na primeira vez e inicia o Qproxy em **Modo Pacotes do Windows**.

### Opção 2 — PowerShell / Terminal

```powershell
# 1) Instalar o driver oficial WinDivert 2.2.2 (verificação SHA-256 automática):
python main.py --install-windivert

# 2) Iniciar como Administrador (modo pacotes automático):
python main.py --elevate
```

Modos disponíveis via linha de comando:

```powershell
python main.py --mode auto    # Escolhe automaticamente: packet > dns > proxy
python main.py --mode packet  # Força filtragem de pacotes (requer Admin + WinDivert)
python main.py --mode dns     # Servidor DNS local (127.0.0.1:53) + cache + CNAME
python main.py --mode proxy   # Proxy HTTP/HTTPS otimizado (não requer Admin)
python main.py --mode hybrid  # Pacotes + Proxy juntos
```

> **Observação sobre antivírus / Windows Defender:** o driver assinado oficial do WinDivert (`basil00/WinDivert`) intercepta pacotes de rede e ocasionalmente pode gerar falso positivo no Windows Defender. Se o Defender impedir o carregamento do `WinDivert64.sys`, o Qproxy alterna automaticamente para o **Modo DNS Local** (sem depender do driver) ou você pode adicionar a pasta `data\windivert` às exclusões após conferir o hash SHA-256 (`63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`).

> **Recuperação rápida de rede:** se precisar restaurar proxy e DNS do Windows a qualquer momento, execute `python main.py --restore-network` ou `scripts\restore_windows_network.ps1`.

---

## Como o `main.py` opera

- recupera qualquer configuração antiga de proxy ou DNS do Qproxy;
- inicia o motor correspondente (`packet`, `dns`, `proxy` ou `hybrid`) e confirma o estado real via `/api/status` antes de alterar qualquer configuração do Windows;
- no **Modo Pacotes**, não ativa o proxy do Windows (zero sobrecarga no tráfego permitido);
- limpa o cache DNS do Windows (`ipconfig /flushdns`) para que bloqueios entrem em vigor na hora;
- detecta Chrome, Edge, Firefox e Brave e gera os pacotes da extensão;
- abre o painel em `http://127.0.0.1:8900`;
- restaura tudo automaticamente ao encerrar (inclusive via watchdog se a janela for fechada).

## Navegadores suportados

### Chrome

Configuração:

```json
"chrome_extension_id": "ID_PUBLICADO_NA_CHROME_WEB_STORE"
```

Quando o ID estiver configurado, o Qproxy usa:

```text
Software\Policies\Google\Chrome\ExtensionInstallForcelist
```

### Microsoft Edge

Configuração:

```json
"edge_extension_id": "ID_PUBLICADO_NO_EDGE_ADDONS"
```

Política:

```text
Software\Policies\Microsoft\Edge\ExtensionInstallForcelist
```

Em Windows não associado a domínio, o Edge restringe force-install a extensões listadas no Microsoft Edge Add-ons.

### Brave

Configuração:

```json
"brave_extension_id": "ID_DA_EXTENSAO"
```

Política:

```text
Software\Policies\BraveSoftware\Brave\ExtensionInstallForcelist
```

O Brave reutiliza as políticas Chromium no namespace próprio `BraveSoftware\Brave`.

### Firefox

Configuração:

```json
"firefox_extension_id": "qproxy-youtube@qproxy.local",
"firefox_signed_xpi": "data/browser/qproxy-youtube-signed.xpi"
```

O Qproxy aplica `ExtensionSettings` com `installation_mode=force_installed` e `install_url`.

Para instalação persistente normal, use um XPI assinado/publicado.

## Estados exibidos

Ao iniciar, o Qproxy agora mostra estados claros:

```text
Google Chrome: AGUARDANDO PUBLICAÇÃO
Microsoft Edge: AGUARDANDO PUBLICAÇÃO
Mozilla Firefox: AGUARDANDO ASSINATURA
Brave: AGUARDANDO PUBLICAÇÃO
```

Depois que os IDs/XPI válidos forem configurados:

```text
Google Chrome: INSTALAÇÃO CONFIGURADA
Microsoft Edge: INSTALAÇÃO CONFIGURADA
Mozilla Firefox: INSTALAÇÃO CONFIGURADA
Brave: INSTALAÇÃO CONFIGURADA
```

Isso diferencia navegador detectado de extensão realmente configurada.

## Configuração padrão

```json
"browser_companion": {
  "auto_detect": true,
  "auto_install": true,
  "package_dir": "data/browser",
  "managed_policy_install": true,

  "chrome_extension_id": null,
  "chrome_update_url": "https://clients2.google.com/service/update2/crx",

  "edge_extension_id": null,
  "edge_update_url": "https://edge.microsoft.com/extensionwebstorebase/v1/crx",

  "brave_extension_id": null,
  "brave_update_url": "https://clients2.google.com/service/update2/crx",

  "firefox_extension_id": "qproxy-youtube@qproxy.local",
  "firefox_signed_xpi": null
}
```

Nenhuma política é gravada enquanto o artefato necessário daquele navegador estiver ausente.

## Pacotes gerados

```text
data/browser/qproxy-youtube-companion.zip
data/browser/qproxy-youtube-companion.xpi
```

O ZIP é o pacote-base para Chrome/Edge/Brave. O XPI local é útil para teste/assinatura, mas não substitui uma assinatura válida do Firefox.

## Correções de estabilidade na V3.3

- O relay HTTP/HTTPS não cancela mais uma resposta quando uma das direções da conexão termina. Isso evita imagens/downloads truncados após o cliente finalizar o envio.
- Regras EasyList com caminhos (`/imagem.jpg`) ou restrições (`$image`, `$script`, `$third-party`) **não** são transformadas em bloqueio de domínio inteiro. Essas regras são ignoradas pelo proxy, que só entende hosts.
- Painel em `http://127.0.0.1:8900` com **Pausar proxy (10 min)** para comparar uma página com/sem filtragem. O proxy retorna sozinho; também existe o botão de retomada. Essa pausa não desativa a extensão de navegador.
- A extensão passou a agir somente quando o player do YouTube indica anúncio de verdade, e deixou de monitorar cada alteração visual da página.
- Quando um site perder imagens, confira em **Atividade recente** quais hosts foram bloqueados e use **liberar**. Não libere domínios desconhecidos indiscriminadamente.

**Importante:** detectar Firefox/Chrome/Edge/Brave e gerar o ZIP/XPI **não** instala a extensão. No Firefox, confirme em `about:addons` se o Qproxy YouTube Companion está ativo. Sem o complemento efetivamente instalado, anúncios embutidos nos vídeos continuarão passando. A instalação permanente depende de assinatura/loja; para teste local use `about:debugging#/runtime/this-firefox` e selecione `browser_extension/manifest.json`.

## Filtragem de rede no navegador (V3.3)

O YouTube Companion ganhou um conjunto pequeno de regras **declarativeNetRequest** (DNR) para domínios publicitários de terceiros em páginas do YouTube. Essas regras não se aplicam a imagens, vídeos nem à página principal; restringem-se a `script`, `xmlhttprequest`, `sub_frame` e `ping`. Isso **não garante eliminar anúncios first-party** embutidos no streaming de vídeo.

**Para funcionar, o complemento precisa estar instalado/ativo no navegador.** Gerar o arquivo `.xpi` por si só não instala o complemento.

## Correção do player na V3.4

O Companion **não acelera mais propagandas**, **não avança a posição do vídeo** e **não muda o áudio**. Agora ele tenta clicar apenas nos botões nativos de **Pular anúncio** e **Fechar propaganda**, quando o YouTube exibe esses controles. As regras DNR e a ocultação de blocos patrocinados continuam ativas.

Em anúncios não puláveis, o vídeo publicitário pode continuar aparecendo: essa decisão evita travar ou modificar a velocidade do conteúdo principal. Se o Firefox já ficou com velocidade incorreta, recarregue a página e ajuste a velocidade pelo menu do próprio YouTube uma vez; isso não será mais modificado pela extensão.

Para usar o código novo, substitua a pasta local atualizada, recarregue o Qproxy YouTube Companion em `about:debugging#/runtime/this-firefox` e recarregue a aba do YouTube. Apenas executar o novo `main.py` não atualiza uma extensão temporária já carregada no navegador.

## Central de bloqueios (V3.5)

Execute o Qproxy normalmente e abra o painel local:

```text
http://127.0.0.1:8900
```

O painel permite:

- **Consultar todas as regras** por domínio, com busca e paginação (não carrega dezenas de milhares de linhas de uma vez).
- Ver a **atividade recente** e clicar em **Bloquear** ao lado de uma conexão permitida. Confirme antes que o host pertence à propaganda: bloquear um domínio de imagem ou API pode prejudicar um site legítimo.
- **Bloquear manualmente**, consultar apenas **Bloqueados por mim** e remover esses bloqueios.
- **Liberar domínios** pela whitelist; útil quando imagens/funcionalidades deixam de carregar. A whitelist prevalece sobre listas externas e bloqueios manuais.
- Conferir a última tentativa de atualização de cada fonte e forçar uma atualização com um botão.
- Pausar o bloqueio do **proxy** por até 10 minutos para diagnosticar falsos positivos (isso não pausa uma extensão do navegador).

Os bloqueios manuais são salvos em `data/manual_blocklist.txt`; o arquivo de liberações continua em `data/whitelist.txt`. Ambos sobrevivem a reinicializações e atualizações de listas. Se uma regra manual for removida mas também fizer parte de uma lista externa, o domínio continuará bloqueado até ser colocado na whitelist.

### Fontes confiáveis e atualizações

A V3.5 inclui o arquivo de hosts consolidado de [StevenBlack/hosts](https://github.com/StevenBlack/hosts), além das fontes já usadas EasyList e EasyPrivacy. O StevenBlack reúne listas mantidas pela comunidade e possui formato `hosts`, apropriado ao filtro por domínio do Qproxy.

**O Qproxy verifica as fontes automaticamente ao iniciar e a cada 6 horas enquanto estiver em execução.** Não há atualização em segundo plano quando o Qproxy está fechado. A atualização valida formato, tamanho e contagem de regras; se a fonte apresentar erro ou redução anormal, mantém a versão em cache. A interface informa falhas.

Atenção: EasyList/EasyPrivacy contêm muitas regras específicas de URL, recurso e página. O proxy só aplica as regras que identificam domínios de forma inequívoca, evitando bloquear imagens/vídeos indevidamente.

**YouTube:** nenhuma lista de domínios garante remover anúncios que usam a mesma origem do vídeo. Para esses casos, é necessário que o YouTube Companion esteja **realmente instalado e ativado** no navegador; não basta que o Qproxy o detecte ou gere um XPI. A extensão não altera velocidade/posição do vídeo.


## Desempenho e anúncios antes dos vídeos — V3.6

### Recuperar a agilidade da navegação

- **Atualização das listas fora do loop de rede:** enquanto as listas StevenBlack/EasyList/EasyPrivacy são recarregadas, o proxy mantém as regras anteriores disponíveis. A troca do conjunto atualizado é atômica.
- **Conexão IPv4/IPv6 com Happy Eyeballs (RFC 8305):** o proxy pode iniciar a segunda tentativa quando a primeira família IP não responde rapidamente; padrão `happy_eyeballs_delay_seconds: 0.25`.
- **Menos gravações síncronas das estatísticas:** os contadores são gravados a cada 200 requisições, em vez de 25, e salvos normalmente ao encerrar. Em uma falha abrupta podem perder-se os últimos contadores ainda não gravados.
- **Indicadores de diagnóstico:** o painel apresenta tempo médio de estabelecimento de conexão, quantidade de amostras e conexões acima de 1 segundo.

Essas otimizações reduzem overhead e evitam pausas de processamento; **não aumentam sua banda contratada**. A melhora percebida depende da rede, dos sites e da configuração do navegador. Não foi medida uma porcentagem real de ganho na sua máquina.

### Anúncios ao começar um vídeo no YouTube

O Companion agora verifica o player aproximadamente a cada 200 ms e observa **apenas as alterações da classe do player**, permitindo tentar o botão nativo de pular mais cedo, inclusive em navegação interna do YouTube. Ele **não altera velocidade, posição, reprodução ou volume**, para evitar o problema anterior.

Anúncios de início de vídeo que o YouTube entrega pelo mesmo domínio do conteúdo **não podem ser eliminados com segurança pelo proxy HTTPS sem inspeção de conteúdo**. A melhoria na detecção não garante que um anúncio não pulável desapareça.

**Se você usa Firefox**, o caminho mais eficaz para filtragem completa de anúncios do YouTube é o [uBlock Origin oficial, na Mozilla Add-ons](https://addons.mozilla.org/pt-BR/firefox/addon/ublock-origin/), que trabalha com regras de rede e de página. Você escolhe instalá-lo no Firefox; o Qproxy não modifica o navegador nem instala extensões de terceiros sem confirmação. Evite configurar duas extensões para manipular os mesmos controles do vídeo se observar conflitos. O Qproxy continua útil para bloquear domínios de publicidade e rastreadores nos demais programas que usam o proxy do sistema.


## Qproxy nativo dentro do navegador — V3.7

O próprio **Qproxy YouTube Companion** agora possui um background script compatível com Firefox (event page) e Chrome/Edge/Brave (service worker), sem depender de instalar o uBlock Origin. O Qproxy compila regras de URL e rede reconhecíveis a partir das listas EasyList e EasyPrivacy já baixadas para o proxy, preservando limites de segurança (não bloquear `image`, `media`, nem `main_frame`). O compilador só usa regras conservadoras aplicáveis a páginas do YouTube, com limite de 800 regras. O navegador aplica esses filtros através da API nativa `declarativeNetRequest`, em vez de tentar manipular o vídeo.

Fluxo: `python main.py` → Qproxy atualiza listas externas a cada 6 horas → compila `data/remote/browser_rules.json` → complemento obtém `http://127.0.0.1:8900/api/browser-rules` ao iniciar e a cada 15 minutos → aplica atualização **atômica** das regras. Se o Qproxy ficar offline ou a lista estiver inválida, as regras já instaladas no navegador são preservadas.

**Instalação:** este recurso só funciona se o próprio complemento estiver **realmente instalado e autorizado** no navegador. Em Firefox normal, instalação permanente ainda depende de XPI assinado pela Mozilla; empacotar XPI não equivale a assinar/instalar. Para testar sua versão local, abra `about:debugging#/runtime/this-firefox`, carregue `browser_extension/manifest.json` e recarregue o YouTube. No Chrome/Edge/Brave, use o modo desenvolvedor e `Carregar sem compactação`, escolhendo `browser_extension`. Autorize o acesso a `http://127.0.0.1` se solicitado.

**Limite:** regras de navegador mais ricas podem bloquear recursos publicitários específicos, mas anúncios first-party veiculados dentro do mesmo fluxo de vídeo do YouTube ainda podem escapar. O Qproxy não promete 100% de bloqueio. Não altera o acelerador de vídeo nem inspeciona HTTPS via MITM.


## Diagnóstico real no Chrome e Firefox — V3.8

**Instalar o complemento não significa que as regras funcionem.** Para verificar:
1. Atualize o código Qproxy, execute `python main.py` e deixe a atualização inicial das listas terminar.
2. Abra `chrome://extensions` → Qproxy YouTube Companion → **Recarregar** (ou `about:debugging#/runtime/this-firefox` no Firefox).
3. Clique no ícone **Qproxy** na barra do navegador. A nova janela de diagnóstico mostra conexão com Qproxy, número **real** de regras dinâmicas aceitas pelo navegador, ativação da lista estática, data de sincronização e erros.
4. Se houver "Desconectado", confirme o painel `http://127.0.0.1:8900`. Se houver "0" regras dinâmicas, use **Sincronizar agora**; se permanecer zero, veja o erro e o estado de atualização das listas no painel.
5. No Chrome em modo desenvolvedor, um teste local verifica se uma requisição publicitária simulada corresponderia a uma regra. Esse teste **não mede anúncios de vídeos reais**, somente o funcionamento do mecanismo DNR.

O Qproxy agora guarda mensagens de falha em `chrome.storage.local`, reconfere as regras instaladas após a atualização e tenta sincronizar a cada **2 minutos**, inclusive quando o programa abre sem cache e termina o primeiro download depois da extensão.

Corrigi também o compilador de regras ABP que descartava filtros quando opções válidas continham domínios separados por `|`, como `$domain=youtube.com|music.youtube.com`.

**Limitação estrutural, mesmo após esta correção:** o Qproxy não é um bloqueador completo de anúncios first-party do player. Muitos pré-anúncios do YouTube podem continuar mesmo com centenas de regras DNR ativas. Regras de domínio e scriptless DNR não substituem scriptlets e processamento de respostas que bloqueadores maduros usam. Não é confiável bloquear o fluxo de vídeo ou alterar velocidade para simular remoção de anúncios. O objetivo desta atualização é diagnosticar o que funciona e corrigir a sincronização, não afirmar que todos os pré-anúncios foram eliminados.

## YouTube

O Companion:

- tenta pular anúncios;
- fecha overlays;
- usa apenas o botão nativo de pular e o de fechar overlays;
- **não altera velocidade, posição, áudio ou estado do player**, evitando efeitos colaterais;
- esconde slots e cards patrocinados identificáveis.

A allowlist do proxy protege a infraestrutura essencial do YouTube para não quebrar a reprodução.

## Se a internet ficar presa

```powershell
python main.py --restore-proxy
```

## Testes

```powershell
python -m unittest discover -s tests -v
```

## Licença

Código do Qproxy: MIT. Listas de terceiros possuem suas próprias licenças.
