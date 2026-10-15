# Qproxy V3.6

Qproxy combina três camadas:

1. **proxy local Python** para anúncios e trackers por domínio;
2. **Qproxy YouTube Companion** para anúncios e elementos patrocinados dentro do YouTube;
3. **integração automática com Chrome, Edge, Firefox e Brave** no Windows.

## Uso

```powershell
python main.py
```

O `main.py`:

- recupera proxy antigo do Qproxy;
- inicia o servidor;
- só ativa o proxy do Windows depois que `127.0.0.1:8899` responde;
- detecta Chrome, Edge, Firefox e Brave;
- gera os pacotes da extensão;
- aplica a política de instalação quando houver um ID/pacote assinado configurado;
- abre o painel;
- restaura o proxy anterior ao encerrar.

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
