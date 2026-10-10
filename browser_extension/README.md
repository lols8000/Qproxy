# Qproxy YouTube Companion

Complemento do Qproxy para Chrome, Microsoft Edge, Firefox e Brave.

O proxy bloqueia anúncios/trackers por domínio. O Companion atua dentro do YouTube para lidar com anúncios first-party que compartilham infraestrutura com o vídeo.

## Distribuição

### Chrome

Use o pacote da extensão como base para publicação na Chrome Web Store. Depois informe o ID publicado em `chrome_extension_id`.

### Microsoft Edge

Publique no Microsoft Edge Add-ons e informe o ID em `edge_extension_id`.

### Brave

Brave é Chromium e aceita as políticas Chromium sob `Software\Policies\BraveSoftware\Brave`. Para distribuição automática, configure `brave_extension_id` e o canal de atualização apropriado.

### Firefox

O arquivo XPI precisa estar assinado/publicado para instalação persistente automática. Configure `firefox_signed_xpi` com o caminho ou URL do XPI assinado.

## Teste manual

Firefox:

```text
about:debugging#/runtime/this-firefox
```

Chrome:

```text
chrome://extensions
```

Edge:

```text
edge://extensions
```

Brave:

```text
brave://extensions
```

Nos navegadores Chromium, para teste local, use **Modo do desenvolvedor → Carregar sem compactação** e selecione a pasta `browser_extension`.

## Regras de rede

O arquivo `network_rules.json` adiciona regras DNR para provedores publicitários de terceiros **somente quando o iniciador da requisição for YouTube**. Tipos de recurso `image`, `media` e `main_frame` não são bloqueados por essas regras.

## O que faz

- esconde slots e cards patrocinados identificáveis;
- fecha overlays;
- tenta clicar em **Pular anúncio**;
- quando o player está realmente em estado de anúncio, muta/acelera e tenta avançar o anúncio;
- restaura mute, volume e velocidade ao retornar ao vídeo normal.

## Limite

O YouTube altera o player e a estrutura do DOM com frequência. O Companion evita bloquear os domínios de vídeo para preservar a reprodução.
