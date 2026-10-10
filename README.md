# Qproxy V3.3

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
- Painel em `http://127.0.0.1:8900` com **Pausar bloqueio (10 min)** para comparar uma página com/sem filtragem. O bloqueio retorna sozinho; também existe o botão de retomada.
- A extensão passou a agir somente quando o player do YouTube indica anúncio de verdade, e deixou de monitorar cada alteração visual da página.
- Quando um site perder imagens, confira em **Atividade recente** quais hosts foram bloqueados e use **liberar**. Não libere domínios desconhecidos indiscriminadamente.

**Importante:** detectar Firefox/Chrome/Edge/Brave e gerar o ZIP/XPI **não** instala a extensão. No Firefox, confirme em `about:addons` se o Qproxy YouTube Companion está ativo. Sem o complemento efetivamente instalado, anúncios embutidos nos vídeos continuarão passando. A instalação permanente depende de assinatura/loja; para teste local use `about:debugging#/runtime/this-firefox` e selecione `browser_extension/manifest.json`.

## YouTube

O Companion:

- tenta pular anúncios;
- fecha overlays;
- acelera/muta anúncios ativos quando necessário;
- restaura o estado do vídeo normal;
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
