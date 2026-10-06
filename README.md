# Qproxy V3.1

Qproxy combina:

1. **proxy local Python** para anúncios e trackers por domínio;
2. **Qproxy YouTube Companion** para anúncios e elementos patrocinados dentro do YouTube;
3. **detecção automática de navegadores instalados** no Windows.

## Uso

```powershell
python main.py
```

O `main.py`:

- recupera um proxy antigo que tenha ficado preso;
- inicia o Qproxy;
- ativa o proxy do Windows somente depois que o servidor responde;
- detecta Chrome, Edge, Firefox, Brave e Chromium;
- gera automaticamente os pacotes da extensão em `data/browser/`;
- tenta configurar instalação administrada somente quando existe um ID/pacote assinado configurado;
- abre o painel local;
- restaura o proxy anterior quando é encerrado.

Painel:

```text
http://127.0.0.1:8900
```

## Instalação automática da extensão

A V3.1 já faz a parte de detecção e distribuição automaticamente, mas navegadores modernos não permitem que um programa comum instale silenciosamente uma extensão local arbitrária.

### Chrome

Para instalação silenciosa suportada, configure um ID publicado/gerenciado em:

```json
"browser_companion": {
  "managed_policy_install": true,
  "chrome_extension_id": "ID_DA_EXTENSAO"
}
```

Por padrão, o Qproxy não grava políticas corporativas no navegador.

### Microsoft Edge

Use o ID da extensão publicada no Edge Add-ons:

```json
"browser_companion": {
  "managed_policy_install": true,
  "edge_extension_id": "ID_DA_EXTENSAO"
}
```

### Firefox

Firefox aceita instalação automática por política usando XPI assinado. Depois de obter um XPI assinado:

```json
"browser_companion": {
  "managed_policy_install": true,
  "firefox_signed_xpi": "data/browser/qproxy-youtube-signed.xpi"
}
```

O Qproxy usa o ID:

```text
qproxy-youtube@qproxy.local
```

### Brave / Chromium

Eles são detectados e o pacote Chromium é criado automaticamente. A integração silenciosa pode ser adicionada quando houver um canal de distribuição assinado apropriado.

## Pacotes gerados

Ao executar `python main.py`, o Qproxy cria:

```text
data/browser/qproxy-youtube-companion.zip
data/browser/qproxy-youtube-companion.xpi
```

O XPI gerado localmente é útil para empacotamento/teste, mas não é considerado assinado pelo Firefox comum.

## Por que não forçar a instalação local de qualquer jeito?

Chrome/Chromium tratam políticas de extensão como mecanismo administrativo. Distribuir software de consumidor que altera políticas corporativas para instalar extensões fora do fluxo oficial pode ser classificado como comportamento indesejado/malware.

Por isso o Qproxy só escreve políticas quando `managed_policy_install=true` **e** há um ID/artefato de distribuição configurado.

## YouTube

A extensão continua:

- tentando clicar em **Pular anúncio**;
- fechando overlays;
- acelerando/mutando anúncios ativos quando necessário;
- restaurando volume e velocidade do vídeo normal;
- ocultando cards e slots patrocinados identificáveis.

A allowlist de reprodução protege domínios essenciais como `youtube.com`, `googlevideo.com` e `ytimg.com`.

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
