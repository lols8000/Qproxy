# Qproxy YouTube Companion

Complemento de navegador da V3 do Qproxy.

O proxy continua bloqueando anúncios/tracking por domínio. Esta extensão trabalha dentro da página do YouTube para lidar com anúncios que compartilham a mesma infraestrutura do vídeo.

## Firefox

1. Abra `about:debugging#/runtime/this-firefox`.
2. Clique em **Carregar extensão temporária...**.
3. Escolha o arquivo `manifest.json` desta pasta.
4. Recarregue o YouTube.

Em uma instalação comum do Firefox, uma extensão local não assinada carregada por `about:debugging` é temporária e precisa ser carregada novamente depois de reiniciar o navegador. Para instalação permanente, a extensão precisa ser empacotada/assinada ou distribuída por política apropriada.

## Chrome / Edge

1. Abra `chrome://extensions` ou `edge://extensions`.
2. Ative o **Modo do desenvolvedor**.
3. Clique em **Carregar sem compactação / Load unpacked**.
4. Escolha esta pasta `browser_extension`.

## O que faz

- oculta slots e cards patrocinados identificáveis;
- fecha overlays publicitários;
- tenta clicar nos botões atuais de pular anúncio;
- quando o YouTube marca o player como anúncio e não há botão de pular, muta/acelera e tenta avançar o vídeo publicitário;
- restaura volume/mute/velocidade quando o anúncio termina.

## Limite

O YouTube altera frequentemente estrutura, classes e fluxo de anúncios. O componente é deliberadamente conservador para não voltar a quebrar a reprodução normal.
