# Chat Assinado com Certificados Locais

## Pré-requisitos
- Node.js instalado
- OpenSSL

## Gerar certificados

### Servidor
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/https.key -out certs/https.crt -days 365 -subj "/CN=localhost"

### Usuário
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/user.key -out certs/user.crt -days 365 -subj "/CN=Joao"

Cole o conteúdo de `user.key` e `user.crt` dentro do `client.html` como indicado.

## Rodar servidor

node server.js

Acesse: https://localhost:8443/client.html
Aceite o certificado self-signed no navegador.

⚠ Para evitar erros de certificado, acesse via Firefox ou use flag `--ignore-certificate-errors` no Chrome.
