const https = require("https");
const fs = require("fs");
const WebSocket = require("ws");
const crypto = require("crypto");
const logFile = "chat_log.json";

const server = https.createServer({
  cert: fs.readFileSync("certs/https.crt"),
  key: fs.readFileSync("certs/https.key")
});

const wss = new WebSocket.Server({ server });

wss.on("connection", function connection(ws) {

  // Enviar histórico ao cliente recém-conectado
  if (fs.existsSync(logFile)) {
    try {
      const history = JSON.parse(fs.readFileSync(logFile));
      ws.send(JSON.stringify({ type: "history", data: history }));
    } catch (err) {
      console.error("Erro ao carregar histórico:", err);
    }
  }

  ws.on("message", function incoming(data) {
    console.log("Recebido:", data);

    let parsed;
    try {
      parsed = JSON.parse(data);
      console.log("Parsed:", parsed);
    } catch (e) {
      console.error("Erro ao parsear JSON:", e);
      return;
    }

    const { message, signature, certificate, to } = parsed;
    console.log("Destinatário:", to);


    try {
      const { createPublicKey } = require("crypto");
      const publicKey = createPublicKey(certificate);

      const verified = crypto.verify(
        "sha256",
        Buffer.from(message),
        publicKey,
        Buffer.from(signature, "base64")
      );
      if (!verified) throw new Error("Assinatura inválida");

      const match = certificate.match(/-----BEGIN CERTIFICATE-----([\\s\\S]+?)-----END CERTIFICATE-----/);
      let subject = "Desconhecido";

      if (certificate.includes("BEGIN CERTIFICATE")) {
        const fixedCert = certificate.replace(/\\n/g, '\n');
        const openssl = require("child_process").spawnSync("openssl", ["x509", "-noout", "-subject"], {
          input: fixedCert
        });
        const output = openssl.stdout.toString();
        console.log("🔍 OpenSSL output:", output);
        const cnMatch = output.match(/CN\s*=\s*([^\n\/,]+)/i);
        subject = cnMatch ? cnMatch[1].trim() : "Desconhecido";
      }


      ws.cn = subject; // associa CN à conexão

      const to = data.to || null;

      // Salvar no arquivo JSON
      const entry = { timestamp: Date.now(), sender: subject, to, message };
      const existing = fs.existsSync(logFile) ? JSON.parse(fs.readFileSync(logFile)) : [];
      existing.push(entry);
      fs.writeFileSync(logFile, JSON.stringify(existing, null, 2));


      // Broadcast
      wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          // Só envia para o destinatário correto (ou todos se to == null)
          if (!to || client.cn === to || client === ws) {
            client.send(JSON.stringify({ from: subject, message, to }));
          }
        }
      });

    } catch (e) {
      console.error("❌ Erro:", e.message);
      ws.send(JSON.stringify({ error: "Assinatura inválida" }));
    }
  });
});

server.listen(8443, () => {
  console.log("Servidor WebSocket seguro rodando em https://localhost:8443");
});
