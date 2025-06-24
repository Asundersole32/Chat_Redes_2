const https = require("https");
const fs = require("fs");
const path = require("path");
const WebSocket = require("ws");
const crypto = require("crypto");
const forge = require('node-forge');
const bcrypt = require('bcrypt');

// Configurações
const SALT_ROUNDS = 12;
const CERT_VALIDITY_DAYS = 90;
const logFile = "chat_log.json";
const usersFile = "users.json";

// Configurações de rate limiting
const connectionAttempts = new Map();
const RATE_LIMIT = {
  WINDOW_MS: 15 * 60 * 1000,
  MAX: 100
};

// Certificado do servidor
const server = https.createServer({
  cert: fs.readFileSync("certs/https.crt"),
  key: fs.readFileSync("certs/https.key")
}, (req, res) => {
  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(path.join(__dirname, 'client.html')));
  } else if (req.url === '/favicon.ico') {
    res.writeHead(204); // No Content
    res.end();
  } else {
    res.writeHead(404);
    res.end();
  }
});

const wss = new WebSocket.Server({ server });

// Inicializa arquivos se não existirem
if (!fs.existsSync(logFile)) fs.writeFileSync(logFile, '[]');
if (!fs.existsSync(usersFile)) fs.writeFileSync(usersFile, '[]');

// Função para salvar mensagens no log
function saveToLog(entry) {
  try {
    const logs = fs.existsSync(logFile) ? JSON.parse(fs.readFileSync(logFile)) : [];
    logs.push(entry);
    fs.writeFileSync(logFile, JSON.stringify(logs, null, 2));
  } catch (e) {
    console.error("Erro ao salvar no log:", e);
  }
}

// Geração de certificados
function generateCertificate(username) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  
  cert.publicKey = keys.publicKey;
  cert.serialNumber = crypto.randomBytes(8).toString('hex');
  
  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(now);
  cert.validity.notAfter.setDate(now.getDate() + CERT_VALIDITY_DAYS);
  
  const attrs = [
    { name: 'commonName', value: username },
    { name: 'countryName', value: 'BR' },
    { shortName: 'ST', value: 'SP' },
    { name: 'localityName', value: 'Sao Paulo' },
    { name: 'organizationName', value: 'Chat Seguro' },
    { shortName: 'OU', value: 'Users' }
  ];
  
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  
  return {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    certificate: forge.pki.certificateToPem(cert),
    expires: cert.validity.notAfter.toISOString()
  };
}

// Renovação de certificados
function renewCertificate(username, oldPrivateKey) {
  const privateKey = forge.pki.privateKeyFromPem(oldPrivateKey);
  const cert = forge.pki.createCertificate();
  
  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(now);
  cert.validity.notAfter.setDate(now.getDate() + CERT_VALIDITY_DAYS);
  
  const attrs = [
    { name: 'commonName', value: username },
    { name: 'countryName', value: 'BR' },
    { shortName: 'ST', value: 'SP' },
    { name: 'localityName', value: 'Sao Paulo' },
    { name: 'organizationName', value: 'Chat Seguro' },
    { shortName: 'OU', value: 'Users' }
  ];
  
  cert.publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(privateKey, forge.md.sha256.create());
  
  return {
    certificate: forge.pki.certificateToPem(cert),
    expires: cert.validity.notAfter.toISOString()
  };
}

// Gerenciamento de usuários
function loadUsers() {
  try {
    return fs.existsSync(usersFile) ? JSON.parse(fs.readFileSync(usersFile)) : [];
  } catch (e) {
    console.error("Erro ao carregar usuários:", e);
    return [];
  }
}

function saveUser(user) {
  const users = loadUsers();
  const index = users.findIndex(u => u.username === user.username);
  if (index >= 0) users[index] = user;
  else users.push(user);
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

// Autenticação
async function authenticate(ws, credentials) {
  const users = loadUsers();
  const user = users.find(u => u.username === credentials.username);
  
  if (!user) throw new Error("Usuário não encontrado");
  
  const match = await bcrypt.compare(credentials.password, user.password);
  if (!match) throw new Error("Senha incorreta");
  
  const certExpiry = new Date(user.certExpires);
  if (certExpiry < new Date()) {
    const renewed = renewCertificate(user.username, user.privateKey);
    user.certificate = renewed.certificate;
    user.certExpires = renewed.expires;
    saveUser(user);
  }
  
  ws.cn = user.username;
  ws.certificate = user.certificate;
  ws.privateKey = user.privateKey;
  
  return user;
}

// Lista de usuários online
const onlineUsers = new Set();

wss.on("connection", function connection(ws, req) {
  const ip = req.socket.remoteAddress;
  console.log(`Nova conexão de ${ip}`);
  
  // Rate limiting
  const now = Date.now();
  const windowStart = now - RATE_LIMIT.WINDOW_MS;
  
  const attempts = (connectionAttempts.get(ip) || []).filter(t => t > windowStart);
  
  if (attempts.length >= RATE_LIMIT.MAX) {
    console.log(`Rate limit excedido para ${ip}`);
    ws.close(1008, "Rate limit exceeded");
    return;
  }
  
  connectionAttempts.set(ip, [...attempts, now]);

  ws.on("message", async function incoming(data) {
    try {
      const message = JSON.parse(data);
      
      // Registro
      if (message.type === "register") {
        if (!message.username || !message.password) throw new Error("Credenciais necessárias");
        
        const users = loadUsers();
        if (users.some(u => u.username === message.username)) throw new Error("Usuário já existe");
        
        const hashedPassword = await bcrypt.hash(message.password, SALT_ROUNDS);
        const certData = generateCertificate(message.username);
        
        saveUser({
          username: message.username,
          password: hashedPassword,
          certificate: certData.certificate,
          privateKey: certData.privateKey,
          certExpires: certData.expires,
          createdAt: new Date().toISOString()
        });
        
        ws.send(JSON.stringify({
          type: "register_success",
          username: message.username,
          certificate: certData.certificate,
          privateKey: certData.privateKey
        }));
        return;
      }

      // Login
      if (message.type === "login") {
        const user = await authenticate(ws, message);
        onlineUsers.add(user.username);
        
        broadcastOnlineUsers();
        
        ws.send(JSON.stringify({
          type: "login_success",
          username: user.username,
          history: fs.existsSync(logFile) ? JSON.parse(fs.readFileSync(logFile)) : [],
          onlineUsers: Array.from(onlineUsers),
          certificate: user.certificate,
          privateKey: user.privateKey,
          publicKeys: loadUsers().reduce((acc, u) => {
            if (u.username !== user.username && u.certificate) acc[u.username] = u.certificate;
            return acc;
          }, {})
        }));
        return;
      }

      // Mensagens de chat
      if (message.payload && message.signature && message.certificate) {
        if (!message.certificate.includes('-----BEGIN CERTIFICATE-----')) throw new Error("Certificado inválido");
        
        const publicKey = crypto.createPublicKey(message.certificate);
        const verified = crypto.verify(
          "sha256",
          Buffer.from(JSON.stringify(message.payload)),
          publicKey,
          Buffer.from(message.signature, "base64")
        );
        
        if (!verified) throw new Error("Assinatura inválida");

        const msgToStore = message.payload.encrypted || message.payload.content;
        if (msgToStore.length > 500) throw new Error("Mensagem muito longa");

        // Salva no log
        saveToLog({
          timestamp: Date.now(),
          sender: ws.cn,
          to: message.payload.to || null,
          message: msgToStore,
          encrypted: !!message.payload.encrypted
        });

        // Broadcast
        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            if (!message.payload.to || client.cn === message.payload.to || client === ws) {
              const isRecipient = client.cn === message.payload.to;
              const isSender = client === ws;
              
              client.send(JSON.stringify({
                from: ws.cn,
                message: isRecipient && message.payload.encrypted ? 
                        message.payload.encrypted : // Envia criptografado apenas para o destinatário
                        message.payload.content,    // Envia plano para o remetente e mensagens públicas
                to: message.payload.to,
                encrypted: isRecipient && !!message.payload.encrypted // Marca como criptografado apenas para o destinatário
              }));
            }
          }
        });
      }
    } catch (e) {
      console.error("Erro:", e.message);
      ws.send(JSON.stringify({ type: "error", message: e.message }));
    }
  });

  ws.on("close", () => {
    if (ws.cn) {
      onlineUsers.delete(ws.cn);
      broadcastOnlineUsers();
      console.log(`Usuário ${ws.cn} desconectado`);
    }
  });
});

function broadcastOnlineUsers() {
  const usersList = Array.from(onlineUsers);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN && client.cn) {
      client.send(JSON.stringify({
        type: "online_users",
        users: usersList
      }));
    }
  });
}

server.listen(8443, () => {
  console.log("Servidor rodando em https://localhost:8443");
});