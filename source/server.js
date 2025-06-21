const https = require("https");
const fs = require("fs");
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
  WINDOW_MS: 15 * 60 * 1000, // 15 minutos
  MAX: 100 // limite por IP
};

// Certificado do servidor
const server = https.createServer({
  cert: fs.readFileSync("certs/https.crt"),
  key: fs.readFileSync("certs/https.key")
});

const wss = new WebSocket.Server({ server });

// Limpeza periódica de tentativas de conexão antigas
setInterval(() => {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT.WINDOW_MS;
  
  connectionAttempts.forEach((attempts, ip) => {
    const filtered = attempts.filter(t => t > windowStart);
    if (filtered.length === 0) {
      connectionAttempts.delete(ip);
    } else {
      connectionAttempts.set(ip, filtered);
    }
  });
}, RATE_LIMIT.WINDOW_MS);

// Gerar certificados com validade
function generateCertificate(username) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01' + crypto.randomBytes(8).toString('hex');
  
  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date();
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

// Renovar certificado
function renewCertificate(username, oldPrivateKey) {
  const privateKey = forge.pki.privateKeyFromPem(oldPrivateKey);
  const cert = forge.pki.createCertificate();
  
  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date();
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

// Carregar/gravar usuários
function loadUsers() {
  if (!fs.existsSync(usersFile)) return [];
  try {
    return JSON.parse(fs.readFileSync(usersFile));
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

// Middleware de autenticação
async function authenticate(ws, credentials) {
  const users = loadUsers();
  const user = users.find(u => u.username === credentials.username);
  
  if (!user) throw new Error("Usuário não encontrado");
  
  const match = await bcrypt.compare(credentials.password, user.password);
  if (!match) throw new Error("Senha incorreta");
  
  // Verificar validade do certificado
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
  
  // Rate limiting manual
  const now = Date.now();
  const windowStart = now - RATE_LIMIT.WINDOW_MS;
  
  const attempts = (connectionAttempts.get(ip) || []).filter(
    timestamp => timestamp > windowStart
  );
  
  if (attempts.length >= RATE_LIMIT.MAX) {
    console.log(`Rate limit excedido para ${ip}`);
    ws.close(1008, "Rate limit exceeded");
    return;
  }
  
  attempts.push(now);
  connectionAttempts.set(ip, attempts);

  ws.on("message", async function incoming(data) {
    try {
      const message = JSON.parse(data);
      
      // Validação de entrada
      if (message.type === "register" || message.type === "login") {
        if (!message.username || !message.password) {
          throw new Error("Username e password são obrigatórios");
        }
        if (message.username.length > 20 || message.password.length > 100) {
          throw new Error("Credenciais muito longas");
        }
        if (!/^[a-zA-Z0-9_]+$/.test(message.username)) {
          throw new Error("Username deve conter apenas letras, números e underscores");
        }
      }

      // Registrar novo usuário
      if (message.type === "register") {
        const users = loadUsers();
        if (users.some(u => u.username === message.username)) {
          throw new Error("Usuário já existe");
        }

        const hashedPassword = await bcrypt.hash(message.password, SALT_ROUNDS);
        const certData = generateCertificate(message.username);

        const newUser = {
          username: message.username,
          password: hashedPassword,
          certificate: certData.certificate,
          privateKey: certData.privateKey,
          certExpires: certData.expires,
          createdAt: new Date().toISOString()
        };

        saveUser(newUser);
        
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
        onlineUsers.add(message.username);
        
        // Notificar todos sobre novo usuário online
        broadcastOnlineUsers();
        
        const history = fs.existsSync(logFile) ? 
          JSON.parse(fs.readFileSync(logFile)) : [];
        
        ws.send(JSON.stringify({ 
          type: "login_success",
          username: user.username,
          history,
          onlineUsers: Array.from(onlineUsers),
          certificate: user.certificate,
          privateKey: user.privateKey
        }));
        return;
      }

      // Mensagem de chat
      if (message.message && message.signature && message.certificate) {
        if (message.message.length > 500) {
          throw new Error("Mensagem muito longa (máximo 500 caracteres)");
        }

        // Verificar se o certificado é válido
        if (!message.certificate.includes('-----BEGIN CERTIFICATE-----')) {
          throw new Error("Certificado inválido");
        }

        const publicKey = crypto.createPublicKey(message.certificate);
        const verified = crypto.verify(
          "sha256",
          Buffer.from(message.message),
          publicKey,
          Buffer.from(message.signature, "base64")
        );

        if (!verified) throw new Error("Assinatura inválida");

        // Salvar mensagem
        const entry = { 
          timestamp: Date.now(), 
          sender: ws.cn, 
          to: message.to || null, 
          message: message.message 
        };
        
        const existing = fs.existsSync(logFile) ? 
          JSON.parse(fs.readFileSync(logFile)) : [];
        existing.push(entry);
        fs.writeFileSync(logFile, JSON.stringify(existing, null, 2));

        // Broadcast
        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            if (!message.to || client.cn === message.to || client === ws) {
              client.send(JSON.stringify({ 
                from: ws.cn, 
                message: message.message,
                to: message.to,
                type: "message"
              }));
            }
          }
        });
      }

    } catch (e) {
      console.error("Erro:", e.message);
      ws.send(JSON.stringify({ 
        type: "error",
        message: e.message 
      }));
    }
  });

  // Remover usuário da lista ao desconectar
  ws.on("close", () => {
    if (ws.cn) {
      onlineUsers.delete(ws.cn);
      broadcastOnlineUsers();
      console.log(`Usuário ${ws.cn} desconectado`);
    }
  });
});

// Atualizar lista de usuários online para todos
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
  console.log("Servidor WebSocket seguro rodando em https://localhost:8443");
});