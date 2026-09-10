export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (url.pathname === '/auth/login' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { userId, username } = body;

        if (!userId || !username) {
          return new Response(JSON.stringify({ error: 'userId e username são obrigatórios' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        const token = await generateEd25519JWT({ userId, username }, env.JWT_PRIVATE_KEY);
        
        return new Response(JSON.stringify({ token }), {
          status: 200,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Erro interno ao gerar token' }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
    }

    if (url.pathname === '/ws' || url.pathname === '/ws/') {
      const token = url.searchParams.get('token');
      const roomCode = url.searchParams.get('room') || 'GLOBAL_HOSPITAL';

      if (!token) {
        return new Response(JSON.stringify({ error: 'Acesso negado: Token JWT ausente.' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      const userData = await verifyEd25519JWT(token, env.JWT_PUBLIC_KEY);
      if (!userData) {
        return new Response(JSON.stringify({ error: 'Acesso negado: Token Ed25519 inválido ou expirado.' }), {
          status: 403,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      const id = env.GAME_ROOM.idFromName(roomCode);
      const stub = env.GAME_ROOM.get(id);

      const newHeaders = new Headers(request.headers);
      newHeaders.set('X-User-Id', userData.userId);
      newHeaders.set('X-Username', userData.username);

      const modifiedRequest = new Request(request, { headers: newHeaders });
      return stub.fetch(modifiedRequest);
    }

    return new Response('WS-00E Operacional.', { status: 200, headers: corsHeaders });
  }
};

export class GameRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = [];
  }

  async fetch(request) {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Esperando uma conexão WebSocket', { status: 426 });
    }

    const userId = request.headers.get('X-User-Id') || 'Anônimo';
    const username = request.headers.get('X-Username') || 'Funcionário Desconhecido';

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    this.handleSession(server, { userId, username });

    return new Response(null, { status: 101, webSocket: client });
  }

  handleSession(ws, userInfo) {
    this.state.acceptWebSocket(ws);
    
    ws.serializeAttachment({ userId: userInfo.userId, username: userInfo.username });
    this.sessions.push(ws);

    this.broadcast({
      type: 'PLAYER_JOINED',
      userId: userInfo.userId,
      username: userInfo.username,
      timestamp: new Date().toISOString()
    }, ws);

    ws.addEventListener('message', async (msg) => {
      try {
        const data = JSON.parse(msg.data);
        const attachment = ws.deserializeAttachment();

        if (data.type === 'CHAT_MESSAGE') {
          this.broadcast({
            type: 'CHAT_MESSAGE',
            userId: attachment.userId,
            username: attachment.username,
            message: data.message,
            timestamp: new Date().toISOString()
          });
        }
      } catch (err) {}
    });

    ws.addEventListener('close', () => {
      const attachment = ws.deserializeAttachment();
      this.sessions = this.sessions.filter(s => s !== ws);
      this.broadcast({
        type: 'PLAYER_LEFT',
        userId: attachment?.userId,
        username: attachment?.username,
        timestamp: new Date().toISOString()
      });
    });
  }

  broadcast(data, excludeWs = null) {
    const payload = JSON.stringify(data);
    for (const ws of this.sessions) {
      if (ws !== excludeWs) {
        try { ws.send(payload); } catch (e) {}
      }
    }
  }
}

async function generateEd25519JWT(payloadData, privateKeyHexOrRaw) {
  const header = { alg: "EdDSA", typ: "JWT" };
  const payload = {
    ...payloadData,
    exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24)
  };

  const headerB64 = uint8ArrayToBase64Url(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = uint8ArrayToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const privKeyBytes = base64UrlToUint8Array(privateKeyHexOrRaw);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    privKeyBytes,
    { name: "Ed25519" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "Ed25519",
    cryptoKey,
    new TextEncoder().encode(signingInput)
  );

  const signatureB64 = uint8ArrayToBase64Url(new Uint8Array(signature));
  return `${signingInput}.${signatureB64}`;
}

async function verifyEd25519JWT(token, publicKeyHexOrRaw) {
  try {
    if (!publicKeyHexOrRaw) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const dataToVerify = `${headerB64}.${payloadB64}`;

    const dataBytes = new TextEncoder().encode(dataToVerify);
    const signatureBytes = base64UrlToUint8Array(signatureB64);
    const pubKeyBytes = base64UrlToUint8Array(publicKeyHexOrRaw);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      pubKeyBytes,
      { name: "Ed25519" },
      false,
      ["verify"]
    );

    const isValid = await crypto.subtle.verify("Ed25519", cryptoKey, signatureBytes, dataBytes);
    if (!isValid) return null;

    const payloadJson = atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'));
    const payload = JSON.parse(payloadJson);

    if (payload.exp && Date.now() >= payload.exp * 1000) {
      return null;
    }

    return payload;
  } catch (e) {
    return null;
  }
}

function uint8ArrayToBase64Url(uint8Array) {
  let binString = "";
  for (let i = 0; i < uint8Array.length; i++) {
    binString += String.fromCharCode(uint8Array[i]);
  }
  return btoa(binString).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlToUint8Array(base64Url) {
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const binString = atob(base64);
  const bytes = new Uint8Array(binString.length);
  for (let i = 0; i < binString.length; i++) {
    bytes[i] = binString.charCodeAt(i);
  }
  return bytes;
}
