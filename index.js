export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Configuração de CORS para permitir requisições do cliente
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    // Responde imediatamente a requisições de verificação CORS (Preflight)
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // Rota para gerar o JWT de login
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

    // Endpoint do WebSocket do jogo
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

// ... (Mantenha as classes GameRoom e as funções de criptografia Ed25519 inalteradas abaixo)
