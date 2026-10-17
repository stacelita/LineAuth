export default {
  async fetch(request, env) {
    console.log("GAS_URL:", env.GAS_URL); 
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // 1. LINEからの署名とボディを取得
    const bodyText = await request.text();
    const signature = request.headers.get("x-line-signature");

    if (!signature) {
      return new Response("No Signature", { status: 401 });
    }

    // 2. 署名検証 (HMAC-SHA256)
    //    登録済みのチャネルシークレットのどれかで一致すれば、いずれかの公式アカウントからの正しいリクエスト
    //    CHANNEL_SECRETS：カンマ区切りで複数指定（部署＝公式アカウントが増えたら書き足す）
    //    CHANNEL_SECRET ：1つだけの従来の設定（そのままでも動くように残す）
    const secrets = [env.CHANNEL_SECRET, ...(env.CHANNEL_SECRETS || "").split(",")]
      .map(s => (s || "").trim())
      .filter(s => s);

    const encoder = new TextEncoder();
    const sigBinary = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    let isValid = false;
    for (const secret of secrets) {
      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"]
      );
      if (await crypto.subtle.verify("HMAC", key, sigBinary, encoder.encode(bodyText))) {
        isValid = true;
        break;
      }
    }

    if (!isValid) {
      return new Response("Invalid Signature", { status: 403 });
    }

    // 3. 検証に成功したらGASへ転送（どの部署宛てかは GAS 側で destination を見て判別する）
    // GAS側で「Workersから来た」と判別するための秘密鍵をヘッダーに添える
    return await fetch(env.GAS_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Custom-Auth": env.PROXY_SECRET // GAS側でこれをチェック
      },
      body: bodyText
    });
  }
};