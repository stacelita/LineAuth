export default {
  async fetch(request, env) {
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

    // 署名が Base64 として壊れている場合は、不正な署名として扱う
    let sigBinary;
    try {
      sigBinary = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    } catch {
      return new Response("Invalid Signature", { status: 403 });
    }

    const encoder = new TextEncoder();
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
    //    GAS はリクエストヘッダーを読めないため、「Workerを通ってきた」ことを示す合言葉は URL のパラメータ key で渡す
    //    （GAS 側のスクリプトプロパティ PROXY_SECRET と同じ値にする）
    const gasUrl = new URL(env.GAS_URL);
    if (env.PROXY_SECRET) {
      gasUrl.searchParams.set("key", env.PROXY_SECRET);
    }

    return await fetch(gasUrl.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: bodyText
    });
  }
};
