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
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(env.CHANNEL_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const sigBinary = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBinary,
      encoder.encode(bodyText)
    );

    if (!isValid) {
      return new Response("Invalid Signature", { status: 401 });
    }

    return;
  }
};