/**
 * LINE の Webhook を受け取り、署名を検証してから GAS へ転送する
 *
 * 環境変数
 *   CHANNEL_SECRETS：チャネルシークレット（カンマ区切りで複数。部署＝公式アカウントが増えたら書き足す）
 *   CHANNEL_SECRET ：1つだけの従来の設定（そのままでも動くように残す）
 *   GAS_URL        ：転送先の GAS Web アプリの URL
 *   PROXY_SECRET   ：Worker を通ってきたことを GAS に示す合言葉（GAS のスクリプトプロパティ PROXY_SECRET と同じ値）
 */
export default {
  async fetch(request, env, ctx) {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const bodyText = await request.text();
    const signature = request.headers.get("x-line-signature");
    if (!signature) {
      return new Response("No Signature", { status: 401 });
    }
    if (!(await isValidSignature(signature, bodyText, channelSecrets(env)))) {
      return new Response("Invalid Signature", { status: 403 });
    }

    // イベントがない Webhook（LINE Developers の「検証」ボタンなど）は GAS へ送らない
    if (!hasEvents(bodyText)) {
      return new Response("OK", { status: 200 });
    }

    // LINE にはすぐに 200 を返し、GAS への転送は応答のあとに続ける
    // （GAS の処理を待つと LINE 側でタイムアウトになることがある。返信は GAS から LINE へ直接送る）
    ctx.waitUntil(forwardToGas(env, bodyText));
    return new Response("OK", { status: 200 });
  },
};

/** 登録済みのチャネルシークレット */
function channelSecrets(env) {
  return [env.CHANNEL_SECRET, ...(env.CHANNEL_SECRETS || "").split(",")]
    .map(s => (s || "").trim())
    .filter(s => s);
}

/**
 * 署名（HMAC-SHA256）の検証
 * 登録済みのチャネルシークレットのどれかで一致すれば、いずれかの公式アカウントからの正しいリクエスト
 * 署名が Base64 として壊れている場合は、不正な署名として扱う
 */
async function isValidSignature(signature, bodyText, secrets) {
  let signatureBytes;
  try {
    signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
  } catch {
    return false;
  }

  const encoder = new TextEncoder();
  const body = encoder.encode(bodyText);
  for (const secret of secrets) {
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    if (await crypto.subtle.verify("HMAC", key, signatureBytes, body)) return true;
  }
  return false;
}

/** イベントが1件以上あるか（JSON として読めない場合は、念のため GAS へ送る） */
function hasEvents(bodyText) {
  try {
    const events = JSON.parse(bodyText).events;
    return !Array.isArray(events) || events.length > 0;
  } catch {
    return true;
  }
}

/**
 * GAS へ転送する（どの部署宛てかは GAS 側で destination を見て判別する）
 * GAS はリクエストヘッダーを読めないため、合言葉は URL のパラメータ key で渡す
 *
 * GAS の Web アプリは、処理を終えてから結果ページへのリダイレクト（302）を返す。
 * Webhook では結果ページを使わないので、リダイレクト先は取りに行かない
 */
async function forwardToGas(env, bodyText) {
  try {
    const gasUrl = new URL(env.GAS_URL);
    if (env.PROXY_SECRET) {
      gasUrl.searchParams.set("key", env.PROXY_SECRET);
    }

    const response = await fetch(gasUrl.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: bodyText,
      redirect: "manual",
    });
    if (!response.ok && response.status !== 302) {
      console.error(`GAS への転送が失敗しました（status ${response.status}）`);
    }
  } catch (e) {
    console.error("GAS への転送で例外が発生しました:", e.message);
  }
}
