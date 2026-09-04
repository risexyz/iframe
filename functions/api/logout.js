async function hashToken(token) {
  const data = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const cookie of header.split(";")) {
    const [key, ...value] = cookie.trim().split("=");
    if (key === name) return value.join("=");
  }
  return null;
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

export async function onRequestPost(context) {
  try {
    if (!context.env?.DB) {
      return json({ success: false, message: "Database belum terhubung." }, 503);
    }

    const token = getCookie(context.request, "session");
    if (token) {
      const tokenHash = await hashToken(token);
      await context.env.DB
        .prepare("DELETE FROM sessions WHERE token_hash = ?")
        .bind(tokenHash)
        .run();
    }

    return json({ success: true, message: "Logout berhasil." }, 200, {
      "Set-Cookie": "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
    });
  } catch {
    return json({ success: false, message: "Terjadi kesalahan server." }, 500);
  }
}
