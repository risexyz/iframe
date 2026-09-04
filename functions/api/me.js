async function hashToken(token) {
  const data = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  for (const cookie of cookieHeader.split(";")) {
    const [key, ...value] = cookie.trim().split("=");
    if (key === name) return value.join("=");
  }
  return null;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

export async function onRequestGet(context) {
  try {
    if (!context.env?.DB) {
      return json({ success: false, message: "Database belum terhubung." }, 503);
    }

    const token = getCookie(context.request, "session");
    if (!token) return json({ success: false, message: "Belum login." }, 401);

    const tokenHash = await hashToken(token);
    const user = await context.env.DB.prepare(`
      SELECT users.id, users.username, users.name, users.role, users.active, sessions.expires_at
      FROM sessions
      INNER JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ?
        AND users.active = 1
        AND sessions.expires_at > ?
      LIMIT 1
    `).bind(tokenHash, new Date().toISOString()).first();

    if (!user) {
      return json({ success: false, message: "Session tidak valid atau sudah expired." }, 401);
    }

    return json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        role: user.role
      }
    });
  } catch {
    return json({ success: false, message: "Terjadi kesalahan server." }, 500);
  }
}
