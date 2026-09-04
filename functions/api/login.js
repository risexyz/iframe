async function hashPassword(password) {
  const data = new TextEncoder().encode(password);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function createToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hashToken(token) {
  const data = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
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

    const contentType = context.request.headers.get("Content-Type") || "";
    if (!contentType.toLowerCase().includes("application/json")) {
      return json({ success: false, message: "Format request tidak valid." }, 415);
    }

    let body;
    try {
      body = await context.request.json();
    } catch {
      return json({ success: false, message: "Data login tidak valid." }, 400);
    }

    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    if (!username || !password) {
      return json({ success: false, message: "Username dan password wajib diisi." }, 400);
    }

    if (username.length > 100 || password.length > 256) {
      return json({ success: false, message: "Data login terlalu panjang." }, 400);
    }

    // Remove expired sessions opportunistically so D1 does not grow forever.
    await context.env.DB
      .prepare("DELETE FROM sessions WHERE expires_at <= ?")
      .bind(new Date().toISOString())
      .run();

    const user = await context.env.DB
      .prepare(`
        SELECT id, username, password_hash, name, role, active
        FROM users
        WHERE username = ?
        LIMIT 1
      `)
      .bind(username)
      .first();

    if (!user) {
      return json({ success: false, message: "Username atau password salah." }, 401);
    }

    if (Number(user.active) !== 1) {
      return json({ success: false, message: "Akun Anda tidak aktif." }, 403);
    }

    const passwordHash = await hashPassword(password);
    if (passwordHash !== user.password_hash) {
      return json({ success: false, message: "Username atau password salah." }, 401);
    }

    const token = createToken();
    const tokenHash = await hashToken(token);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    await context.env.DB
      .prepare(`
        INSERT INTO sessions (user_id, token_hash, expires_at)
        VALUES (?, ?, ?)
      `)
      .bind(user.id, tokenHash, expiresAt)
      .run();

    return json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        role: user.role
      }
    }, 200, {
      "Set-Cookie": `session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
    });
  } catch {
    return json({ success: false, message: "Terjadi kesalahan server." }, 500);
  }
}
