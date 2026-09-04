async function hashPassword(password) {
  const data = new TextEncoder().encode(password);

  const hash = await crypto.subtle.digest(
    "SHA-256",
    data
  );

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

  const hash = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequestPost(context) {
  try {
    const body = await context.request.json();

    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    if (!username || !password) {
      return Response.json(
        {
          success: false,
          message: "Username dan password wajib diisi."
        },
        { status: 400 }
      );
    }

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
      return Response.json(
        {
          success: false,
          message: "Username atau password salah."
        },
        { status: 401 }
      );
    }

    if (user.active !== 1) {
      return Response.json(
        {
          success: false,
          message: "Akun Anda tidak aktif."
        },
        { status: 403 }
      );
    }

    const passwordHash = await hashPassword(password);

    if (passwordHash !== user.password_hash) {
      return Response.json(
        {
          success: false,
          message: "Username atau password salah."
        },
        { status: 401 }
      );
    }

    const token = createToken();
    const tokenHash = await hashToken(token);

    const expiresAt = new Date(
      Date.now() + 24 * 60 * 60 * 1000
    ).toISOString();

    await context.env.DB
      .prepare(`
        INSERT INTO sessions
        (user_id, token_hash, expires_at)
        VALUES (?, ?, ?)
      `)
      .bind(
        user.id,
        tokenHash,
        expiresAt
      )
      .run();

    return new Response(
      JSON.stringify({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          name: user.name,
          role: user.role
        }
      }),
      {
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie":
            `session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
        }
      }
    );

  } catch (error) {
    return Response.json(
      {
        success: false,
        message: "Terjadi kesalahan server."
      },
      { status: 500 }
    );
  }
}
