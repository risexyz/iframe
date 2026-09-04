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

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...value] = cookie.trim().split("=");

    if (key === name) {
      return value.join("=");
    }
  }

  return null;
}

export async function onRequestGet(context) {
  try {
    const token = getCookie(
      context.request,
      "session"
    );

    if (!token) {
      return Response.json(
        {
          success: false,
          message: "Belum login."
        },
        { status: 401 }
      );
    }

    const tokenHash = await hashToken(token);

    const user = await context.env.DB
      .prepare(`
        SELECT
          users.id,
          users.username,
          users.name,
          users.role,
          users.active,
          sessions.expires_at
        FROM sessions
        INNER JOIN users
          ON users.id = sessions.user_id
        WHERE sessions.token_hash = ?
          AND users.active = 1
          AND sessions.expires_at > ?
        LIMIT 1
      `)
      .bind(
        tokenHash,
        new Date().toISOString()
      )
      .first();

    if (!user) {
      return Response.json(
        {
          success: false,
          message: "Session tidak valid atau sudah expired."
        },
        { status: 401 }
      );
    }

    return Response.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        role: user.role
      }
    });

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
