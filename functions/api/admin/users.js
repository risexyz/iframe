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

  for (const cookie of cookieHeader.split(";")) {
    const [key, ...value] = cookie.trim().split("=");

    if (key === name) {
      return value.join("=");
    }
  }

  return null;
}

async function getAdmin(context) {
  const token = getCookie(
    context.request,
    "session"
  );

  if (!token) {
    return null;
  }

  const tokenHash = await hashToken(token);

  const user = await context.env.DB
    .prepare(`
      SELECT
        users.id,
        users.username,
        users.name,
        users.role,
        users.active
      FROM sessions
      INNER JOIN users
        ON users.id = sessions.user_id
      WHERE sessions.token_hash = ?
        AND sessions.expires_at > ?
        AND users.active = 1
      LIMIT 1
    `)
    .bind(
      tokenHash,
      new Date().toISOString()
    )
    .first();

  if (!user || user.role !== "admin") {
    return null;
  }

  return user;
}

export async function onRequestGet(context) {
  try {
    const admin = await getAdmin(context);

    if (!admin) {
      return Response.json(
        {
          success: false,
          message: "Akses admin ditolak."
        },
        { status: 403 }
      );
    }

    const result = await context.env.DB
      .prepare(`
        SELECT
          id,
          username,
          name,
          role,
          active,
          created_at
        FROM users
        ORDER BY id DESC
      `)
      .all();

    return Response.json({
      success: true,
      users: result.results
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

export async function onRequestPost(context) {
  try {
    const admin = await getAdmin(context);

    if (!admin) {
      return Response.json(
        {
          success: false,
          message: "Akses admin ditolak."
        },
        { status: 403 }
      );
    }

    const body = await context.request.json();

    const username = String(
      body.username || ""
    ).trim();

    const password = String(
      body.password || ""
    );

    const name = String(
      body.name || ""
    ).trim();

    if (!username || !password || !name) {
      return Response.json(
        {
          success: false,
          message: "Nama, username, dan password wajib diisi."
        },
        { status: 400 }
      );
    }

    if (username.length < 3) {
      return Response.json(
        {
          success: false,
          message: "Username minimal 3 karakter."
        },
        { status: 400 }
      );
    }

    if (password.length < 6) {
      return Response.json(
        {
          success: false,
          message: "Password minimal 6 karakter."
        },
        { status: 400 }
      );
    }

    const existing = await context.env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE username = ?
        LIMIT 1
      `)
      .bind(username)
      .first();

    if (existing) {
      return Response.json(
        {
          success: false,
          message: "Username sudah digunakan."
        },
        { status: 409 }
      );
    }

    const passwordHash =
      await hashPassword(password);

    await context.env.DB
      .prepare(`
        INSERT INTO users
        (
          username,
          password_hash,
          name,
          role,
          active
        )
        VALUES (?, ?, ?, 'user', 1)
      `)
      .bind(
        username,
        passwordHash,
        name
      )
      .run();

    return Response.json({
      success: true,
      message: "Pengguna berhasil dibuat."
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
