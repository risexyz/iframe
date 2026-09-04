async function hashPassword(password) {
  const data = new TextEncoder().encode(password);
  const hash = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequestPost(context) {
  try {
    const body = await context.request.json();

    const username = String(body.username || "").trim();
    const password = String(body.password || "");
    const name = String(body.name || "").trim();

    if (!username || !password || !name) {
      return Response.json(
        {
          success: false,
          message: "Username, password, dan nama wajib diisi."
        },
        { status: 400 }
      );
    }

    if (password.length < 8) {
      return Response.json(
        {
          success: false,
          message: "Password minimal 8 karakter."
        },
        { status: 400 }
      );
    }

    const existing = await context.env.DB
      .prepare("SELECT id FROM users WHERE username = ?")
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

    const passwordHash = await hashPassword(password);

    await context.env.DB
      .prepare(`
        INSERT INTO users
        (username, password_hash, name, role, active)
        VALUES (?, ?, ?, 'admin', 1)
      `)
      .bind(username, passwordHash, name)
      .run();

    return Response.json({
      success: true,
      message: "Admin berhasil dibuat."
    });

  } catch (error) {
    return Response.json(
      {
        success: false,
        message: "Terjadi kesalahan.",
        error: error.message
      },
      { status: 500 }
    );
  }
}
