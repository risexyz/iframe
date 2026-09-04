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

export async function onRequestPost(context) {
  try {
    const token = getCookie(
      context.request,
      "session"
    );

    if (token) {
      const tokenHash = await hashToken(token);

      await context.env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE token_hash = ?
        `)
        .bind(tokenHash)
        .run();
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: "Logout berhasil."
      }),
      {
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie":
            "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
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
