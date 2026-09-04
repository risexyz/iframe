async function hashPassword(password) {
  const data = new TextEncoder().encode(password);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashToken(token) {
  const data = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const cookie of header.split(";")) {
    const [key, ...value] = cookie.trim().split("=");
    if (key === name) return value.join("=");
  }
  return null;
}

async function getAdmin(context) {
  const token = getCookie(context.request, "session");
  if (!token) return null;
  const tokenHash = await hashToken(token);

  const user = await context.env.DB.prepare(`
    SELECT users.id, users.username, users.name, users.role, users.active
    FROM sessions
    INNER JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
      AND users.active = 1
    LIMIT 1
  `).bind(tokenHash, new Date().toISOString()).first();

  if (!user || user.role !== "admin") return null;
  return user;
}

export async function onRequestGet(context) {
  try {
    const admin = await getAdmin(context);
    if (!admin) return Response.json({ success: false, message: "Akses admin ditolak." }, { status: 403 });

    const result = await context.env.DB.prepare(`
      SELECT id, username, name, role, active, created_at
      FROM users
      ORDER BY id DESC
    `).all();

    return Response.json({ success: true, users: result.results });
  } catch (error) {
    return Response.json({ success: false, message: "Terjadi kesalahan server." }, { status: 500 });
  }
}

export async function onRequestPost(context) {
  try {
    const admin = await getAdmin(context);
    if (!admin) return Response.json({ success: false, message: "Akses admin ditolak." }, { status: 403 });

    const body = await context.request.json();
    const username = String(body.username || "").trim();
    const password = String(body.password || "");
    const name = String(body.name || "").trim();

    if (!username || !password || !name) return Response.json({ success: false, message: "Nama, username, dan password wajib diisi." }, { status: 400 });
    if (username.length < 3) return Response.json({ success: false, message: "Username minimal 3 karakter." }, { status: 400 });
    if (password.length < 6) return Response.json({ success: false, message: "Password minimal 6 karakter." }, { status: 400 });

    const existing = await context.env.DB.prepare("SELECT id FROM users WHERE username = ? LIMIT 1").bind(username).first();
    if (existing) return Response.json({ success: false, message: "Username sudah digunakan." }, { status: 409 });

    const passwordHash = await hashPassword(password);
    await context.env.DB.prepare(`
      INSERT INTO users (username, password_hash, name, role, active)
      VALUES (?, ?, ?, 'user', 1)
    `).bind(username, passwordHash, name).run();

    return Response.json({ success: true, message: "Pengguna berhasil dibuat." });
  } catch (error) {
    return Response.json({ success: false, message: "Terjadi kesalahan server." }, { status: 500 });
  }
}

export async function onRequestPatch(context) {
  try {
    const admin = await getAdmin(context);
    if (!admin) return Response.json({ success: false, message: "Akses admin ditolak." }, { status: 403 });

    const body = await context.request.json();
    const userId = Number(body.id);

    // Reset password: { id, password }
    if (body.password !== undefined) {
      const password = String(body.password || "");
      if (!Number.isInteger(userId)) return Response.json({ success: false, message: "ID pengguna tidak valid." }, { status: 400 });
      if (password.length < 6) return Response.json({ success: false, message: "Password minimal 6 karakter." }, { status: 400 });
      if (userId === admin.id) return Response.json({ success: false, message: "Gunakan menu login untuk mengubah password admin." }, { status: 400 });

      const target = await context.env.DB.prepare("SELECT id, role, active FROM users WHERE id = ? LIMIT 1").bind(userId).first();
      if (!target) return Response.json({ success: false, message: "Pengguna tidak ditemukan." }, { status: 404 });
      if (target.role !== "user") return Response.json({ success: false, message: "Password akun admin tidak dapat diubah melalui menu ini." }, { status: 400 });

      const passwordHash = await hashPassword(password);
      await context.env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(passwordHash, userId).run();
      await context.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run();

      return Response.json({ success: true, message: "Password berhasil direset. User harus login kembali." });
    }

    // Aktif/nonaktif: { id, active }
    const active = Number(body.active);
    if (!Number.isInteger(userId) || ![0, 1].includes(active)) return Response.json({ success: false, message: "Data tidak valid." }, { status: 400 });
    if (userId === admin.id) return Response.json({ success: false, message: "Admin yang sedang login tidak dapat dinonaktifkan." }, { status: 400 });

    const target = await context.env.DB.prepare("SELECT id, role FROM users WHERE id = ? LIMIT 1").bind(userId).first();
    if (!target) return Response.json({ success: false, message: "Pengguna tidak ditemukan." }, { status: 404 });
    if (target.role !== "user") return Response.json({ success: false, message: "Akun admin tidak dapat diubah melalui menu ini." }, { status: 400 });

    await context.env.DB.prepare("UPDATE users SET active = ? WHERE id = ?").bind(active, userId).run();
    if (active === 0) await context.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run();

    return Response.json({ success: true, message: active === 1 ? "Pengguna berhasil diaktifkan." : "Pengguna berhasil dinonaktifkan." });
  } catch (error) {
    return Response.json({ success: false, message: "Terjadi kesalahan server." }, { status: 500 });
  }
}

export async function onRequestDelete(context) {
  try {
    const admin = await getAdmin(context);
    if (!admin) return Response.json({ success: false, message: "Akses admin ditolak." }, { status: 403 });

    const body = await context.request.json();
    const userId = Number(body.id);
    if (!Number.isInteger(userId)) return Response.json({ success: false, message: "ID pengguna tidak valid." }, { status: 400 });
    if (userId === admin.id) return Response.json({ success: false, message: "Admin yang sedang login tidak dapat dihapus." }, { status: 400 });

    const target = await context.env.DB.prepare("SELECT id, role FROM users WHERE id = ? LIMIT 1").bind(userId).first();
    if (!target) return Response.json({ success: false, message: "Pengguna tidak ditemukan." }, { status: 404 });
    if (target.role !== "user") return Response.json({ success: false, message: "Akun admin tidak dapat dihapus." }, { status: 400 });

    await context.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run();
    await context.env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();

    return Response.json({ success: true, message: "Pengguna berhasil dihapus." });
  } catch (error) {
    return Response.json({ success: false, message: "Terjadi kesalahan server." }, { status: 500 });
  }
}
