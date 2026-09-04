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

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

async function getAdmin(context) {
  if (!context.env?.DB) return null;
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

async function readJson(request) {
  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().includes("application/json")) return null;
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export async function onRequestGet(context) {
  try {
    if (!context.env?.DB) return json({ success: false, message: "Database belum terhubung." }, 503);
    const admin = await getAdmin(context);
    if (!admin) return json({ success: false, message: "Akses admin ditolak." }, 403);

    const result = await context.env.DB.prepare(`
      SELECT id, username, name, role, active, created_at
      FROM users
      ORDER BY id DESC
    `).all();

    return json({ success: true, users: result.results });
  } catch {
    return json({ success: false, message: "Terjadi kesalahan server." }, 500);
  }
}

export async function onRequestPost(context) {
  try {
    if (!context.env?.DB) return json({ success: false, message: "Database belum terhubung." }, 503);
    const admin = await getAdmin(context);
    if (!admin) return json({ success: false, message: "Akses admin ditolak." }, 403);

    const body = await readJson(context.request);
    if (!body) return json({ success: false, message: "Format request tidak valid." }, 415);

    const username = String(body.username || "").trim();
    const password = String(body.password || "");
    const name = String(body.name || "").trim();

    if (!username || !password || !name) return json({ success: false, message: "Nama, username, dan password wajib diisi." }, 400);
    if (username.length < 3 || username.length > 100) return json({ success: false, message: "Username harus 3-100 karakter." }, 400);
    if (name.length > 150) return json({ success: false, message: "Nama terlalu panjang." }, 400);
    if (password.length < 6 || password.length > 256) return json({ success: false, message: "Password harus 6-256 karakter." }, 400);

    const existing = await context.env.DB.prepare("SELECT id FROM users WHERE username = ? LIMIT 1").bind(username).first();
    if (existing) return json({ success: false, message: "Username sudah digunakan." }, 409);

    const passwordHash = await hashPassword(password);
    await context.env.DB.prepare(`
      INSERT INTO users (username, password_hash, name, role, active)
      VALUES (?, ?, ?, 'user', 1)
    `).bind(username, passwordHash, name).run();

    return json({ success: true, message: "Pengguna berhasil dibuat." });
  } catch {
    return json({ success: false, message: "Terjadi kesalahan server." }, 500);
  }
}

export async function onRequestPatch(context) {
  try {
    if (!context.env?.DB) return json({ success: false, message: "Database belum terhubung." }, 503);
    const admin = await getAdmin(context);
    if (!admin) return json({ success: false, message: "Akses admin ditolak." }, 403);

    const body = await readJson(context.request);
    if (!body) return json({ success: false, message: "Format request tidak valid." }, 415);
    const userId = Number(body.id);

    if (body.password !== undefined) {
      const password = String(body.password || "");
      if (!Number.isInteger(userId)) return json({ success: false, message: "ID pengguna tidak valid." }, 400);
      if (password.length < 6 || password.length > 256) return json({ success: false, message: "Password harus 6-256 karakter." }, 400);
      if (userId === admin.id) return json({ success: false, message: "Gunakan menu login untuk mengubah password admin." }, 400);

      const target = await context.env.DB.prepare("SELECT id, role FROM users WHERE id = ? LIMIT 1").bind(userId).first();
      if (!target) return json({ success: false, message: "Pengguna tidak ditemukan." }, 404);
      if (target.role !== "user") return json({ success: false, message: "Password akun admin tidak dapat diubah melalui menu ini." }, 400);

      const passwordHash = await hashPassword(password);
      await context.env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(passwordHash, userId).run();
      await context.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run();
      return json({ success: true, message: "Password berhasil direset. User harus login kembali." });
    }

    const active = Number(body.active);
    if (!Number.isInteger(userId) || ![0, 1].includes(active)) return json({ success: false, message: "Data tidak valid." }, 400);
    if (userId === admin.id) return json({ success: false, message: "Admin yang sedang login tidak dapat dinonaktifkan." }, 400);

    const target = await context.env.DB.prepare("SELECT id, role FROM users WHERE id = ? LIMIT 1").bind(userId).first();
    if (!target) return json({ success: false, message: "Pengguna tidak ditemukan." }, 404);
    if (target.role !== "user") return json({ success: false, message: "Akun admin tidak dapat diubah melalui menu ini." }, 400);

    await context.env.DB.prepare("UPDATE users SET active = ? WHERE id = ?").bind(active, userId).run();
    if (active === 0) await context.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run();
    return json({ success: true, message: active === 1 ? "Pengguna berhasil diaktifkan." : "Pengguna berhasil dinonaktifkan." });
  } catch {
    return json({ success: false, message: "Terjadi kesalahan server." }, 500);
  }
}

export async function onRequestDelete(context) {
  try {
    if (!context.env?.DB) return json({ success: false, message: "Database belum terhubung." }, 503);
    const admin = await getAdmin(context);
    if (!admin) return json({ success: false, message: "Akses admin ditolak." }, 403);

    const body = await readJson(context.request);
    if (!body) return json({ success: false, message: "Format request tidak valid." }, 415);
    const userId = Number(body.id);
    if (!Number.isInteger(userId)) return json({ success: false, message: "ID pengguna tidak valid." }, 400);
    if (userId === admin.id) return json({ success: false, message: "Admin yang sedang login tidak dapat dihapus." }, 400);

    const target = await context.env.DB.prepare("SELECT id, role FROM users WHERE id = ? LIMIT 1").bind(userId).first();
    if (!target) return json({ success: false, message: "Pengguna tidak ditemukan." }, 404);
    if (target.role !== "user") return json({ success: false, message: "Akun admin tidak dapat dihapus." }, 400);

    await context.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run();
    await context.env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();
    return json({ success: true, message: "Pengguna berhasil dihapus." });
  } catch {
    return json({ success: false, message: "Terjadi kesalahan server." }, 500);
  }
}
