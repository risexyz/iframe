export async function onRequestGet(context) {
  try {
    const result = await context.env.DB
      .prepare("SELECT name FROM sqlite_master WHERE type='table'")
      .all();

    return new Response(
      JSON.stringify({
        success: true,
        message: "D1 berhasil terhubung",
        tables: result.results
      }),
      {
        headers: {
          "Content-Type": "application/json"
        }
      }
    );

  } catch (error) {
    return new Response(
      JSON.stringify({
        success: false,
        error: error.message
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  }
}
