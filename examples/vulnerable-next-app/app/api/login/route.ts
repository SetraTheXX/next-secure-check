export async function POST(request: Request) {
  const body = await request.json();
  const query = `SELECT * FROM users WHERE email = '${body.email}'`;

  return Response.json({
    ok: true,
    query,
    token: "demo-token"
  });
}
