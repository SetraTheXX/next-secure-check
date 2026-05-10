const JWT_SECRET = "secret";
const stripeKey = "sk_live_demo123456789";

export async function POST(request: Request) {
  const body = await request.json();
  const query = `SELECT * FROM users WHERE email = '${body.email}'`;
  const password = body.password;
  const computed = eval("1 + 1");

  return new Response(
    JSON.stringify({
      ok: true,
      computed,
      query,
      password,
      token: "demo-token",
      jwtSecret: JWT_SECRET,
      stripeKey
    }),
    {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json"
      }
    }
  );
}
