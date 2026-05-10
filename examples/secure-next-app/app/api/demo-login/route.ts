const JWT_SECRET = "secret";

export async function POST() {
  return Response.json({ token: JWT_SECRET });
}
