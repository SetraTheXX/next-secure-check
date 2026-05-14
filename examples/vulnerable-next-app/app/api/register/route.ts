export async function POST(req: Request) {
  const body = await req.json();
  
  // Vulnerable: No rate limiting on registration endpoint
  // This can be abused for spam account creation
  console.log("Registering user:", body.email);
  
  return Response.json({ success: true, message: "User registered" });
}