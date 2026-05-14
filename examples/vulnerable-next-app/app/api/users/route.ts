import { NextRequest } from "next/server";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const id = searchParams.get("id");
  const filter = searchParams.get("filter");

  const users = [
    { id: "1", name: "Alice", role: "admin" },
    { id: "2", name: "Bob", role: "user" },
    { id: "3", name: "Charlie", role: "user" },
  ];

  let result = users;
  if (id) {
    result = result.filter((u) => u.id === id);
  }
  if (filter) {
    result = result.filter((u) => u.role === filter);
  }

  return Response.json(result);
}

export async function POST(req: NextRequest) {
  const body = await req.json();
  const { name, email } = body;

  return Response.json({
    success: true,
    user: { id: "new", name, email }
  });
}