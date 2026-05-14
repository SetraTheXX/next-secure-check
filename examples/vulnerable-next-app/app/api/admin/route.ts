import { NextRequest } from "next/server";

export async function GET(req: NextRequest) {
  const users = [
    { id: "1", name: "Alice", email: "alice@example.com" },
    { id: "2", name: "Bob", email: "bob@example.com" },
  ];

  return Response.json({ users, total: users.length });
}

export async function DELETE(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const userId = searchParams.get("userId");

  return Response.json({
    success: true,
    deleted: userId
  });
}