import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  const formData = await request.formData();
  const file = formData.get("file") as File;

  if (!file) {
    return NextResponse.json({ error: "No file uploaded" }, { status: 400 });
  }

  // VULNERABLE: No file type validation
  // VULNERABLE: No file size limit check

  const bytes = await file.arrayBuffer();
  const buffer = Buffer.from(bytes);

  // Simulate saving file
  console.log(`Saving file: ${file.name}`);

  return NextResponse.json({ success: true });
}