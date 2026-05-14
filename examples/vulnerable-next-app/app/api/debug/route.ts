import { exec } from "child_process";
import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const cmd = searchParams.get("cmd") || "ls";

  // Vulnerable to command injection
  exec(cmd, (error, stdout, stderr) => {
    console.log(stdout);
  });

  // Vulnerable to code injection
  const formula = searchParams.get("formula") || "1+1";
  const result = new Function(`return ${formula}`)();

  return NextResponse.json({ result });
}