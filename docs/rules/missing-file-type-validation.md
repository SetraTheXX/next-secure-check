# Upload endpoint may be missing file type validation

**ID:** `upload/missing-file-type-validation`  
**Severity:** `MEDIUM`  
**Category:** `upload`  
**Confidence:** `MEDIUM`

## Description
Upload endpoints should validate file types before accepting user-controlled files. Accepting any file type can lead to various security risks, including remote code execution (RCE) if an attacker can upload and execute a malicious script.

## Impact
- **Malware Distribution:** Attackers can upload malicious files to be served to other users.
- **Remote Code Execution:** If the server executes uploaded files, an attacker can gain full control.
- **Cross-Site Scripting (XSS):** Uploading HTML or SVG files can lead to XSS.

## Recommendation
Validate MIME type and file extension with an allowlist before storing or processing uploaded files.

### Vulnerable Example
```typescript
export async function POST(request: Request) {
  const formData = await request.formData();
  const file = formData.get("file") as File;
  // No validation
  return Response.json({ success: true });
}
```

### Secure Example
```typescript
const ALLOWED_TYPES = ["image/jpeg", "image/png", "application/pdf"];

export async function POST(request: Request) {
  const formData = await request.formData();
  const file = formData.get("file") as File;

  if (!ALLOWED_TYPES.includes(file.type)) {
    return Response.json({ error: "Invalid file type" }, { status: 400 });
  }

  return Response.json({ success: true });
}