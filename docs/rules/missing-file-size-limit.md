# Upload endpoint may be missing file size limit

**ID:** `upload/missing-file-size-limit`  
**Severity:** `MEDIUM`  
**Category:** `upload`  
**Confidence:** `MEDIUM`

## Description
Upload endpoints should enforce file size limits to reduce abuse and resource exhaustion risk. Without limits, an attacker can upload extremely large files to consume disk space, memory, or bandwidth, leading to a Denial of Service (DoS).

## Impact
- **Denial of Service (DoS):** Exhausting server resources (disk, RAM, CPU).
- **Increased Costs:** Higher storage and bandwidth usage costs.
- **System Instability:** Large files can crash processing services or fill up partitions.

## Recommendation
Add a strict maximum file size and reject files that exceed it before storage or further processing.

### Vulnerable Example
```typescript
export async function POST(request: Request) {
  const formData = await request.formData();
  const file = formData.get("file") as File;
  // No size limit check
  const bytes = await file.arrayBuffer();
  return Response.json({ success: true });
}
```

### Secure Example
```typescript
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

export async function POST(request: Request) {
  const formData = await request.formData();
  const file = formData.get("file") as File;

  if (file.size > MAX_FILE_SIZE) {
    return Response.json({ error: "File too large" }, { status: 400 });
  }

  return Response.json({ success: true });
}