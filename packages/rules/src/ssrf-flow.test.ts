import ts from "typescript";
import { describe, expect, it } from "vitest";
import { findUnvalidatedOutboundRequestTargets } from "./ssrf-flow.js";

function sourceFile(content: string, fileName = "app/api/proxy/route.ts"): ts.SourceFile {
  return ts.createSourceFile(fileName, content, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

describe("bounded SSRF flow", () => {
  it("reports a request-derived URL reaching global fetch", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function GET(request) {
          const url = request.nextUrl.searchParams.get("url");
          await fetch(url);
        }
      `)
    );

    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({
      evidencePath: "request.nextUrl.searchParams.get()",
      sinkName: "fetch"
    });
  });

  it("tracks a JSON URL field through two local aliases", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function POST(request) {
          const body = await request.json();
          const url = body.url;
          const alias = url;
          const second = alias;
          await fetch(second);
        }
      `)
    );

    expect(matches).toHaveLength(1);
    expect(matches[0]?.evidencePath).toBe("request.json() -> url -> alias -> second");
  });

  it("reports a URL field read from form data", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function POST(request) {
          const formData = await request.formData();
          await fetch(formData.get("url"));
        }
      `)
    );

    expect(matches).toHaveLength(1);
    expect(matches[0]?.evidencePath).toBe("request.formData() -> get()");
  });

  it("recognizes query and route URL fields", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function GET(req, { params }) {
          await fetch(req.query.url);
          await fetch(params.url);
        }
      `)
    );

    expect(matches.map((match) => match.evidencePath)).toEqual(["req.query -> url", "params -> url"]);
  });

  it("does not report constant outbound URLs", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function GET() {
          const url = "https://api.example.com/health";
          await fetch(url);
        }
      `)
    );

    expect(matches).toHaveLength(0);
  });

  it("does not report client-side fetches or a shadowed fetch name", () => {
    const clientMatches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        "use client";
        export function Client({ request }) {
          return fetch(request.query.url);
        }
      `, "app/proxy/client.tsx")
    );
    const shadowedMatches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function GET(request) {
          const fetch = (url) => url;
          return fetch(request.query.url);
        }
      `)
    );
    const moduleShadowedMatches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        const fetch = customFetch;
        export async function GET(request) {
          return fetch(request.query.url);
        }
      `)
    );
    const moduleShadowedRequestMatches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        const request = getRequestContext();
        export async function GET() {
          return fetch(request.query.url);
        }
      `)
    );

    expect(clientMatches).toHaveLength(0);
    expect(shadowedMatches).toHaveLength(0);
    expect(moduleShadowedMatches).toHaveLength(0);
    expect(moduleShadowedRequestMatches).toHaveLength(0);
  });

  it("does not scan module-scope or non-exported helper fetches", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        fetch(request.query.url);
        function forward(request) {
          return fetch(request.query.url);
        }
      `)
    );

    expect(matches).toHaveLength(0);
  });

  it("recognizes the documented axios and got sinks", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        import axios from "axios";
        import got from "got";
        export async function POST(request) {
          const url = request.body.url;
          await axios.get(url);
          await got(url);
        }
      `)
    );
    const shadowedClientMatches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        import axios from "axios";
        export async function POST(request) {
          const axios = customClient;
          return axios(request.query.url);
        }
      `)
    );

    expect(matches.map((match) => match.sinkName)).toEqual(["axios.get", "got"]);
    expect(shadowedClientMatches).toHaveLength(0);
  });

  it("recognizes the incoming request URL as a URL-like source", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function GET(request) {
          await fetch(request.url);
        }
      `)
    );

    expect(matches).toHaveLength(1);
    expect(matches[0]?.evidencePath).toBe("request.url");
  });

  it("suppresses a URL protected by a static host allowlist", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        const ALLOWED_HOSTS = ["api.example.com"];
        export async function GET(request) {
          const url = request.query.url;
          if (ALLOWED_HOSTS.includes(new URL(url).hostname)) {
            await fetch(url);
          }
        }
      `)
    );

    expect(matches).toHaveLength(0);
  });

  it("does not treat URL parsing alone as an SSRF guard", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function GET(request) {
          const url = request.query.url;
          const parsed = new URL(url);
          await fetch(parsed);
        }
      `)
    );

    expect(matches).toHaveLength(1);
    expect(matches[0]?.evidencePath).toBe("request.query -> url -> URL()");
  });

  it("accepts a same-file helper with visible host validation", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        const ALLOWED_HOSTS = ["api.example.com"];
        function isSafeOutboundUrl(value) {
          const parsed = new URL(value);
          return ALLOWED_HOSTS.has(parsed.hostname);
        }
        export async function GET(request) {
          const url = request.query.url;
          if (isSafeOutboundUrl(url)) {
            await fetch(url);
          }
        }
      `)
    );

    expect(matches).toHaveLength(0);
  });

  it("accepts a visible private-network rejection before fetch", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        function isPrivateNetwork(value) {
          const parsed = new URL(value);
          return ["localhost", "127.0.0.1"].includes(parsed.hostname);
        }
        export async function GET(request) {
          const url = request.query.url;
          if (isPrivateNetwork(url)) return Response.json({ ok: false });
          await fetch(url);
        }
      `)
    );

    expect(matches).toHaveLength(0);
  });

  it("does not trust an inverted private-network check", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        function isPrivateNetwork(value) {
          const parsed = new URL(value);
          return ["localhost", "127.0.0.1"].includes(parsed.hostname);
        }
        export async function GET(request) {
          const url = request.query.url;
          if (!isPrivateNetwork(url)) return Response.json({ ok: false });
          await fetch(url);
        }
      `)
    );

    expect(matches).toHaveLength(1);
  });

  it("does not trust unsafe guard branches and supports equality rejection", () => {
    const privateBranch = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        function isPrivateNetwork(value) {
          const parsed = new URL(value);
          return ["localhost", "127.0.0.1"].includes(parsed.hostname);
        }
        export async function GET(request) {
          const url = request.query.url;
          if (isPrivateNetwork(url)) {
            await fetch(url);
          }
        }
      `)
    );
    const negativeAllowlistBranch = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        const ALLOWED_HOSTS = ["api.example.com"];
        export async function GET(request) {
          const url = request.query.url;
          if (!ALLOWED_HOSTS.includes(new URL(url).hostname)) {
            await fetch(url);
          }
        }
      `)
    );
    const negativeEqualityBranch = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function GET(request) {
          const url = request.query.url;
          if (new URL(url).hostname !== "api.example.com") {
            await fetch(url);
          }
        }
      `)
    );
    const protocolOnlyGuard = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function GET(request) {
          const url = request.query.url;
          if (new URL(url).protocol === "https:") {
            await fetch(url);
          }
        }
      `)
    );
    const protocolAllowlist = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        const ALLOWED_PROTOCOLS = ["https:"];
        export async function GET(request) {
          const url = request.query.url;
          if (ALLOWED_PROTOCOLS.includes(new URL(url).protocol)) {
            await fetch(url);
          }
        }
      `)
    );
    const shadowedAllowlist = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        const ALLOWED_HOSTS = ["api.example.com"];
        export async function GET(request) {
          const ALLOWED_HOSTS = getAllowedHosts();
          const url = request.query.url;
          if (ALLOWED_HOSTS.includes(new URL(url).hostname)) {
            await fetch(url);
          }
        }
      `)
    );
    const unrelatedSafeHelper = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        function isSafeOutboundUrl(value) {
          const parsed = new URL("https://api.example.com");
          return ["api.example.com"].includes(parsed.hostname);
        }
        export async function GET(request) {
          const url = request.query.url;
          if (isSafeOutboundUrl(url)) {
            await fetch(url);
          }
        }
      `)
    );
    const multiParameterSafeHelper = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        function isSafeOutboundUrl(value, fixed) {
          const parsed = new URL(fixed);
          return ["api.example.com"].includes(parsed.hostname);
        }
        export async function GET(request) {
          const url = request.query.url;
          if (isSafeOutboundUrl(url, "https://api.example.com")) {
            await fetch(url);
          }
        }
      `)
    );
    const dynamicAllowlistHelper = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        function isSafeOutboundUrl(value) {
          const parsed = new URL(value);
          const allowed = getAllowedHosts();
          return allowed.includes(parsed.hostname);
        }
        export async function GET(request) {
          const url = request.query.url;
          if (isSafeOutboundUrl(url)) {
            await fetch(url);
          }
        }
      `)
    );
    const mutatedAllowlist = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        const ALLOWED_HOSTS = ["api.example.com"];
        export async function GET(request) {
          ALLOWED_HOSTS.push(getHostFromRequest(request));
          const url = request.query.url;
          if (ALLOWED_HOSTS.includes(new URL(url).hostname)) {
            await fetch(url);
          }
        }
      `)
    );
    expect(privateBranch).toHaveLength(1);
    expect(negativeAllowlistBranch).toHaveLength(1);
    expect(negativeEqualityBranch).toHaveLength(1);
    expect(protocolOnlyGuard).toHaveLength(1);
    expect(protocolAllowlist).toHaveLength(1);
    expect(shadowedAllowlist).toHaveLength(1);
    expect(unrelatedSafeHelper).toHaveLength(1);
    expect(multiParameterSafeHelper).toHaveLength(1);
    expect(dynamicAllowlistHelper).toHaveLength(1);
    expect(mutatedAllowlist).toHaveLength(1);
  });

  it("accepts a negated visible safe-url helper with an early exit", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        function isSafeOutboundUrl(value) {
          const parsed = new URL(value);
          return ["api.example.com"].includes(parsed.hostname);
        }
        export async function GET(request) {
          const url = request.query.url;
          if (!isSafeOutboundUrl(url)) return Response.json({ ok: false });
          await fetch(url);
        }
      `)
    );

    expect(matches).toHaveLength(0);
  });

  it("keeps an earlier guarded sink from hiding a later unguarded sink", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        const ALLOWED_HOSTS = ["api.example.com"];
        export async function GET(request) {
          const url = request.query.url;
          if (ALLOWED_HOSTS.includes(new URL(url).hostname)) {
            await fetch(url);
          }
          await fetch(url);
        }
      `)
    );

    expect(matches).toHaveLength(1);
    expect(matches[0]?.evidencePath).toBe("request.query -> url");
  });

  it("stops after reassignment", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function GET(request) {
          let url = request.query.url;
          url = "https://api.example.com";
          await fetch(url);
        }
      `)
    );

    expect(matches).toHaveLength(0);
  });

  it("stops beyond the two-alias budget", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function GET(request) {
          const url = request.query.url;
          const first = url;
          const second = first;
          const third = second;
          await fetch(third);
        }
      `)
    );

    expect(matches).toHaveLength(0);
  });

  it("stops at a helper function boundary", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        function forward(request) {
          return fetch(request.query.url);
        }
        export async function GET(request) {
          return forward(request);
        }
      `)
    );

    expect(matches).toHaveLength(0);
  });

  it("does not guess unknown wrappers, fields, or dynamic sinks", () => {
    const matches = findUnvalidatedOutboundRequestTargets(
      sourceFile(`
        export async function GET(request, field) {
          await fetch(request.query.name);
          await safeFetch(request.query.url);
          await client[field](request.query.url);
        }
      `)
    );

    expect(matches).toHaveLength(0);
  });

  it("does not throw on malformed syntax and keeps evidence deterministic", () => {
    const content = `
      export async function GET(request) {
        const url = request.query.url;
        await fetch(url);
      }
    `;
    const first = findUnvalidatedOutboundRequestTargets(sourceFile(content)).map((match) => ({
      evidencePath: match.evidencePath,
      sinkName: match.sinkName,
      start: match.node.getStart()
    }));
    const second = findUnvalidatedOutboundRequestTargets(sourceFile(content)).map((match) => ({
      evidencePath: match.evidencePath,
      sinkName: match.sinkName,
      start: match.node.getStart()
    }));
    const malformed = () => findUnvalidatedOutboundRequestTargets(sourceFile("export async function GET(request) { const url = request.query.url; await fetch(url);"));

    expect(first).toEqual(second);
    expect(JSON.stringify(first)).not.toContain("https://");
    expect(malformed).not.toThrow();
  });
});
