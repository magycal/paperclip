import { describe, expect, it, vi } from "vitest";
import {
  buildOidcAuthOptions,
  fetchOidcUserInfo,
  resolveOidcProviderConfig,
  toOidcPublicProviders,
} from "../auth/oidc.js";

const BASE = {
  PAPERCLIP_AUTH_OIDC_ISSUER: "https://idp.example.com/application/o/paperclip/",
  PAPERCLIP_AUTH_OIDC_CLIENT_ID: "client-id",
  PAPERCLIP_AUTH_OIDC_CLIENT_SECRET: "client-secret",
};
const ENDPOINTS = {
  PAPERCLIP_AUTH_OIDC_AUTHORIZATION_URL: "https://idp.example.com/application/o/authorize/",
  PAPERCLIP_AUTH_OIDC_TOKEN_URL: "https://idp.example.com/application/o/token/",
  PAPERCLIP_AUTH_OIDC_USERINFO_URL: "https://idp.example.com/application/o/userinfo/",
};

describe("resolveOidcProviderConfig", () => {
  it("is off when nothing is configured", () => {
    expect(resolveOidcProviderConfig({})).toBeNull();
    expect(toOidcPublicProviders(null)).toEqual([]);
  });

  it("fails on a partial configuration instead of silently disabling SSO", () => {
    expect(() =>
      resolveOidcProviderConfig({ PAPERCLIP_AUTH_OIDC_ISSUER: BASE.PAPERCLIP_AUTH_OIDC_ISSUER }),
    ).toThrow(/partially configured/);
  });

  it("uses discovery derived from the issuer by default", () => {
    const config = resolveOidcProviderConfig(BASE)!;
    expect(config).toMatchObject({
      providerId: "oidc",
      label: "Single sign-on",
      discoveryUrl: "https://idp.example.com/application/o/paperclip/.well-known/openid-configuration",
      endpoints: null,
    });
  });

  it("uses explicit endpoints, with no discovery, when all three are set", () => {
    const config = resolveOidcProviderConfig({
      ...BASE,
      ...ENDPOINTS,
      PAPERCLIP_AUTH_OIDC_PROVIDER_ID: "authentik",
      PAPERCLIP_AUTH_OIDC_LABEL: "Magycal",
    })!;
    expect(config.discoveryUrl).toBeNull();
    expect(config.endpoints).toEqual({
      authorizationUrl: ENDPOINTS.PAPERCLIP_AUTH_OIDC_AUTHORIZATION_URL,
      tokenUrl: ENDPOINTS.PAPERCLIP_AUTH_OIDC_TOKEN_URL,
      userInfoUrl: ENDPOINTS.PAPERCLIP_AUTH_OIDC_USERINFO_URL,
    });
    expect(toOidcPublicProviders(config)).toEqual([{ id: "authentik", label: "Magycal" }]);
  });

  it("rejects an incomplete endpoint set", () => {
    expect(() =>
      resolveOidcProviderConfig({ ...BASE, PAPERCLIP_AUTH_OIDC_TOKEN_URL: ENDPOINTS.PAPERCLIP_AUTH_OIDC_TOKEN_URL }),
    ).toThrow(/or none of them/);
  });

  it("requires https outside localhost", () => {
    expect(() =>
      resolveOidcProviderConfig({ ...BASE, PAPERCLIP_AUTH_OIDC_ISSUER: "http://idp.example.com/" }),
    ).toThrow(/https/);
    expect(
      resolveOidcProviderConfig({ ...BASE, PAPERCLIP_AUTH_OIDC_ISSUER: "http://localhost:9000/o/app/" }),
    ).not.toBeNull();
  });

  it("rejects provider ids that would not be a safe callback path segment", () => {
    expect(() =>
      resolveOidcProviderConfig({ ...BASE, PAPERCLIP_AUTH_OIDC_PROVIDER_ID: "../x" }),
    ).toThrow(/PROVIDER_ID/);
  });

  it("never exposes endpoints or secrets in the public provider list", () => {
    const publicList = JSON.stringify(toOidcPublicProviders(resolveOidcProviderConfig({ ...BASE, ...ENDPOINTS })));
    expect(publicList).not.toContain("client-secret");
    expect(publicList).not.toContain("idp.example.com");
  });
});

describe("buildOidcAuthOptions", () => {
  it("trusts the provider for linking existing (unverified) local users", () => {
    const options = buildOidcAuthOptions(resolveOidcProviderConfig(BASE)!);
    expect(options.account.accountLinking).toEqual({
      enabled: true,
      trustedProviders: ["oidc"],
      requireLocalEmailVerified: false,
    });
    expect(options.plugin.id).toBe("generic-oauth");
  });
});

describe("fetchOidcUserInfo", () => {
  const ok = (body: unknown) =>
    vi.fn(async () => new Response(JSON.stringify(body), { status: 200 })) as unknown as typeof fetch;

  it("maps the userinfo claims and sends the access token", async () => {
    const fetchImpl = ok({ sub: "u1", email: "a@example.com", email_verified: true, name: "A" });
    const info = await fetchOidcUserInfo("https://idp.example.com/userinfo/", "tok", fetchImpl);
    expect(info).toEqual({ id: "u1", email: "a@example.com", emailVerified: true, name: "A", image: undefined });
    expect(fetchImpl).toHaveBeenCalledWith("https://idp.example.com/userinfo/", {
      headers: { Authorization: "Bearer tok", Accept: "application/json" },
    });
  });

  it("treats a missing email_verified as unverified and falls back to the email for the name", async () => {
    const info = await fetchOidcUserInfo("https://x/", "tok", ok({ sub: "u1", email: "a@example.com" }));
    expect(info).toMatchObject({ emailVerified: false, name: "a@example.com" });
  });

  it("returns null without an access token, on an error status, or without sub/email", async () => {
    expect(await fetchOidcUserInfo("https://x/", undefined, ok({}))).toBeNull();
    const failing = vi.fn(async () => new Response("nope", { status: 401 })) as unknown as typeof fetch;
    expect(await fetchOidcUserInfo("https://x/", "tok", failing)).toBeNull();
    expect(await fetchOidcUserInfo("https://x/", "tok", ok({ sub: "u1" }))).toBeNull();
  });
});
