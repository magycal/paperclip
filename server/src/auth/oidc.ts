import { genericOAuth, type GenericOAuthUserInfo } from "better-auth/plugins/generic-oauth";

/**
 * Optional single sign-on through one generic OpenID Connect provider (for example
 * Authentik, Keycloak or Okta), configured entirely from environment variables.
 *
 * - Off unless issuer, client id and client secret are all set. A partial
 *   configuration fails startup instead of silently leaving SSO off.
 * - Users the provider authenticates get an account on first sign-in, even when
 *   `PAPERCLIP_AUTH_DISABLE_SIGN_UP=true` (that flag only governs email/password).
 *   Who may sign in is therefore decided by the provider, e.g. an application
 *   policy bound to a group. A new account has no company access until it is
 *   invited, and only instance admins can create companies.
 * - The provider is trusted for account linking: a first SSO sign-in whose email
 *   matches an existing local user links to that user. Only point this at an
 *   identity provider whose users cannot choose arbitrary email addresses.
 */
export type OidcProviderConfig = {
  providerId: string;
  label: string;
  issuer: string;
  /** Set when endpoints are discovered at startup (needs the provider reachable then). */
  discoveryUrl: string | null;
  /** Set when endpoints are configured explicitly (no network call at startup). */
  endpoints: { authorizationUrl: string; tokenUrl: string; userInfoUrl: string } | null;
  clientId: string;
  clientSecret: string;
};

export type OidcPublicProvider = { id: string; label: string };

const PROVIDER_ID_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;

function isAllowedUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || (url.protocol === "http:" && url.hostname === "localhost");
  } catch {
    return false;
  }
}

function read(env: NodeJS.ProcessEnv, key: string): string | undefined {
  const value = env[key]?.trim();
  return value ? value : undefined;
}

export function resolveOidcProviderConfig(env: NodeJS.ProcessEnv = process.env): OidcProviderConfig | null {
  const issuer = read(env, "PAPERCLIP_AUTH_OIDC_ISSUER");
  const clientId = read(env, "PAPERCLIP_AUTH_OIDC_CLIENT_ID");
  const clientSecret = read(env, "PAPERCLIP_AUTH_OIDC_CLIENT_SECRET");
  const set = [issuer, clientId, clientSecret].filter(Boolean).length;
  if (set === 0) return null;
  if (set !== 3) {
    throw new Error(
      "OIDC sign-in is partially configured: PAPERCLIP_AUTH_OIDC_ISSUER, " +
        "PAPERCLIP_AUTH_OIDC_CLIENT_ID and PAPERCLIP_AUTH_OIDC_CLIENT_SECRET must all be set (or none).",
    );
  }

  if (!isAllowedUrl(issuer!)) {
    throw new Error("PAPERCLIP_AUTH_OIDC_ISSUER must be an https URL (localhost excepted).");
  }
  const issuerUrl = new URL(issuer!);

  const providerId = read(env, "PAPERCLIP_AUTH_OIDC_PROVIDER_ID") ?? "oidc";
  if (!PROVIDER_ID_RE.test(providerId)) {
    throw new Error(
      "PAPERCLIP_AUTH_OIDC_PROVIDER_ID must be lowercase letters, digits or dashes (max 32 chars).",
    );
  }

  // Explicit endpoints: all three or none. With them, startup never calls the
  // provider, so an IdP outage can't break email/password sign-in as well
  // (Better Auth fails its whole auth context when discovery fails).
  const endpointKeys = [
    "PAPERCLIP_AUTH_OIDC_AUTHORIZATION_URL",
    "PAPERCLIP_AUTH_OIDC_TOKEN_URL",
    "PAPERCLIP_AUTH_OIDC_USERINFO_URL",
  ] as const;
  const endpointValues = endpointKeys.map((key) => read(env, key));
  const endpointCount = endpointValues.filter(Boolean).length;
  if (endpointCount !== 0 && endpointCount !== endpointKeys.length) {
    throw new Error(`Set all of ${endpointKeys.join(", ")} or none of them.`);
  }
  for (const [i, value] of endpointValues.entries()) {
    if (value && !isAllowedUrl(value)) {
      throw new Error(`${endpointKeys[i]} must be an https URL (localhost excepted).`);
    }
  }

  const issuerBase = issuerUrl.href.endsWith("/") ? issuerUrl.href : `${issuerUrl.href}/`;
  const [authorizationUrl, tokenUrl, userInfoUrl] = endpointValues;
  return {
    providerId,
    label: read(env, "PAPERCLIP_AUTH_OIDC_LABEL") ?? "Single sign-on",
    issuer: issuerUrl.href,
    discoveryUrl: endpointCount ? null : new URL(".well-known/openid-configuration", issuerBase).href,
    endpoints: endpointCount ? { authorizationUrl: authorizationUrl!, tokenUrl: tokenUrl!, userInfoUrl: userInfoUrl! } : null,
    clientId: clientId!,
    clientSecret: clientSecret!,
  };
}

export function toOidcPublicProviders(config: OidcProviderConfig | null): OidcPublicProvider[] {
  return config ? [{ id: config.providerId, label: config.label }] : [];
}

/**
 * Identity from the userinfo endpoint only, ignoring any unverified ID-token claims.
 * Used with explicit endpoints, where no JWKS is available to verify the ID token.
 */
export async function fetchOidcUserInfo(
  userInfoUrl: string,
  accessToken: string | undefined,
  fetchImpl: typeof fetch = fetch,
): Promise<GenericOAuthUserInfo | null> {
  if (!accessToken) return null;
  const res = await fetchImpl(userInfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
  });
  if (!res.ok) return null;
  const data = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  if (!data || typeof data.sub !== "string" || typeof data.email !== "string" || !data.email) return null;
  return {
    id: data.sub,
    email: data.email,
    emailVerified: data.email_verified === true,
    name: typeof data.name === "string" && data.name ? data.name : data.email,
    image: typeof data.picture === "string" ? data.picture : undefined,
  };
}

/** Better Auth options to merge into the instance config when OIDC is configured. */
export function buildOidcAuthOptions(config: OidcProviderConfig) {
  return {
    plugin: genericOAuth({
      config: [
        {
          providerId: config.providerId,
          name: config.label,
          ...(config.endpoints
            ? {
                ...config.endpoints,
                // Without discovery there is no JWKS to verify ID tokens against. The
                // identity then comes from the userinfo endpoint, called server-side
                // over TLS with the access token from the code exchange.
                accountIssuer: config.issuer,
                getUserInfo: (tokens) => fetchOidcUserInfo(config.endpoints!.userInfoUrl, tokens.accessToken),
              }
            : {
                discoveryUrl: config.discoveryUrl!,
                // Verify ID tokens against the provider's JWKS (signature, issuer, audience).
                requireIdTokenVerification: true,
              }),
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          scopes: ["openid", "profile", "email"],
          pkce: true,
        },
      ],
    }),
    account: {
      accountLinking: {
        enabled: true,
        trustedProviders: [config.providerId],
        // Local email/password users are created unverified (Paperclip does not
        // require email verification), so the default `true` would make linking
        // an existing user impossible.
        requireLocalEmailVerified: false,
      },
    },
  };
}
