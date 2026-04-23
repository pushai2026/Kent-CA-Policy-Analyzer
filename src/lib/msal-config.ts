import { Configuration, BrowserCacheLocation, LogLevel } from "@azure/msal-browser";

/**
 * REQUIRED ENVIRONMENT VARIABLES
 * These MUST be set at build time.
 */
const CLIENT_ID = process.env.NEXT_PUBLIC_MSAL_CLIENT_ID|| "a166d2a2-dcca-414a-8a6f-f629e0a3c61a";;
const TENANT_ID = process.env.NEXT_PUBLIC_TENANT_ID ||"60b4016c-366c-4f2f-af05-dc2fda09d07b";

if (!CLIENT_ID) {
  throw new Error("NEXT_PUBLIC_MSAL_CLIENT_ID is not set");
}

if (!TENANT_ID) {
  throw new Error("NEXT_PUBLIC_TENANT_ID is not set");
}

/**
 * Microsoft Entra authority locked to a single tenant.
 * Multi-tenant (/common) is intentionally NOT allowed.
 */
const AUTHORITY = `https://login.microsoftonline.com/${TENANT_ID}`;

/**
 * Redirect URI
 * Must be registered in the App Registration (SPA).
 */
const REDIRECT_URI =
  (typeof window !== "undefined" && window.location.origin) || "";

export const msalConfig: Configuration = {
  auth: {
    clientId: CLIENT_ID,
    authority: AUTHORITY,
    redirectUri: REDIRECT_URI,
    navigateToLoginRequestUrl: true
  },

  cache: {
    cacheLocation: BrowserCacheLocation.SessionStorage,
    storeAuthStateInCookie: false
  },

  system: {
    loggerOptions: {
      logLevel: LogLevel.Error,
      piiLoggingEnabled: false,
      loggerCallback: (level, message) => {
        if (level === LogLevel.Error) {
          console.error(message);
        }
      }
    }
  }
};

/**
 * Delegated Graph permissions required by the app.
 * NOTE: Admin consent MUST be granted in the tenant.
 */
export const loginRequest = {
  scopes: [
    "Policy.Read.All",
    "Application.Read.All",
    "Directory.Read.All"
  ]
};