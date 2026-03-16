export const DEFAULT_PROXY_BASE_URL =
  process.env.NANOMASK_BASE_URL ?? "http://127.0.0.1:8081/v1";
export const DEFAULT_ENTITY_HEADER = "X-ZPG-Entities";

function normalizePath(pathname) {
  return pathname.endsWith("/v1") ? pathname : `${pathname.replace(/\/$/, "")}/v1`;
}

export function normalizeBaseUrl(baseUrl = DEFAULT_PROXY_BASE_URL) {
  const raw = `${baseUrl ?? DEFAULT_PROXY_BASE_URL}`.trim() || DEFAULT_PROXY_BASE_URL;
  const url = new URL(raw);
  url.pathname = normalizePath(url.pathname || "/");
  return url.toString();
}

export function healthcheckUrl(baseUrl = DEFAULT_PROXY_BASE_URL, path = "/healthz") {
  const url = new URL(normalizeBaseUrl(baseUrl));
  const probePath = path.startsWith("/") ? path : `/${path}`;
  const prefix = url.pathname.endsWith("/v1") ? url.pathname.slice(0, -3) : url.pathname;
  url.pathname = `${prefix.replace(/\/$/, "")}${probePath}` || probePath;
  url.search = "";
  return url.toString();
}

export function entityHeaders(entities, headerName = DEFAULT_ENTITY_HEADER) {
  if (!entities) return {};
  const value = Array.isArray(entities)
    ? entities.map((entity) => `${entity}`.trim()).filter(Boolean).join(", ")
    : `${entities}`.trim();
  return value ? { [headerName]: value } : {};
}

function mergedHeaders(defaultHeaders, entities, headerName) {
  return {
    ...(defaultHeaders ?? {}),
    ...entityHeaders(entities, headerName),
  };
}

export function createClient({
  OpenAIClass,
  baseUrl,
  baseURL,
  entities,
  headerName = DEFAULT_ENTITY_HEADER,
  defaultHeaders,
  ...options
} = {}) {
  if (!OpenAIClass) {
    throw new TypeError(
      "createClient requires an OpenAIClass. Pass the official OpenAI constructor from the 'openai' package.",
    );
  }

  const resolvedBaseURL = baseURL ?? baseUrl ?? DEFAULT_PROXY_BASE_URL;
  return new OpenAIClass({
    ...options,
    baseURL: normalizeBaseUrl(resolvedBaseURL),
    defaultHeaders: mergedHeaders(defaultHeaders, entities, headerName),
  });
}

export async function verify({
  baseUrl = DEFAULT_PROXY_BASE_URL,
  path = "/healthz",
  expectedStatus = 200,
  timeoutMs = 2000,
  fetchImpl = globalThis.fetch,
} = {}) {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("verify requires a fetch implementation.");
  }

  const url = healthcheckUrl(baseUrl, path);
  const controller = typeof AbortController === "function" ? new AbortController() : null;
  const timeout = controller
    ? setTimeout(() => controller.abort(new Error("NanoMask probe timed out")), timeoutMs)
    : null;

  try {
    const response = await fetchImpl(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: controller?.signal,
    });
    return {
      ok: response.status === expectedStatus,
      status: response.status,
      url,
      error: response.status === expectedStatus ? null : `unexpected status ${response.status}`,
    };
  } catch (error) {
    return {
      ok: false,
      status: null,
      url,
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

export default {
  DEFAULT_ENTITY_HEADER,
  DEFAULT_PROXY_BASE_URL,
  createClient,
  entityHeaders,
  healthcheckUrl,
  normalizeBaseUrl,
  verify,
};
