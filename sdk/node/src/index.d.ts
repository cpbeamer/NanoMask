export const DEFAULT_PROXY_BASE_URL: string;
export const DEFAULT_ENTITY_HEADER: string;

export type EntityInput = string | string[] | null | undefined;

export interface VerifyResult {
  ok: boolean;
  status: number | null;
  url: string;
  error: string | null;
}

export interface CreateClientOptions {
  OpenAIClass: new (options: Record<string, unknown>) => unknown;
  baseUrl?: string;
  baseURL?: string;
  entities?: EntityInput;
  headerName?: string;
  defaultHeaders?: Record<string, string>;
  [key: string]: unknown;
}

export interface VerifyOptions {
  baseUrl?: string;
  path?: string;
  expectedStatus?: number;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export function normalizeBaseUrl(baseUrl?: string): string;
export function healthcheckUrl(baseUrl?: string, path?: string): string;
export function entityHeaders(entities?: EntityInput, headerName?: string): Record<string, string>;
export function createClient(options: CreateClientOptions): unknown;
export function verify(options?: VerifyOptions): Promise<VerifyResult>;

declare const _default: {
  DEFAULT_ENTITY_HEADER: string;
  DEFAULT_PROXY_BASE_URL: string;
  createClient: typeof createClient;
  entityHeaders: typeof entityHeaders;
  healthcheckUrl: typeof healthcheckUrl;
  normalizeBaseUrl: typeof normalizeBaseUrl;
  verify: typeof verify;
};

export default _default;
