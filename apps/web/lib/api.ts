import { z } from "zod";

const apiBase = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080").replace(/\/$/, "");

const dependencySchema = z.object({ status: z.string(), latency_ms: z.number().int().nonnegative() });
export const readinessSchema = z.object({
  status: z.string(),
  checked_at: z.string().datetime(),
  dependencies: z.record(z.string(), dependencySchema),
});

export const principalSchema = z.object({
  data: z.object({
    user_id: z.string().uuid(),
    tenant_id: z.string().uuid(),
    email: z.string().optional(),
    display_name: z.string().optional(),
    preferred_username: z.string().optional(),
    roles: z.array(z.string()),
    permissions: z.array(z.string()),
  }),
});

export type Readiness = z.infer<typeof readinessSchema>;
export type Principal = z.infer<typeof principalSchema>["data"];

export function apiURL(path: string): string {
  if (!path.startsWith("/")) throw new Error("API path must start with /");
  return `${apiBase}${path}`;
}

async function request(path: string, init?: RequestInit): Promise<Response> {
  return fetch(apiURL(path), {
    ...init,
    credentials: "include",
    headers: { Accept: "application/json", ...init?.headers },
  });
}

export async function fetchReadiness(): Promise<Readiness> {
  const response = await request("/health/ready");
  const payload: unknown = await response.json();
  const parsed = readinessSchema.parse(payload);
  if (!response.ok) throw new Error(`API is ${parsed.status}`);
  return parsed;
}

export async function fetchPrincipal(): Promise<Principal | null> {
  const response = await request("/api/v1/auth/me");
  if (response.status === 401) return null;
  if (!response.ok) throw new Error("Unable to load the authenticated user");
  return principalSchema.parse(await response.json()).data;
}

export async function logout(): Promise<string> {
  const response = await request("/api/v1/auth/logout", { method: "POST" });
  if (!response.ok) throw new Error("Logout failed");
  const parsed = z
    .object({ data: z.object({ logout_url: z.string() }) })
    .parse(await response.json());
  return parsed.data.logout_url;
}

export function loginURL(returnTo = "/"): string {
  return apiURL(`/api/v1/auth/login?return_to=${encodeURIComponent(returnTo)}`);
}
