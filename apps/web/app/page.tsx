"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchPrincipal, fetchReadiness, loginURL, logout } from "@/lib/api";

export default function HomePage() {
  const queryClient = useQueryClient();
  const readiness = useQuery({ queryKey: ["readiness"], queryFn: fetchReadiness, refetchInterval: 30_000 });
  const principal = useQuery({ queryKey: ["principal"], queryFn: fetchPrincipal });

  async function handleLogout() {
    const providerLogoutURL = await logout();
    queryClient.setQueryData(["principal"], null);
    window.location.assign(providerLogoutURL || "/");
  }

  return (
    <main className="shell">
      <header className="hero">
        <div>
          <p className="eyebrow">External Attack Surface Management</p>
          <h1>CVE Atlas</h1>
          <p className="subtitle">
            Пассивная платформа киберразведки. Активная проверка не входит в Foundation и не может запускаться.
          </p>
        </div>
        <div className="authPanel" aria-live="polite">
          {principal.isPending ? (
            <span>Проверка сессии…</span>
          ) : principal.data ? (
            <>
              <strong>{principal.data.display_name || principal.data.email || principal.data.preferred_username}</strong>
              <span>{principal.data.roles.join(", ")}</span>
              <button type="button" onClick={handleLogout}>Выйти</button>
            </>
          ) : (
            <a className="button" href={loginURL("/")}>Войти через OIDC</a>
          )}
        </div>
      </header>

      <section className="grid" aria-label="Foundation status">
        <article className="card">
          <div className="cardHeader">
            <h2>Состояние платформы</h2>
            <span className={`badge ${readiness.data?.status === "ready" ? "ok" : "warning"}`}>
              {readiness.isPending ? "Проверка" : readiness.data?.status ?? "Недоступно"}
            </span>
          </div>
          {readiness.data ? (
            <dl className="statusList">
              {Object.entries(readiness.data.dependencies).map(([name, value]) => (
                <div key={name}>
                  <dt>{name}</dt>
                  <dd>{value.status} · {value.latency_ms} мс</dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="muted">API или одна из зависимостей пока недоступна.</p>
          )}
        </article>

        <article className="card">
          <h2>Milestone 0</h2>
          <ul className="checkList">
            <li>Go REST API и OpenAPI 3.1</li>
            <li>OIDC + PKCE, server-side sessions</li>
            <li>RBAC и tenant isolation</li>
            <li>Append-only audit logging</li>
            <li>PostgreSQL, Redis, Neo4j, MinIO</li>
            <li>OpenTelemetry traces и metrics</li>
          </ul>
        </article>
      </section>

      <section className="notice">
        <strong>Безопасный режим:</strong> в текущем milestone нет сканеров, эксплуатации CVE, RIPEstat или Censys.
      </section>
    </main>
  );
}
