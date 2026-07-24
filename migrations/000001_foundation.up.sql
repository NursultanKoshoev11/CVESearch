BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION app_current_tenant_id() RETURNS uuid
LANGUAGE sql STABLE
AS $$
    SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
$$;

CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid NULL,
    updated_by uuid NULL,
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    deleted_at timestamptz NULL,
    deleted_by uuid NULL
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    oidc_issuer text NOT NULL,
    oidc_subject text NOT NULL,
    email text NULL,
    email_verified boolean NOT NULL DEFAULT false,
    display_name text NULL,
    preferred_username text NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked', 'disabled')),
    last_login_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid NULL,
    updated_by uuid NULL,
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    deleted_at timestamptz NULL,
    deleted_by uuid NULL,
    UNIQUE (tenant_id, oidc_issuer, oidc_subject),
    UNIQUE (tenant_id, id)
);

CREATE INDEX users_tenant_email_idx ON users (tenant_id, lower(email)) WHERE email IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE roles (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE,
    description text NOT NULL,
    is_system boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version integer NOT NULL DEFAULT 1 CHECK (version > 0)
);

CREATE TABLE permissions (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE,
    description text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version integer NOT NULL DEFAULT 1 CHECK (version > 0)
);

CREATE TABLE role_permissions (
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    user_id uuid NOT NULL,
    role_id uuid NOT NULL REFERENCES roles(id),
    assigned_at timestamptz NOT NULL DEFAULT now(),
    assigned_by uuid NULL,
    PRIMARY KEY (tenant_id, user_id, role_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE audit_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_id uuid NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    action text NOT NULL CHECK (length(action) BETWEEN 1 AND 160),
    resource_type text NULL,
    resource_id uuid NULL,
    result text NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    request_id text NULL CHECK (request_id IS NULL OR length(request_id) <= 128),
    ip_address_hash text NULL CHECK (ip_address_hash IS NULL OR length(ip_address_hash) = 64),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_logs_tenant_occurred_idx ON audit_logs (tenant_id, occurred_at DESC, id DESC);
CREATE INDEX audit_logs_actor_occurred_idx ON audit_logs (actor_id, occurred_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_logs_action_idx ON audit_logs (tenant_id, action, occurred_at DESC);

CREATE OR REPLACE FUNCTION set_updated_at_and_version() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    NEW.version = OLD.version + 1;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tenants_set_updated_at
BEFORE UPDATE ON tenants
FOR EACH ROW EXECUTE FUNCTION set_updated_at_and_version();

CREATE TRIGGER users_set_updated_at
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION set_updated_at_and_version();

CREATE TRIGGER roles_set_updated_at
BEFORE UPDATE ON roles
FOR EACH ROW EXECUTE FUNCTION set_updated_at_and_version();

CREATE TRIGGER permissions_set_updated_at
BEFORE UPDATE ON permissions
FOR EACH ROW EXECUTE FUNCTION set_updated_at_and_version();

CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only';
END;
$$;

CREATE TRIGGER audit_logs_reject_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

CREATE TRIGGER audit_logs_reject_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenants_isolation ON tenants
    USING (id = app_current_tenant_id())
    WITH CHECK (id = app_current_tenant_id());

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_isolation ON users
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY user_roles_isolation ON user_roles
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_logs_isolation ON audit_logs
    USING (tenant_id = app_current_tenant_id())
    WITH CHECK (tenant_id = app_current_tenant_id());

INSERT INTO roles (id, name, description) VALUES
    ('10000000-0000-4000-8000-000000000001', 'super_administrator', 'Full platform administration.'),
    ('10000000-0000-4000-8000-000000000002', 'platform_analyst', 'Restricted intelligence analysis.'),
    ('10000000-0000-4000-8000-000000000003', 'organization_owner', 'Owner access to a verified organization.'),
    ('10000000-0000-4000-8000-000000000004', 'remediation_engineer', 'Finding remediation workflow.'),
    ('10000000-0000-4000-8000-000000000005', 'cert_csirt_coordinator', 'Responsible disclosure coordination.'),
    ('10000000-0000-4000-8000-000000000006', 'auditor', 'Read-only audit access.'),
    ('10000000-0000-4000-8000-000000000007', 'public_user', 'Public aggregate access only.')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (id, name, description) VALUES
    ('20000000-0000-4000-8000-000000000001', 'platform.manage', 'Manage platform settings and privileged operations.'),
    ('20000000-0000-4000-8000-000000000002', 'audit.read', 'Read tenant audit events.'),
    ('20000000-0000-4000-8000-000000000003', 'restricted_assets.read', 'Read restricted asset intelligence.'),
    ('20000000-0000-4000-8000-000000000004', 'confidential_findings.read', 'Read confidential findings.'),
    ('20000000-0000-4000-8000-000000000005', 'findings.manage', 'Triage and manage findings.'),
    ('20000000-0000-4000-8000-000000000006', 'disclosure.manage', 'Manage disclosure cases.'),
    ('20000000-0000-4000-8000-000000000007', 'reports.generate', 'Generate authorized reports.'),
    ('20000000-0000-4000-8000-000000000008', 'public_aggregate.read', 'Read public aggregate data.')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'super_administrator'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN ('audit.read', 'restricted_assets.read', 'confidential_findings.read', 'findings.manage', 'disclosure.manage', 'reports.generate', 'public_aggregate.read')
WHERE r.name = 'platform_analyst'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN ('confidential_findings.read', 'reports.generate', 'public_aggregate.read')
WHERE r.name = 'organization_owner'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN ('confidential_findings.read', 'findings.manage')
WHERE r.name = 'remediation_engineer'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN ('audit.read', 'restricted_assets.read', 'confidential_findings.read', 'disclosure.manage', 'reports.generate')
WHERE r.name = 'cert_csirt_coordinator'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN ('audit.read', 'confidential_findings.read', 'public_aggregate.read')
WHERE r.name = 'auditor'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name = 'public_aggregate.read'
WHERE r.name = 'public_user'
ON CONFLICT DO NOTHING;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cve_atlas_app') THEN
        GRANT USAGE ON SCHEMA public TO cve_atlas_app;
        GRANT SELECT, INSERT, UPDATE ON tenants, users, user_roles TO cve_atlas_app;
        GRANT SELECT ON roles, permissions, role_permissions TO cve_atlas_app;
        GRANT SELECT, INSERT ON audit_logs TO cve_atlas_app;
    END IF;
END
$$;

COMMIT;
