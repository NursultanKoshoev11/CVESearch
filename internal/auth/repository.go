package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/NursultanKoshoev11/CVESearch/packages/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Principal struct {
	UserID            uuid.UUID `json:"user_id"`
	TenantID          uuid.UUID `json:"tenant_id"`
	Email             string    `json:"email,omitempty"`
	DisplayName       string    `json:"display_name,omitempty"`
	PreferredUsername string    `json:"preferred_username,omitempty"`
	Roles             []string  `json:"roles"`
	Permissions       []string  `json:"permissions"`
}

func (p Principal) HasPermission(permission string) bool {
	index := sort.SearchStrings(p.Permissions, permission)
	return index < len(p.Permissions) && p.Permissions[index] == permission
}

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) EnsureTenant(ctx context.Context, tenantID uuid.UUID, slug, name string) error {
	return database.WithTenantTx(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO tenants (id, slug, name)
			VALUES ($1, $2, $3)
			ON CONFLICT (id) DO UPDATE
			SET slug = EXCLUDED.slug,
			    name = EXCLUDED.name,
			    updated_at = now()
			WHERE tenants.deleted_at IS NULL`, tenantID, slug, name)
		if err != nil {
			return fmt.Errorf("ensure bootstrap tenant: %w", err)
		}
		return nil
	})
}

func (r *Repository) UpsertUserAndRoles(ctx context.Context, tenantID uuid.UUID, identity Identity, roleNames []string) (uuid.UUID, error) {
	if len(roleNames) == 0 {
		return uuid.Nil, errors.New("at least one role is required")
	}
	var userID uuid.UUID
	err := database.WithTenantTx(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO users (
				tenant_id, oidc_issuer, oidc_subject, email, email_verified,
				display_name, preferred_username, last_login_at
			) VALUES ($1, $2, $3, NULLIF($4, ''), $5, NULLIF($6, ''), NULLIF($7, ''), now())
			ON CONFLICT (tenant_id, oidc_issuer, oidc_subject) DO UPDATE
			SET email = EXCLUDED.email,
			    email_verified = EXCLUDED.email_verified,
			    display_name = EXCLUDED.display_name,
			    preferred_username = EXCLUDED.preferred_username,
			    last_login_at = now(),
			    updated_at = now()
			WHERE users.deleted_at IS NULL
			RETURNING id`, tenantID, identity.Issuer, identity.Subject, identity.Email,
			identity.EmailVerified, identity.Name, identity.PreferredUsername).Scan(&userID)
		if err != nil {
			return fmt.Errorf("upsert OIDC user: %w", err)
		}

		rows, err := tx.Query(ctx, `SELECT id, name FROM roles WHERE name = ANY($1::text[])`, roleNames)
		if err != nil {
			return fmt.Errorf("resolve roles: %w", err)
		}
		defer rows.Close()
		roleIDs := make(map[string]uuid.UUID, len(roleNames))
		for rows.Next() {
			var id uuid.UUID
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				return fmt.Errorf("scan role: %w", err)
			}
			roleIDs[name] = id
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate roles: %w", err)
		}
		if len(roleIDs) != len(roleNames) {
			return fmt.Errorf("one or more configured roles do not exist")
		}
		if _, err := tx.Exec(ctx, `DELETE FROM user_roles WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID); err != nil {
			return fmt.Errorf("replace user roles: %w", err)
		}
		for _, roleName := range roleNames {
			if _, err := tx.Exec(ctx, `
				INSERT INTO user_roles (tenant_id, user_id, role_id)
				VALUES ($1, $2, $3)`, tenantID, userID, roleIDs[roleName]); err != nil {
				return fmt.Errorf("assign role %s: %w", roleName, err)
			}
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

func (r *Repository) LoadPrincipal(ctx context.Context, tenantID, userID uuid.UUID) (Principal, error) {
	principal := Principal{TenantID: tenantID, UserID: userID}
	err := database.WithTenantTx(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			SELECT COALESCE(email, ''), COALESCE(display_name, ''), COALESCE(preferred_username, '')
			FROM users
			WHERE tenant_id = $1 AND id = $2 AND status = 'active' AND deleted_at IS NULL`, tenantID, userID).
			Scan(&principal.Email, &principal.DisplayName, &principal.PreferredUsername); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errors.New("active user not found")
			}
			return fmt.Errorf("load user: %w", err)
		}

		rows, err := tx.Query(ctx, `
			SELECT DISTINCT r.name, p.name
			FROM user_roles ur
			JOIN roles r ON r.id = ur.role_id
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id
			WHERE ur.tenant_id = $1 AND ur.user_id = $2
			ORDER BY r.name, p.name`, tenantID, userID)
		if err != nil {
			return fmt.Errorf("load roles and permissions: %w", err)
		}
		defer rows.Close()
		roles := map[string]struct{}{}
		permissions := map[string]struct{}{}
		for rows.Next() {
			var role string
			var permission *string
			if err := rows.Scan(&role, &permission); err != nil {
				return fmt.Errorf("scan role and permission: %w", err)
			}
			roles[role] = struct{}{}
			if permission != nil {
				permissions[*permission] = struct{}{}
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate roles and permissions: %w", err)
		}
		if len(roles) == 0 {
			return errors.New("user has no assigned roles")
		}
		for role := range roles {
			principal.Roles = append(principal.Roles, role)
		}
		for permission := range permissions {
			principal.Permissions = append(principal.Permissions, permission)
		}
		sort.Strings(principal.Roles)
		sort.Strings(principal.Permissions)
		return nil
	})
	if err != nil {
		return Principal{}, err
	}
	return principal, nil
}

func ResolveRoles(defaultRole string, mappings map[string]string, groups []string) []string {
	selected := map[string]struct{}{}
	for _, group := range groups {
		if role, ok := mappings[group]; ok && role != "" {
			selected[role] = struct{}{}
		}
	}
	if len(selected) == 0 && defaultRole != "" {
		selected[defaultRole] = struct{}{}
	}
	roles := make([]string, 0, len(selected))
	for role := range selected {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles
}
