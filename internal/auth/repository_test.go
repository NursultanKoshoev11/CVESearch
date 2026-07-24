package auth

import "testing"

func TestResolveRolesUsesMappedGroups(t *testing.T) {
	roles := ResolveRoles("public_user", map[string]string{
		"/analysts": "platform_analyst",
		"/auditors": "auditor",
	}, []string{"/auditors", "/analysts", "/analysts"})
	if len(roles) != 2 || roles[0] != "auditor" || roles[1] != "platform_analyst" {
		t.Fatalf("roles = %#v", roles)
	}
}

func TestResolveRolesUsesSafeDefault(t *testing.T) {
	roles := ResolveRoles("public_user", map[string]string{"/admins": "super_administrator"}, []string{"/unknown"})
	if len(roles) != 1 || roles[0] != "public_user" {
		t.Fatalf("roles = %#v", roles)
	}
}
