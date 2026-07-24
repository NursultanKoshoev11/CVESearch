package auth

import "testing"

func TestCodeChallengeDeterministic(t *testing.T) {
	const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	first := codeChallenge(verifier)
	second := codeChallenge(verifier)
	if first == "" || first != second {
		t.Fatalf("unexpected challenge values %q and %q", first, second)
	}
	if first == verifier {
		t.Fatal("challenge must not equal verifier")
	}
}

func TestRandomTokenMinimumEntropy(t *testing.T) {
	if _, err := randomToken(31); err == nil {
		t.Fatal("expected minimum entropy error")
	}
	first, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("random tokens collided")
	}
}
