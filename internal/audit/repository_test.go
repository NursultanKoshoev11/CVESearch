package audit

import "testing"

func TestHashRemoteAddressIsStableAndProtected(t *testing.T) {
	repo := &Repository{ipHashKey: []byte("01234567890123456789012345678901")}
	first := repo.hashRemoteAddress("192.0.2.10:443")
	second := repo.hashRemoteAddress("192.0.2.10:80")
	if first == "" || first != second {
		t.Fatalf("hashes differ: %q %q", first, second)
	}
	if first == "192.0.2.10" || len(first) != 64 {
		t.Fatalf("unexpected protected address %q", first)
	}
}
